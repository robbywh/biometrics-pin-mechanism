package handlers

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/idem"
	"github.com/cryptoapp/api/internal/lockout"
	"github.com/cryptoapp/api/internal/pin"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/store/db"
)

const (
	epSetPin    = "POST /pin"
	epChangePin = "PUT /pin"
	epResetPin  = "POST /pin/reset"
)

func pinWeak() *httpx.Error { return httpx.New(http.StatusUnprocessableEntity, "PIN_WEAK") }

// SetPin sets the initial PIN. It never overwrites (SEC-015) and never replays tokens (SEC-060).
func (s *Server) SetPin(ctx context.Context, req apigen.SetPinRequestObject) (apigen.SetPinResponseObject, error) {
	p := principal(ctx)
	if req.Body.Pin == nil {
		return nil, httpx.Validation()
	}
	newPin := *req.Body.Pin
	k, herr := s.idemKey(p.UserID, epSetPin, req.Params.IdempotencyKey, req.Body)
	if herr != nil {
		return nil, herr
	}
	st, _, herr := s.peekIdem(ctx, k)
	if herr != nil {
		return nil, herr
	}
	if herr := idemOutcomeErr(st); herr != nil {
		return nil, herr
	}
	if p.Used {
		return nil, httpx.AuthFailed()
	}
	if !p.Bound {
		return nil, auth403()
	}
	httpx.InfoFrom(ctx).SetActor(p.UserID.String(), p.DeviceID.String())
	u, err := s.St.Q.GetUserByID(ctx, p.UserID)
	if err != nil {
		return nil, s.fail(ctx, "setPin", err)
	}
	if u.PinHash != nil {
		return nil, httpx.New(http.StatusConflict, "PIN_ALREADY_SET")
	}
	if pin.Validate(newPin) != nil {
		return nil, pinWeak()
	}
	hash, err := s.Hasher.Hash(ctx, newPin)
	if err != nil {
		return nil, s.fail(ctx, "setPin", err)
	}
	now := s.Clk.Now()
	var out apigen.SessionResponse
	var replay idem.State
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.LockUserRow(ctx, p.UserID); err != nil {
			return err
		}
		state, _, err := idem.Begin(ctx, q, k, now)
		if err != nil {
			return err
		}
		if state != idem.Fresh {
			replay = state
			return nil
		}
		if _, err := q.SetInitialPin(ctx, db.SetInitialPinParams{ID: p.UserID, PinHash: &hash, PepperVersion: ptr(s.Hasher.CurrentVersion()), PinSetAt: ptr(now)}); err != nil {
			if isNoRows(err) {
				return httpx.New(http.StatusConflict, "PIN_ALREADY_SET")
			}
			return err
		}
		if n, err := q.UseBootstrap(ctx, db.UseBootstrapParams{TokenHash: p.BootstrapHash, UsedAt: ptr(now)}); err != nil || n == 0 {
			if err == nil {
				err = httpx.AuthFailed()
			}
			return err
		}
		is, err := s.Auth.Create(ctx, q, p.UserID, p.DeviceID, "pin")
		if err != nil {
			return err
		}
		if out, err = s.sessionResponse(ctx, q, is, ptr(0)); err != nil {
			return err
		}
		return idem.Complete(ctx, q, k, http.StatusCreated, nil) // status only: tokens are never stored
	})
	if err != nil {
		return nil, s.fail(ctx, "setPin", err)
	}
	if herr := idemOutcomeErr(replay); herr != nil {
		return nil, herr
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.PinSet, UserID: &p.UserID, DeviceID: &p.DeviceID})
	s.Audit.Emit(ctx, audit.Event{Type: audit.LoginOK, UserID: &p.UserID, DeviceID: &p.DeviceID, Meta: map[string]any{"method": "pin_set"}})
	return apigen.SetPin201JSONResponse{Body: out}, nil
}

// ChangePin implements PUT /pin (SEC-045): old PIN through the shared lockout, then revoke everything else.
func (s *Server) ChangePin(ctx context.Context, req apigen.ChangePinRequestObject) (apigen.ChangePinResponseObject, error) {
	p := principal(ctx)
	b := req.Body
	if b.OldPin == nil || b.NewPin == nil {
		return nil, httpx.Validation()
	}
	k, herr := s.idemKey(p.UserID, epChangePin, req.Params.IdempotencyKey, b)
	if herr != nil {
		return nil, herr
	}
	st, _, herr := s.peekIdem(ctx, k)
	if herr != nil {
		return nil, herr
	}
	if herr := idemOutcomeErr(st); herr != nil {
		return nil, herr
	}
	if p.RevokedByPinChange { // session was revoked by an earlier change; only the replay lookup above may succeed
		return nil, httpx.AuthFailed()
	}
	httpx.InfoFrom(ctx).SetActor(p.UserID.String(), p.DeviceID.String())
	if herr := s.limit(ctx, "pinchange-user", p.UserID.String(), s.Cfg.Limits.PinChangeUser, true); herr != nil {
		return nil, herr
	}
	if pin.Validate(*b.NewPin) != nil {
		return nil, pinWeak()
	}
	now := s.Clk.Now()
	res, err := s.Lock.Attempt(ctx, p.UserID, *b.OldPin, &p.DeviceID, false)
	if err != nil {
		return nil, s.fail(ctx, "changePin", err)
	}
	if res.Kind != lockout.OK {
		return nil, lockout.Error(res, now)
	}
	if subtle.ConstantTimeCompare([]byte(*b.OldPin), []byte(*b.NewPin)) == 1 {
		return nil, httpx.New(http.StatusUnprocessableEntity, "PIN_UNCHANGED")
	}
	hash, err := s.Hasher.Hash(ctx, *b.NewPin)
	if err != nil {
		return nil, s.fail(ctx, "changePin", err)
	}
	now = s.Clk.Now()
	var out apigen.SessionResponse
	var replay idem.State
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.LockUserRow(ctx, p.UserID); err != nil {
			return err
		}
		state, _, err := idem.Begin(ctx, q, k, now)
		if err != nil {
			return err
		}
		if state != idem.Fresh {
			replay = state
			return nil
		}
		if err := q.ReplacePin(ctx, db.ReplacePinParams{ID: p.UserID, PinHash: &hash, PepperVersion: ptr(s.Hasher.CurrentVersion()), PinSetAt: ptr(now)}); err != nil {
			return err
		}
		// Revoke ALL sessions (this device's included: it is re-issued below) and biometric keys on OTHER devices.
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: p.UserID, RevokedAt: ptr(now), RevokeReason: ptr("pin_changed")}); err != nil {
			return err
		}
		if err := q.RevokeKeysOnOtherDevices(ctx, db.RevokeKeysOnOtherDevicesParams{UserID: p.UserID, DeviceID: p.DeviceID, RevokedAt: ptr(now), RevokeReason: ptr("pin_changed")}); err != nil {
			return err
		}
		if err := q.InvalidateUserChallenges(ctx, db.InvalidateUserChallengesParams{UserID: p.UserID, ConsumedAt: ptr(now)}); err != nil {
			return err
		}
		is, err := s.Auth.Create(ctx, q, p.UserID, p.DeviceID, "pin")
		if err != nil {
			return err
		}
		if out, err = s.sessionResponse(ctx, q, is, ptr(res.RecentFailures)); err != nil {
			return err
		}
		return idem.Complete(ctx, q, k, http.StatusOK, nil)
	})
	if err != nil {
		return nil, s.fail(ctx, "changePin", err)
	}
	if herr := idemOutcomeErr(replay); herr != nil {
		return nil, herr
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.PinChanged, UserID: &p.UserID, DeviceID: &p.DeviceID})
	return apigen.ChangePin200JSONResponse{Body: out}, nil
}

// ResetPin implements POST /pin/reset (SEC-046): set PIN, clear locks, revoke everything, start cooling-off.
func (s *Server) ResetPin(ctx context.Context, req apigen.ResetPinRequestObject) (apigen.ResetPinResponseObject, error) {
	p := principal(ctx)
	if req.Body.Pin == nil {
		return nil, httpx.Validation()
	}
	newPin := *req.Body.Pin
	k, herr := s.idemKey(p.UserID, epResetPin, req.Params.IdempotencyKey, req.Body)
	if herr != nil {
		return nil, herr
	}
	st, _, herr := s.peekIdem(ctx, k)
	if herr != nil {
		return nil, herr
	}
	if herr := idemOutcomeErr(st); herr != nil {
		return nil, herr
	}
	if p.Used {
		return nil, httpx.AuthFailed()
	}
	if !p.Bound {
		return nil, auth403()
	}
	httpx.InfoFrom(ctx).SetActor(p.UserID.String(), p.DeviceID.String())
	if herr := s.limit(ctx, "pinchange-user", p.UserID.String(), s.Cfg.Limits.PinChangeUser, true); herr != nil {
		return nil, herr
	}
	if pin.Validate(newPin) != nil {
		return nil, pinWeak()
	}
	hash, err := s.Hasher.Hash(ctx, newPin)
	if err != nil {
		return nil, s.fail(ctx, "resetPin", err)
	}
	now := s.Clk.Now()
	until := now.Add(s.Cfg.CoolingOffDuration)
	var out apigen.SessionResponse
	var replay idem.State
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		if _, err := q.LockUserRow(ctx, p.UserID); err != nil {
			return err
		}
		state, _, err := idem.Begin(ctx, q, k, now)
		if err != nil {
			return err
		}
		if state != idem.Fresh {
			replay = state
			return nil
		}
		if n, err := q.UseBootstrap(ctx, db.UseBootstrapParams{TokenHash: p.BootstrapHash, UsedAt: ptr(now)}); err != nil || n == 0 {
			if err == nil {
				err = httpx.AuthFailed()
			}
			return err
		}
		if err := q.ReplacePin(ctx, db.ReplacePinParams{ID: p.UserID, PinHash: &hash, PepperVersion: ptr(s.Hasher.CurrentVersion()), PinSetAt: ptr(now)}); err != nil {
			return err
		}
		if err := q.ResetLockStateAndCoolOff(ctx, db.ResetLockStateAndCoolOffParams{ID: p.UserID, CoolingOffUntil: ptr(until)}); err != nil {
			return err
		}
		if err := q.RevokeUserSessions(ctx, db.RevokeUserSessionsParams{UserID: p.UserID, RevokedAt: ptr(now), RevokeReason: ptr("pin_reset")}); err != nil {
			return err
		}
		if err := q.RevokeAllUserKeys(ctx, db.RevokeAllUserKeysParams{UserID: p.UserID, RevokedAt: ptr(now), RevokeReason: ptr("pin_reset")}); err != nil {
			return err
		}
		if err := q.RevokeOtherDevices(ctx, db.RevokeOtherDevicesParams{UserID: p.UserID, ID: p.DeviceID, RevokedAt: ptr(now)}); err != nil {
			return err
		}
		if err := q.InvalidateUserChallenges(ctx, db.InvalidateUserChallengesParams{UserID: p.UserID, ConsumedAt: ptr(now)}); err != nil {
			return err
		}
		is, err := s.Auth.Create(ctx, q, p.UserID, p.DeviceID, "pin")
		if err != nil {
			return err
		}
		if out, err = s.sessionResponse(ctx, q, is, ptr(0)); err != nil {
			return err
		}
		return idem.Complete(ctx, q, k, http.StatusOK, nil)
	})
	if err != nil {
		return nil, s.fail(ctx, "resetPin", err)
	}
	if herr := idemOutcomeErr(replay); herr != nil {
		return nil, herr
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.PinReset, UserID: &p.UserID, DeviceID: &p.DeviceID})
	s.Audit.Emit(ctx, audit.Event{Type: audit.CoolingOffStarted, UserID: &p.UserID, DeviceID: &p.DeviceID, Meta: map[string]any{"reason": "pin_reset"}})
	return apigen.ResetPin200JSONResponse{Body: out}, nil
}
