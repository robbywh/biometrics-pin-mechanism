package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/auth"
	"github.com/cryptoapp/api/internal/lockout"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

func (s *Server) Healthz(ctx context.Context, _ apigen.HealthzRequestObject) (apigen.HealthzResponseObject, error) {
	c, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.St.Ping(c); err != nil {
		return nil, httpx.Unavailable()
	}
	return apigen.Healthz200JSONResponse{Status: apigen.HealthStatus("ok")}, nil
}

// DemoLogin issues a limited-scope bootstrap token (SEC-016). Unknown user and wrong secret are indistinguishable.
func (s *Server) DemoLogin(ctx context.Context, req apigen.DemoLoginRequestObject) (apigen.DemoLoginResponseObject, error) {
	if !s.Cfg.DemoMode {
		return nil, httpx.NotFound()
	}
	b := req.Body
	secret, known := s.Cfg.DemoSecrets[b.Username]
	provided := ""
	if b.Secret != nil {
		provided = *b.Secret
	}
	if !known {
		secret = "unknown-user-placeholder-secret"
	}
	secretOK := constEq(secret, provided) && known
	// Same DB read on both paths (timing equalisation, best effort).
	u, uerr := s.St.Q.GetUserByUsername(ctx, b.Username)
	if !secretOK || uerr != nil {
		if uerr != nil && !store.NotFound(uerr) {
			return nil, s.fail(ctx, "demoLogin", uerr)
		}
		s.Audit.Emit(ctx, audit.Event{Type: audit.LoginFail, Result: "fail", Meta: map[string]any{"method": "demo"}})
		return nil, httpx.AuthFailed()
	}
	scope := "pin-setup"
	if u.PinHash != nil {
		scope = "pin-verify"
		if b.Intent == apigen.DemoLoginRequestIntentReset {
			scope = "pin-reset"
		}
	}
	raw, hash, err := auth.NewOpaque()
	if err != nil {
		return nil, s.fail(ctx, "demoLogin", err)
	}
	now := s.Clk.Now()
	if err := s.St.Q.InsertBootstrap(ctx, db.InsertBootstrapParams{TokenHash: hash, UserID: u.ID, Scope: scope, ExpiresAt: now.Add(s.Cfg.BootstrapTTL), CreatedAt: now}); err != nil {
		return nil, s.fail(ctx, "demoLogin", err)
	}
	httpx.InfoFrom(ctx).SetActor(u.ID.String(), "")
	s.Audit.Emit(ctx, audit.Event{Type: audit.LoginOK, UserID: &u.ID, Meta: map[string]any{"method": "demo", "scope": scope}})
	return apigen.DemoLogin200JSONResponse{Body: apigen.BootstrapResponse{BootstrapToken: raw, ExpiresIn: int(s.Cfg.BootstrapTTL.Seconds()), Scope: apigen.BootstrapResponseScope(scope)}}, nil
}

// VerifyPin: device credential first (no counter change on failure), then block/limit checks, then the shared lockout.
func (s *Server) VerifyPin(ctx context.Context, req apigen.VerifyPinRequestObject) (apigen.VerifyPinResponseObject, error) {
	p := principal(ctx)
	b := req.Body
	if b.Pin == nil {
		return nil, httpx.Validation()
	}
	now := s.Clk.Now()
	// Per-device block (SEC-009): never touches the user counter.
	if f, err := s.St.Q.GetDevicePinFailure(ctx, p.DeviceID); err == nil {
		if f.BlockedUntil != nil && f.BlockedUntil.After(now) {
			return nil, httpx.RateLimited(int(f.BlockedUntil.Sub(now).Seconds()+0.999), nil)
		}
	} else if !store.NotFound(err) {
		return nil, s.fail(ctx, "verifyPin", err)
	}
	if herr := s.limit(ctx, "pinverify-dev", p.DeviceID.String(), s.Cfg.Limits.PinVerifyDevice, true); herr != nil {
		return nil, herr
	}
	res, err := s.Lock.Attempt(ctx, p.UserID, *b.Pin, &p.DeviceID, true)
	if err != nil {
		return nil, s.fail(ctx, "verifyPin", err)
	}
	if res.Kind != lockout.OK {
		if res.Kind == lockout.Invalid {
			s.recordDeviceFailure(ctx, p.DeviceID, p.UserID, now)
		}
		return nil, lockout.Error(res, now)
	}
	var out apigen.SessionResponse
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		if p.BootstrapHash != nil {
			if n, err := q.UseBootstrap(ctx, db.UseBootstrapParams{TokenHash: p.BootstrapHash, UsedAt: ptr(now)}); err != nil || n == 0 {
				if err == nil {
					err = httpx.AuthFailed()
				}
				return err
			}
		}
		is, err := s.Auth.Create(ctx, q, p.UserID, p.DeviceID, "pin")
		if err != nil {
			return err
		}
		if b.Risk != nil {
			s.storeRisk(ctx, q, p.UserID, p.DeviceID, b.Risk, now)
		}
		_ = q.TouchDevice(ctx, db.TouchDeviceParams{ID: p.DeviceID, LastSeenAt: now})
		if err := q.UnsuspendKey(ctx, p.DeviceID); err != nil { // PIN unlock re-enables a suspended biometric key
			return err
		}
		out, err = s.sessionResponse(ctx, q, is, ptr(res.RecentFailures))
		return err
	})
	if err != nil {
		return nil, s.fail(ctx, "verifyPin", err)
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.LoginOK, UserID: &p.UserID, DeviceID: &p.DeviceID, Meta: map[string]any{"method": "pin", "recent_failures": res.RecentFailures}})
	return apigen.VerifyPin200JSONResponse{Body: out}, nil
}

func (s *Server) recordDeviceFailure(ctx context.Context, dev, user uuid.UUID, now time.Time) {
	l := s.Cfg.Limits
	if l.DeviceFailMax <= 0 {
		return
	}
	f, err := s.St.Q.RecordDevicePinFailure(ctx, db.RecordDevicePinFailureParams{DeviceID: dev, WindowStartedAt: now, WindowFloor: now.Add(-l.DeviceFailWindow),
		Now: now, MaxFails: int32(l.DeviceFailMax), BlockUntil: now.Add(l.DeviceBlockFor)})
	if err != nil {
		return
	}
	if f.BlockedUntil != nil && f.BlockedUntil.After(now) && int(f.FailCount) == l.DeviceFailMax {
		s.Audit.Emit(ctx, audit.Event{Type: audit.DeviceBlocked, UserID: &user, DeviceID: &dev, Result: "fail"})
	}
}

func (s *Server) storeRisk(ctx context.Context, q *db.Queries, user, dev uuid.UUID, r *apigen.RiskSignals, now time.Time) {
	b, err := jsonMarshal(r)
	if err != nil {
		return
	}
	_ = q.UpdateDeviceRisk(ctx, db.UpdateDeviceRiskParams{ID: dev, UserID: user, Risk: b, LastSeenAt: now})
}

func (s *Server) Refresh(ctx context.Context, _ apigen.RefreshRequestObject) (apigen.RefreshResponseObject, error) {
	raw := bearer(ctx)
	if !auth.LooksOpaque(raw) {
		return nil, httpx.AuthFailed()
	}
	// Per-device limit (6/min) keyed by the token's device; unknown tokens fall through to the uniform failure.
	if row, err := s.St.Q.GetSessionByRefreshHash(ctx, auth.HashToken(raw)); err == nil {
		httpx.InfoFrom(ctx).SetActor(row.UserID.String(), row.DeviceID.String())
		if herr := s.limit(ctx, "refresh-dev", row.DeviceID.String(), s.Cfg.Limits.RefreshDevice, true); herr != nil {
			return nil, herr
		}
	}
	is, out, err := s.Auth.Rotate(ctx, raw)
	if err != nil {
		return nil, s.fail(ctx, "refresh", err)
	}
	switch out {
	case auth.RotateOK:
		var resp apigen.SessionResponse
		if err := s.St.InTx(ctx, func(q *db.Queries) (e error) { resp, e = s.sessionResponse(ctx, q, is, nil); return }); err != nil {
			return nil, s.fail(ctx, "refresh", err)
		}
		return apigen.Refresh200JSONResponse{Body: resp}, nil
	case auth.RotateUnlockRequired:
		return nil, httpx.New(http.StatusUnauthorized, "UNLOCK_REQUIRED")
	default:
		return nil, httpx.AuthFailed()
	}
}

func (s *Server) Logout(ctx context.Context, _ apigen.LogoutRequestObject) (apigen.LogoutResponseObject, error) {
	p := principal(ctx)
	if err := s.Auth.Logout(ctx, p.UserID, p.SessionID); err != nil {
		return nil, s.fail(ctx, "logout", err)
	}
	return apigen.Logout204Response{}, nil
}
