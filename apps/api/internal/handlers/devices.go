package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/cryptomsg"
	"github.com/cryptoapp/api/internal/idem"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/stepup"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

const maxActiveDevices = 5

const epRegisterDevice = "POST /devices"

func (s *Server) RegisterDevice(ctx context.Context, req apigen.RegisterDeviceRequestObject) (apigen.RegisterDeviceResponseObject, error) {
	p := principal(ctx)
	b := req.Body
	k, herr := s.idemKey(p.UserID, epRegisterDevice, req.Params.IdempotencyKey, b)
	if herr != nil {
		return nil, herr
	}
	// Replay check BEFORE the "token not yet bound" check: after the first success the token is bound to the device.
	st, stored, herr := s.peekIdem(ctx, k)
	if herr != nil {
		return nil, herr
	}
	if resp, herr := s.deviceReplay(st, stored); herr != nil || resp != nil {
		if herr != nil {
			return nil, herr
		}
		return resp, nil
	}
	if p.Used {
		return nil, httpx.AuthFailed()
	}
	if p.Bound {
		return nil, auth403()
	}
	now := s.Clk.Now()
	var out apigen.RegisterDeviceResponse
	var replayResp apigen.RegisterDeviceResponseObject
	var coolingStarted bool
	var devID uuid.UUID
	err := s.St.InTx(ctx, func(q *db.Queries) error {
		u, err := q.LockUserRow(ctx, p.UserID) // serialises the cap check per user
		if err != nil {
			return err
		}
		state, stored, err := idem.Begin(ctx, q, k, now)
		if err != nil {
			return err
		}
		if state != idem.Fresh {
			resp, herr := s.deviceReplay(state, stored)
			if herr != nil {
				return herr
			}
			replayResp = resp
			return nil
		}
		active, err := q.CountActiveDevices(ctx, u.ID)
		if err != nil {
			return err
		}
		if active >= maxActiveDevices && p.Scope != "pin-reset" {
			return httpx.New(http.StatusConflict, "DEVICE_LIMIT")
		}
		total, err := q.CountAllDevices(ctx, u.ID)
		if err != nil {
			return err
		}
		first := total == 0 // "first device" = the user never had one (revoked devices count)
		var cool *time.Time
		if !first {
			cool = ptr(now.Add(s.Cfg.CoolingOffDuration))
		}
		var risk []byte
		if b.Risk != nil {
			risk, _ = json.Marshal(b.Risk)
		}
		d, err := q.InsertDevice(ctx, db.InsertDeviceParams{ID: uuid.New(), UserID: u.ID, Platform: string(b.Platform), Name: b.Name, Risk: risk, CreatedAt: now, CoolingOffUntil: cool})
		if err != nil {
			return err
		}
		n, err := q.BindBootstrap(ctx, db.BindBootstrapParams{TokenHash: p.BootstrapHash, DeviceID: ptr(d.ID), ExpiresAt: now})
		if err != nil {
			return err
		}
		if n == 0 {
			return httpx.AuthFailed()
		}
		devID = d.ID
		out = apigen.RegisterDeviceResponse{DeviceId: d.ID, CreatedAt: d.CreatedAt.Unix()}
		if cool != nil {
			out.CoolingOffUntil = ptr(cool.Unix())
			coolingStarted = true
		}
		body, _ := json.Marshal(out)
		return idem.Complete(ctx, q, k, http.StatusCreated, body)
	})
	if err != nil {
		return nil, s.fail(ctx, "registerDevice", err)
	}
	if replayResp != nil {
		return replayResp, nil
	}
	httpx.InfoFrom(ctx).SetActor(p.UserID.String(), devID.String())
	s.Audit.Emit(ctx, audit.Event{Type: audit.DeviceAdded, UserID: &p.UserID, DeviceID: &devID, Meta: map[string]any{"platform": string(b.Platform), "scope": p.Scope}})
	if coolingStarted {
		s.Audit.Emit(ctx, audit.Event{Type: audit.CoolingOffStarted, UserID: &p.UserID, DeviceID: &devID, Meta: map[string]any{"reason": "new_device"}})
	}
	return apigen.RegisterDevice201JSONResponse(out), nil
}

func (s *Server) deviceReplay(st idem.State, stored *idem.Stored) (apigen.RegisterDeviceResponseObject, *httpx.Error) {
	switch st {
	case idem.Reused:
		return nil, errReused()
	case idem.Replay:
		var r apigen.RegisterDeviceResponse
		if stored == nil || json.Unmarshal(stored.Body, &r) != nil {
			return nil, httpx.Internal()
		}
		return apigen.RegisterDevice200JSONResponse(r), nil
	}
	return nil, nil
}

func auth403() *httpx.Error { return httpx.New(http.StatusForbidden, "SCOPE_INSUFFICIENT") }

func (s *Server) ListDevices(ctx context.Context, _ apigen.ListDevicesRequestObject) (apigen.ListDevicesResponseObject, error) {
	p := principal(ctx)
	rows, err := s.St.Q.ListActiveDevices(ctx, p.UserID)
	if err != nil {
		return nil, s.fail(ctx, "listDevices", err)
	}
	out := apigen.DeviceList{Devices: make([]apigen.Device, 0, len(rows))}
	for _, d := range rows {
		out.Devices = append(out.Devices, apigen.Device{Id: d.ID, Name: d.Name, Platform: apigen.DevicePlatform(d.Platform), CreatedAt: d.CreatedAt.Unix(),
			LastSeenAt: d.LastSeenAt.Unix(), Current: d.ID == p.DeviceID, BiometricEnabled: d.BiometricEnabled})
	}
	return apigen.ListDevices200JSONResponse(out), nil
}

// requireStepUp validates presence of the step-up header (missing/placeholder => 403 STEPUP_REQUIRED).
func requireStepUp(tok string, required string) (string, *httpx.Error) {
	if tok == "" || tok == MissingStepUp {
		e := httpx.New(http.StatusForbidden, "STEPUP_REQUIRED")
		e.Required = required
		return "", e
	}
	return tok, nil
}

func stepUpInvalid() *httpx.Error { return httpx.New(http.StatusForbidden, "STEPUP_INVALID") }

// revokeDeviceTx revokes a device and everything bound to it (SEC-024).
func (s *Server) revokeDeviceTx(ctx context.Context, q *db.Queries, userID, deviceID uuid.UUID, now time.Time, reason string) (bool, error) {
	n, err := q.RevokeDevice(ctx, db.RevokeDeviceParams{ID: deviceID, UserID: userID, RevokedAt: ptr(now)})
	if err != nil || n == 0 {
		return false, err
	}
	if err := q.RevokeDeviceSessions(ctx, db.RevokeDeviceSessionsParams{DeviceID: deviceID, RevokedAt: ptr(now), RevokeReason: ptr(reason)}); err != nil {
		return false, err
	}
	if _, err := q.RevokeActiveKey(ctx, db.RevokeActiveKeyParams{DeviceID: deviceID, RevokedAt: ptr(now), RevokeReason: ptr(reason)}); err != nil {
		return false, err
	}
	return true, q.InvalidateDeviceChallenges(ctx, db.InvalidateDeviceChallengesParams{DeviceID: deviceID, ConsumedAt: ptr(now)})
}

func (s *Server) RevokeDevice(ctx context.Context, req apigen.RevokeDeviceRequestObject) (apigen.RevokeDeviceResponseObject, error) {
	p := principal(ctx)
	id := req.DeviceId
	d, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: id, UserID: p.UserID})
	if err != nil || d.RevokedAt != nil {
		if err != nil && !store.NotFound(err) {
			return nil, s.fail(ctx, "revokeDevice", err)
		}
		return nil, httpx.NotFound()
	}
	other := id != p.DeviceID
	var tok string
	if other {
		var herr *httpx.Error
		raw := ""
		if req.Params.XStepUpToken != nil {
			raw = *req.Params.XStepUpToken
		}
		if tok, herr = requireStepUp(raw, "pin"); herr != nil {
			return nil, herr
		}
	}
	now := s.Clk.Now()
	var revoked bool
	err = s.St.InTx(ctx, func(q *db.Queries) error {
		if other {
			out, proof, err := stepup.Consume(ctx, q, tok, p.UserID, p.SessionID, p.DeviceID, "revoke_device", cryptomsg.ActionHash("revoke_device", id.String()), now)
			if err != nil {
				return err
			}
			switch {
			case out == stepup.Mismatch:
				return &store.CommitErr{Err: stepUpInvalid()}
			case out == stepup.Invalid || proof != "pin":
				return stepUpInvalid()
			}
		}
		var err error
		revoked, err = s.revokeDeviceTx(ctx, q, p.UserID, id, now, "device_revoked")
		return err
	})
	if err != nil {
		return nil, s.fail(ctx, "revokeDevice", err)
	}
	if revoked {
		s.Audit.Emit(ctx, audit.Event{Type: audit.DeviceRevoked, UserID: &p.UserID, DeviceID: &id, Meta: map[string]any{"reason": map[bool]string{true: "other", false: "current"}[other]}})
	}
	return apigen.RevokeDevice204Response{}, nil
}
