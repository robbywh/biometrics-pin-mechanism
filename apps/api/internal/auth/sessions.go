package auth

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

type Config struct {
	UnlockWindow, IdleWindow time.Duration
	AbsoluteLife, IdleLife   time.Duration
}

func DefaultConfig() Config {
	return Config{UnlockWindow: 15 * time.Minute, IdleWindow: 5 * time.Minute, AbsoluteLife: 30 * 24 * time.Hour, IdleLife: 7 * 24 * time.Hour}
}

type Service struct {
	St    *store.Store
	Tok   *Tokens
	Clk   clock.Clock
	Cfg   Config
	Audit *audit.Writer
}

// Issued is a freshly created session with its tokens.
type Issued struct {
	Access    string
	ExpiresIn int
	Refresh   string
	SessionID uuid.UUID
	UserID    uuid.UUID
	DeviceID  uuid.UUID
	AMR       string
	AuthTime  time.Time
}

func ptr[T any](v T) *T { return &v }

// Create starts a NEW refresh family for the device (SEC-037): every earlier family of the device is revoked in the
// same transaction. last_unlock_at is set (callers: pin set/verify/reset/change, biometric verify).
func (s *Service) Create(ctx context.Context, q *db.Queries, userID, deviceID uuid.UUID, amr string) (*Issued, error) {
	now := s.Clk.Now()
	if err := q.RevokeDeviceSessions(ctx, db.RevokeDeviceSessionsParams{DeviceID: deviceID, RevokedAt: ptr(now), RevokeReason: ptr("new_unlock")}); err != nil {
		return nil, err
	}
	return s.insert(ctx, q, userID, deviceID, uuid.New(), nil, amr, now, now, now.Add(s.Cfg.AbsoluteLife))
}

func (s *Service) insert(ctx context.Context, q *db.Queries, userID, deviceID, family uuid.UUID, parent *uuid.UUID, amr string, authTime, created, expires time.Time) (*Issued, error) {
	raw, hash, err := NewOpaque()
	if err != nil {
		return nil, err
	}
	id := uuid.New()
	if err := q.InsertSession(ctx, db.InsertSessionParams{ID: id, UserID: userID, DeviceID: deviceID, FamilyID: family, ParentID: parent,
		RefreshHash: hash, Amr: amr, CreatedAt: created, LastUnlockAt: authTime, ExpiresAt: expires}); err != nil {
		return nil, err
	}
	access, exp, err := s.Tok.Issue(userID, id, deviceID, amr, authTime)
	if err != nil {
		return nil, err
	}
	return &Issued{Access: access, ExpiresIn: exp, Refresh: raw, SessionID: id, UserID: userID, DeviceID: deviceID, AMR: amr, AuthTime: authTime}, nil
}

// RotateOutcome is the result of POST /auth/refresh before response mapping.
type RotateOutcome int

const (
	RotateOK RotateOutcome = iota
	RotateAuthFailed
	RotateReuse
	RotateUnlockRequired
)

// Rotate implements SEC-032/033: single-use rotation with reuse detection and the server-enforced unlock window.
// UNLOCK_REQUIRED and AUTH_FAILED (non-reuse) leave all state untouched.
func (s *Service) Rotate(ctx context.Context, refreshRaw string) (*Issued, RotateOutcome, error) {
	hash := HashToken(refreshRaw)
	var out RotateOutcome
	var issued *Issued
	var reuseUser, reuseDevice uuid.UUID
	err := s.St.InTx(ctx, func(q *db.Queries) error {
		now := s.Clk.Now()
		row, err := q.GetSessionByRefreshHash(ctx, hash)
		if store.NotFound(err) {
			out = RotateAuthFailed
			return nil
		}
		if err != nil {
			return err
		}
		reuse := func() error {
			out, reuseUser, reuseDevice = RotateReuse, row.UserID, row.DeviceID
			return q.RevokeFamily(ctx, db.RevokeFamilyParams{FamilyID: row.FamilyID, RevokedAt: ptr(now), RevokeReason: ptr("refresh_reuse")})
		}
		if row.RevokedAt != nil || row.UsedAt != nil {
			return reuse()
		}
		dev, err := q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: row.DeviceID, UserID: row.UserID})
		if err != nil || dev.RevokedAt != nil || !now.Before(row.ExpiresAt) || now.Sub(row.LastSeenAt) > s.Cfg.IdleLife {
			out = RotateAuthFailed
			return nil
		}
		if now.Sub(row.LastUnlockAt) > s.Cfg.UnlockWindow || now.Sub(row.LastSeenAt) > s.Cfg.IdleWindow {
			out = RotateUnlockRequired
			return nil
		}
		if _, err := q.MarkSessionUsed(ctx, db.MarkSessionUsedParams{RefreshHash: hash, UsedAt: ptr(now)}); err != nil {
			if store.NotFound(err) {
				return reuse() // lost the race: someone else rotated this token
			}
			return err
		}
		parent := row.ID
		issued, err = s.insert(ctx, q, row.UserID, row.DeviceID, row.FamilyID, &parent, row.Amr, row.LastUnlockAt, now, row.ExpiresAt)
		out = RotateOK
		return err
	})
	if err != nil {
		return nil, RotateAuthFailed, err
	}
	if out == RotateReuse {
		s.Audit.Emit(ctx, audit.Event{Type: audit.RefreshReuse, UserID: &reuseUser, DeviceID: &reuseDevice, Result: "fail"})
	}
	return issued, out, nil
}

// Logout revokes the session's whole family.
func (s *Service) Logout(ctx context.Context, userID, sessionID uuid.UUID) error {
	now := s.Clk.Now()
	row, err := s.St.Q.GetSessionRaw(ctx, db.GetSessionRawParams{ID: sessionID, UserID: userID})
	if err != nil {
		if store.NotFound(err) {
			return nil
		}
		return err
	}
	return s.St.Q.RevokeFamily(ctx, db.RevokeFamilyParams{FamilyID: row.FamilyID, RevokedAt: ptr(now), RevokeReason: ptr("logout")})
}

// Principal is the authenticated caller resolved from a credential.
type Principal struct {
	UserID     uuid.UUID
	DeviceID   uuid.UUID // zero for unbound bootstrap tokens
	SessionID  uuid.UUID
	AMR        string
	AuthTime   time.Time
	LastUnlock time.Time

	// bootstrap
	Scope         string
	BootstrapHash []byte
	Bound         bool
	Used          bool

	// device credential
	FromRefresh bool

	// access token whose session was revoked by PUT /pin itself (idempotency lookup only)
	RevokedByPinChange bool
}

// Access resolves an access JWT. A bootstrap token yields 403 SCOPE_INSUFFICIENT. allowPinChanged lets PUT /pin
// answer an idempotent retry whose session was revoked by the original request.
func (s *Service) Access(ctx context.Context, bearer string, allowPinChanged bool) (*Principal, *httpx.Error) {
	if bearer == "" {
		return nil, httpx.AuthFailed()
	}
	c, err := s.Tok.Parse(bearer)
	if err != nil {
		if LooksOpaque(bearer) {
			if b, err := s.St.Q.GetBootstrap(ctx, HashToken(bearer)); err == nil && s.Clk.Now().Before(b.ExpiresAt) {
				return nil, scopeInsufficient()
			}
		}
		return nil, httpx.AuthFailed()
	}
	uid, e1 := uuid.Parse(c.Subject)
	sid, e2 := uuid.Parse(c.SID)
	did, e3 := uuid.Parse(c.DID)
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, httpx.AuthFailed()
	}
	now := s.Clk.Now()
	row, err := s.St.Q.TouchSession(ctx, db.TouchSessionParams{ID: sid, LastSeenAt: now, UserID: uid})
	if err != nil {
		if store.NotFound(err) && allowPinChanged {
			if raw, err2 := s.St.Q.GetSessionRaw(ctx, db.GetSessionRawParams{ID: sid, UserID: uid}); err2 == nil && raw.RevokeReason != nil && *raw.RevokeReason == "pin_changed" && raw.DeviceID == did {
				return &Principal{UserID: uid, DeviceID: did, SessionID: sid, RevokedByPinChange: true}, nil
			}
		}
		if !store.NotFound(err) {
			return nil, httpx.Unavailable()
		}
		return nil, httpx.AuthFailed()
	}
	if row.DeviceID != did {
		return nil, httpx.AuthFailed()
	}
	return &Principal{UserID: uid, DeviceID: did, SessionID: sid, AMR: row.Amr, AuthTime: time.Unix(c.AuthTime, 0).UTC(), LastUnlock: row.LastUnlockAt}, nil
}

func scopeInsufficient() *httpx.Error { return httpx.New(403, "SCOPE_INSUFFICIENT") }

// ScopeInsufficient is exported for handlers.
func ScopeInsufficient() *httpx.Error { return scopeInsufficient() }

// Bootstrap resolves a bootstrap token and checks its scope. Used tokens are returned flagged (Used) so a handler can
// still answer an idempotent replay; expired/unknown tokens fail.
func (s *Service) Bootstrap(ctx context.Context, bearer string, scopes ...string) (*Principal, *httpx.Error) {
	if bearer == "" || !LooksOpaque(bearer) {
		return nil, httpx.AuthFailed()
	}
	b, err := s.St.Q.GetBootstrap(ctx, HashToken(bearer))
	if err != nil {
		if store.NotFound(err) {
			return nil, httpx.AuthFailed()
		}
		return nil, httpx.Unavailable()
	}
	if !s.Clk.Now().Before(b.ExpiresAt) {
		return nil, httpx.AuthFailed()
	}
	p := &Principal{UserID: b.UserID, Scope: b.Scope, BootstrapHash: HashToken(bearer), Bound: b.DeviceID != nil, Used: b.UsedAt != nil}
	if b.DeviceID != nil {
		p.DeviceID = *b.DeviceID
		if d, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: *b.DeviceID, UserID: b.UserID}); err != nil || d.RevokedAt != nil {
			return nil, httpx.AuthFailed()
		}
	}
	ok := false
	for _, sc := range scopes {
		if sc == b.Scope {
			ok = true
		}
	}
	if !ok {
		return nil, scopeInsufficient()
	}
	return p, nil
}

// DeviceCredential resolves the pin/verify credential (SEC-014): the device's current refresh token or a device-bound
// bootstrap token with scope pin-verify. It has no side effects, and any mismatch with the body deviceId fails.
func (s *Service) DeviceCredential(ctx context.Context, bearer string, bodyDevice uuid.UUID) (*Principal, *httpx.Error) {
	if bearer == "" || !LooksOpaque(bearer) {
		return nil, httpx.AuthFailed()
	}
	now := s.Clk.Now()
	hash := HashToken(bearer)
	if row, err := s.St.Q.GetSessionByRefreshHash(ctx, hash); err == nil {
		if row.RevokedAt != nil || row.UsedAt != nil || !now.Before(row.ExpiresAt) || now.Sub(row.LastSeenAt) > s.Cfg.IdleLife || row.DeviceID != bodyDevice {
			return nil, httpx.AuthFailed()
		}
		if d, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: row.DeviceID, UserID: row.UserID}); err != nil || d.RevokedAt != nil {
			return nil, httpx.AuthFailed()
		}
		return &Principal{UserID: row.UserID, DeviceID: row.DeviceID, FromRefresh: true}, nil
	} else if !store.NotFound(err) {
		return nil, httpx.Unavailable()
	}
	b, err := s.St.Q.GetBootstrap(ctx, hash)
	if err != nil {
		if store.NotFound(err) {
			return nil, httpx.AuthFailed()
		}
		return nil, httpx.Unavailable()
	}
	if b.Scope != "pin-verify" || b.UsedAt != nil || !now.Before(b.ExpiresAt) || b.DeviceID == nil || *b.DeviceID != bodyDevice {
		return nil, httpx.AuthFailed()
	}
	if d, err := s.St.Q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: *b.DeviceID, UserID: b.UserID}); err != nil || d.RevokedAt != nil {
		return nil, httpx.AuthFailed()
	}
	return &Principal{UserID: b.UserID, DeviceID: *b.DeviceID, Scope: b.Scope, BootstrapHash: hash, Bound: true}, nil
}
