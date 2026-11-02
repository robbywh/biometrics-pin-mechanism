// Package handlers implements apigen.StrictServerInterface. Handlers return typed success responses or a
// *httpx.Error (rendered by the central error handler); no other error text leaves the process.
package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/auth"
	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/config"
	"github.com/cryptoapp/api/internal/idem"
	"github.com/cryptoapp/api/internal/lockout"
	"github.com/cryptoapp/api/internal/pin"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/ratelimit"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

// MissingStepUp is the placeholder the router injects when X-StepUp-Token is absent so that the contract's
// 403 STEPUP_REQUIRED (not a 400) is returned after authentication. It is not a valid token shape for lookups.
const MissingStepUp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// Hooks are test seams (fault injection).
type Hooks struct {
	AfterStepUpConsume func() error
}

type Server struct {
	Cfg    *config.Config
	St     *store.Store
	Clk    clock.Clock
	Log    *slog.Logger
	Audit  *audit.Writer
	Auth   *auth.Service
	Lock   *lockout.Service
	Hasher *pin.Hasher
	Lim    *ratelimit.Limiter
	Hooks  Hooks

	macKey []byte
}

var _ apigen.StrictServerInterface = (*Server)(nil)

// New wires derived values.
func New(s Server) *Server {
	m := hmac.New(sha256.New, s.Cfg.Pepper)
	m.Write([]byte("idempotency-request-mac-v1"))
	s.macKey = m.Sum(nil)
	return &s
}

type ctxKey int

const (
	principalKey ctxKey = iota + 1
	bearerKey
)

func WithPrincipal(ctx context.Context, p *auth.Principal) context.Context {
	return context.WithValue(ctx, principalKey, p)
}
func principal(ctx context.Context) *auth.Principal {
	p, _ := ctx.Value(principalKey).(*auth.Principal)
	return p
}

// WithBearer stores the raw Authorization bearer (refresh token) for the refresh handler.
func WithBearer(ctx context.Context, b string) context.Context {
	return context.WithValue(ctx, bearerKey, b)
}
func bearer(ctx context.Context) string { s, _ := ctx.Value(bearerKey).(string); return s }

func ptr[T any](v T) *T { return &v }

func internal(ctx context.Context, log *slog.Logger, op string, err error) *httpx.Error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return httpx.Unavailable()
	}
	log.ErrorContext(ctx, "internal error", "component", "handler", "op", op, "err_class", "internal")
	return httpx.Internal()
}

// fail maps infrastructure errors (and pin.ErrBusy) to contract errors.
func (s *Server) fail(ctx context.Context, op string, err error) *httpx.Error {
	var he *httpx.Error
	switch {
	case errors.As(err, &he):
		return he
	case errors.Is(err, pin.ErrBusy):
		return httpx.RateLimited(2, nil)
	}
	return internal(ctx, s.Log, op, err)
}

// limit applies a rate-limit rule; on success it optionally exposes RateLimit-* headers, on rejection it audits.
func (s *Server) limit(ctx context.Context, class, key string, lim config.Limit, headers bool) *httpx.Error {
	if lim.N <= 0 {
		return nil
	}
	r := s.Lim.Allow(class+":"+key, lim)
	if r.Allowed {
		if headers {
			httpx.SetHeader(ctx, "RateLimit-Limit", strconv.Itoa(r.Limit))
			httpx.SetHeader(ctx, "RateLimit-Remaining", strconv.Itoa(r.Remaining))
			httpx.SetHeader(ctx, "RateLimit-Reset", strconv.Itoa(r.ResetSec))
		}
		return nil
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.RateLimited, Result: "fail", Meta: map[string]any{"limit_class": class}})
	return httpx.RateLimited(r.RetryAfter, &httpx.RateInfo{Limit: r.Limit, Remaining: 0, Reset: r.ResetSec})
}

func ratFromString(s string) *big.Rat {
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return new(big.Rat)
	}
	return r
}

// decimalString renders r with up to 18 fraction digits, trailing zeros trimmed (matches DecimalString).
func decimalString(r *big.Rat) string {
	s := r.FloatString(18)
	for len(s) > 1 && s[len(s)-1] == '0' && containsDot(s) {
		s = s[:len(s)-1]
	}
	if len(s) > 0 && s[len(s)-1] == '.' {
		s = s[:len(s)-1]
	}
	return s
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}

func constEq(a, b string) bool {
	ha, hb := sha256.Sum256([]byte(a)), sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ha[:], hb[:]) == 1
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// idemKey builds the idempotency identity from the typed header and the canonical request body.
func (s *Server) idemKey(userID uuid.UUID, endpoint string, key uuid.UUID, body any) (idem.Key, *httpx.Error) {
	b, err := json.Marshal(body)
	if err != nil {
		return idem.Key{}, httpx.Validation()
	}
	k, err := idem.New(userID, endpoint, key, b, s.macKey)
	if err != nil {
		return idem.Key{}, httpx.Validation()
	}
	return k, nil
}

// peekIdem answers replays before any credential is consumed. found=true means the caller must return replayErr.
func (s *Server) peekIdem(ctx context.Context, k idem.Key) (state idem.State, st *idem.Stored, err *httpx.Error) {
	state, st, e := idem.Peek(ctx, s.St.Q, k, s.Clk.Now())
	if e != nil {
		return state, nil, s.fail(ctx, "idem.peek", e)
	}
	return state, st, nil
}

var (
	errReplay = func() *httpx.Error { return httpx.New(http.StatusConflict, "IDEMPOTENT_REPLAY") }
	errReused = func() *httpx.Error { return httpx.New(http.StatusUnprocessableEntity, "IDEMPOTENCY_KEY_REUSED") }
)

// idemOutcomeErr converts Replay/Reused for token-bearing endpoints (never replays tokens).
func idemOutcomeErr(st idem.State) *httpx.Error {
	switch st {
	case idem.Replay:
		return errReplay()
	case idem.Reused:
		return errReused()
	}
	return nil
}

// sessionResponse builds the contract SessionResponse for an issued session.
func (s *Server) sessionResponse(ctx context.Context, q *db.Queries, is *auth.Issued, recent *int) (apigen.SessionResponse, error) {
	now := s.Clk.Now()
	u, err := q.GetUserByID(ctx, is.UserID)
	if err != nil {
		return apigen.SessionResponse{}, err
	}
	d, err := q.GetDeviceForUser(ctx, db.GetDeviceForUserParams{ID: is.DeviceID, UserID: is.UserID})
	if err != nil {
		return apigen.SessionResponse{}, err
	}
	bio := true
	if _, err := q.GetActiveKey(ctx, is.DeviceID); err != nil {
		if !store.NotFound(err) {
			return apigen.SessionResponse{}, err
		}
		bio = false
	}
	var cool *int64
	for _, t := range []*time.Time{u.CoolingOffUntil, d.CoolingOffUntil} {
		if t != nil && t.After(now) && (cool == nil || t.Unix() > *cool) {
			cool = ptr(t.Unix())
		}
	}
	return apigen.SessionResponse{
		AccessToken: is.Access, ExpiresIn: is.ExpiresIn, RefreshToken: is.Refresh, Amr: apigen.SessionResponseAmr(is.AMR),
		AuthTime: is.AuthTime.Unix(), DeviceId: is.DeviceID, BiometricEnabled: bio, RecentFailures: recent, CoolingOffUntil: cool,
	}, nil
}

func (s *Server) coolingActive(u db.User, d db.Device, k *db.DeviceKey, now time.Time) (bool, time.Time) {
	var until time.Time
	for _, t := range []*time.Time{u.CoolingOffUntil, d.CoolingOffUntil, keyCool(k)} {
		if t != nil && t.After(now) && t.After(until) {
			until = *t
		}
	}
	return !until.IsZero(), until
}

func keyCool(k *db.DeviceKey) *time.Time {
	if k == nil {
		return nil
	}
	return k.CoolingOffUntil
}

func isNoRows(err error) bool { return store.NotFound(err) }

func tokenHash(raw string) []byte { return auth.HashToken(raw) }
