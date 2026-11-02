package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/config"
	"github.com/cryptoapp/api/internal/pin"
	"github.com/cryptoapp/api/internal/server"
)

// SEC-003: a stale pepper version / parameter set is upgraded on the next successful login.
func TestSec3_PepperUpgradeOnLogin(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	require.Contains(t, e.pinHash("alice"), "$pv=1")
	// rotate: pepper v2 becomes current, v1 stays available for verification
	h2, err := pin.NewHasher(map[int16][]byte{1: e.cfg.Pepper, 2: []byte(strings.Repeat("N", 40))}, 2, pin.Params{MemoryKiB: 64, Time: 1, Parallelism: 1}, 4, 5*time.Second)
	require.NoError(t, err)
	e.hasher = h2
	e.restart()
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 200, r.Status, string(r.Body))
	require.Contains(t, e.pinHash("alice"), "$pv=2", "hash upgraded to the new pepper version")
	d.applySession(r.m())
	require.Equal(t, 200, e.verifyPin(d, goodPIN).Status, "still verifies after the upgrade")
	require.Equal(t, 1, e.count("SELECT count(*) FROM users WHERE pepper_version=2 AND username='alice'"))
	// a wrong PIN never triggers an upgrade
	h3, _ := pin.NewHasher(map[int16][]byte{1: e.cfg.Pepper, 2: []byte(strings.Repeat("N", 40)), 3: []byte(strings.Repeat("M", 40))}, 3, pin.Params{MemoryKiB: 64, Time: 1, Parallelism: 1}, 4, 5*time.Second)
	e.hasher = h3
	e.restart()
	d2 := *d
	e.verifyPin(&d2, otherPIN)
	require.Contains(t, e.pinHash("alice"), "$pv=2")
}

func TestHSTSOnlyBehindTrustedTLSProxy(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TrustedProxy = true })
	r := e.do("GET", "/healthz", nil, map[string]string{"X-Forwarded-Proto": "https"})
	require.Contains(t, r.Header.Get("Strict-Transport-Security"), "max-age=")
	r = e.do("GET", "/healthz", nil, nil)
	require.Empty(t, r.Header.Get("Strict-Transport-Security"))
	e2 := newEnv(t)
	r = e2.do("GET", "/healthz", nil, map[string]string{"X-Forwarded-Proto": "https"})
	require.Empty(t, r.Header.Get("Strict-Transport-Security"), "header is not trusted without TRUSTED_PROXY")
}

func TestMaintenancePurgesExpiredRows(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.demoLogin("alice", "login")
	id, _ := e.register(tok, "p")
	require.NotEmpty(t, id)
	tok2, _ := e.demoLogin("bob", "login") // never bound
	_ = tok2
	e.clk.Advance(25 * time.Hour)
	idemN, bootN, _, err := server.PurgeOnce(context.Background(), e.app.Store, e.clk)
	require.NoError(t, err)
	require.EqualValues(t, 1, idemN, "24 h idempotency retention")
	require.EqualValues(t, 1, bootN, "expired unbound bootstrap token purged; the bound one is kept for replay checks")
}

// A rotated/used bootstrap pin-verify token cannot be replayed to pin/verify after it was consumed.
func TestBootstrapPinVerifyTokenIsConsumedOnSuccess(t *testing.T) {
	e := newEnv(t)
	e.onboard("alice", goodPIN)
	tok, _ := e.demoLogin("alice", "login")
	id, _ := e.register(tok, "tab")
	r := e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": id, "pin": otherPIN}, bearer(tok))
	require.Equal(t, 401, r.Status)
	require.Equal(t, "PIN_INVALID", r.code(), "wrong PIN does not consume the credential")
	require.Equal(t, 200, e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": id, "pin": goodPIN}, bearer(tok)).Status)
	r = e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": id, "pin": goodPIN}, bearer(tok))
	require.Equal(t, 401, r.Status)
	require.Equal(t, "AUTH_FAILED", r.code())
}

// T11: the demo-login route does not exist outside DEMO_MODE (404, contract gap: no 404 declared on demoLogin).
func TestDemoLoginAbsentWithoutDemoMode(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.DemoMode = false })
	r := e.do("POST", "/v1/auth/demo-login", map[string]string{"username": "alice", "secret": secretAlice, "intent": "login"}, nil)
	require.Equal(t, 404, r.Status)
	require.Equal(t, "NOT_FOUND", r.code())
}
