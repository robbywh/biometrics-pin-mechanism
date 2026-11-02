package e2e

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/config"
)

func (e *env) failCount(user string) int {
	return e.count("SELECT fail_count FROM users WHERE username=$1", user)
}

func (e *env) pinHash(user string) string {
	var h string
	require.NoError(e.t, e.db.Pool.QueryRow(context.Background(), "SELECT pin_hash FROM users WHERE username=$1", user).Scan(&h))
	return h
}

// spec s7 test 1: 50 parallel wrong PINs => at most 5 evaluated, then 423; counter durable across a restart.
func TestSec7_01_ParallelGuessesAtMostFiveEvaluated(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	before := e.app.Hasher.Evaluations()
	var wg sync.WaitGroup
	var n401, n423, other atomic.Int64
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.verifyPin(d, otherPIN)
			switch r.Status {
			case 401:
				n401.Add(1)
			case 423:
				n423.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 0, other.Load())
	require.EqualValues(t, 4, n401.Load(), "failures 1-4 are PIN_INVALID")
	require.EqualValues(t, 46, n423.Load(), "the 5th failure and everything after is 423")
	require.LessOrEqual(t, e.app.Hasher.Evaluations()-before, int64(5), "at most 5 hash evaluations may start")
	require.Equal(t, 5, e.failCount("alice"))
	// durable across a simulated restart: still locked, correct PIN still refused
	e.restart()
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 423, r.Status, string(r.Body))
	require.Equal(t, 5, e.failCount("alice"))
}

// spec s7 test 2 + the schedule table: lock escalation, correct PIN during lock, expiry and reset.
func TestSec7_02_LockScheduleAndCorrectPinDuringLock(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.DeviceFailMax = 1000 }) // this test walks the user schedule up to the hard lock
	d := e.onboard("alice", goodPIN)
	for i := 1; i <= 4; i++ {
		r := e.verifyPin(d, otherPIN)
		require.Equal(t, 401, r.Status)
		require.Equal(t, "PIN_INVALID", r.code())
		require.EqualValues(t, 5-i, r.errField("attemptsRemaining"))
	}
	waits := []float64{30, 60, 300, 900, 3600}
	for i, w := range waits { // failures 5..9
		r := e.verifyPin(d, otherPIN)
		require.Equal(t, 423, r.Status, "failure %d", i+5)
		require.Equal(t, "PIN_LOCKED", r.code())
		require.Equal(t, "soft", r.errField("lockType"))
		require.EqualValues(t, w, r.errField("retryAfter"))
		require.EqualValues(t, 10-(i+5), r.errField("attemptsUntilHardLock"))
		require.Equal(t, itoa(int(w)), r.Header.Get("Retry-After"))
		// correct PIN during the lock: same 423, lock unchanged, no hashing
		evals := e.app.Hasher.Evaluations()
		c := e.verifyPin(d, goodPIN)
		require.Equal(t, 423, c.Status)
		require.Equal(t, evals, e.app.Hasher.Evaluations(), "locked: no PIN evaluation")
		require.Equal(t, i+5, e.failCount("alice"))
		e.clk.Advance(time.Duration(w)*time.Second + time.Second)
	}
	// failure 10: hard lock, no retryAfter
	r := e.verifyPin(d, otherPIN)
	require.Equal(t, 423, r.Status)
	require.Equal(t, "hard", r.errField("lockType"))
	require.Nil(t, r.errField("retryAfter"))
	e.clk.Advance(100 * time.Hour)
	r = e.verifyPin(d, goodPIN)
	require.Equal(t, 423, r.Status, "hard lock never expires and refuses the correct PIN")
	require.Equal(t, "hard", r.errField("lockType"))
}

func TestSec7_02_CorrectPinAfterExpiryResets(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	for i := 0; i < 5; i++ {
		e.verifyPin(d, otherPIN)
	}
	require.Equal(t, 5, e.failCount("alice"))
	e.clk.Advance(31 * time.Second)
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 200, r.Status, string(r.Body))
	d.applySession(r.m())
	require.Equal(t, 0, e.failCount("alice"))
	require.EqualValues(t, 5, r.m()["recentFailures"], "SEC-012 notice carries the failed attempts since the last unlock")
	// reported once, then cleared
	r2 := e.verifyPin(d, goodPIN)
	require.EqualValues(t, 0, r2.m()["recentFailures"])
	require.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_events WHERE event_type='PIN_UNLOCKED_AFTER_LOCK'"), 1)
	require.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_events WHERE event_type='PIN_LOCKED'"), 1)
}

// 10th reserved attempt that happens to be correct must clear even the hard lock the reservation just set.
func TestLockout_NinthFailureThenCorrectPin(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	for i := 0; i < 9; i++ {
		e.verifyPin(d, otherPIN)
		e.clk.Advance(2 * time.Hour)
	}
	require.Equal(t, 9, e.failCount("alice"))
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 200, r.Status, string(r.Body))
	require.Equal(t, 0, e.failCount("alice"))
	require.Equal(t, 0, e.count("SELECT count(*) FROM users WHERE username='alice' AND hard_locked"))
}

// spec s7 test 3 (F1): no/invalid credential => 401 AUTH_FAILED, counter untouched, no attempts/retry fields.
func TestSec7_03_PinVerifyNeedsDeviceCredential(t *testing.T) {
	e := newEnv(t)
	a := e.onboard("alice", goodPIN)
	b := e.onboard("bob", otherPIN)
	for _, tc := range []struct {
		name string
		hdr  map[string]string
		dev  string
	}{
		{"none", nil, a.id},
		{"garbage", bearer("not-a-token"), a.id},
		{"wrong shape", bearer("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), a.id},
		{"access token instead", bearer(a.access), a.id},
		{"other user's refresh", bearer(b.refresh), a.id},
		{"own refresh, other device id", bearer(a.refresh), b.id},
		{"own refresh, random device id", bearer(a.refresh), "11111111-1111-4111-8111-111111111111"},
	} {
		r := e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": tc.dev, "pin": goodPIN}, tc.hdr)
		require.Equal(t, 401, r.Status, tc.name)
		require.Equal(t, "AUTH_FAILED", r.code(), tc.name)
		require.Nil(t, r.errField("attemptsRemaining"), tc.name)
		require.Nil(t, r.errField("retryAfter"), tc.name)
		require.Equal(t, 0, e.failCount("alice"), tc.name)
		require.Equal(t, 0, e.failCount("bob"), tc.name)
	}
}

// spec s7 test 4: F2.
func TestSec7_04_SetPinNeverOverwrites(t *testing.T) {
	e := newEnv(t)
	// two setup tokens exist before any PIN is set
	t1, _ := e.demoLogin("alice", "login")
	t2, _ := e.demoLogin("alice", "login")
	id1, _ := e.register(t1, "phone-1")
	id2, _ := e.register(t2, "phone-2")
	require.NotEmpty(t, id1)
	require.NotEmpty(t, id2)
	r := e.do("POST", "/v1/pin", map[string]string{"pin": goodPIN}, withIdem(bearer(t1)))
	require.Equal(t, 201, r.Status, string(r.Body))
	h := e.pinHash("alice")
	r = e.do("POST", "/v1/pin", map[string]string{"pin": otherPIN}, withIdem(bearer(t2)))
	require.Equal(t, 409, r.Status)
	require.Equal(t, "PIN_ALREADY_SET", r.code())
	require.Equal(t, h, e.pinHash("alice"), "hash byte-identical")
	// a fresh login on an account WITH a PIN yields a pin-verify token, which cannot reach POST /pin
	t3, scope := e.demoLogin("alice", "login")
	require.Equal(t, "pin-verify", scope)
	e.register(t3, "phone-3")
	r = e.do("POST", "/v1/pin", map[string]string{"pin": otherPIN}, withIdem(bearer(t3)))
	require.Equal(t, 403, r.Status)
	require.Equal(t, "SCOPE_INSUFFICIENT", r.code())
	require.Equal(t, h, e.pinHash("alice"))
	// the setup token is single use
	r = e.do("POST", "/v1/pin", map[string]string{"pin": otherPIN}, withIdem(bearer(t1)))
	require.Equal(t, 401, r.Status)
}

func TestSec7_04_DemoLoginRequiresSecretAndIsUniform(t *testing.T) {
	e := newEnv(t)
	bad := []map[string]string{
		{"username": "alice", "secret": "wrong-secret-value", "intent": "login"},
		{"username": "nobody", "secret": "wrong-secret-value", "intent": "login"},
		{"username": "nobody", "secret": secretAlice, "intent": "login"},
		{"username": "alice", "secret": secretBob, "intent": "login"},
	}
	var first []byte
	for i, b := range bad {
		r := e.do("POST", "/v1/auth/demo-login", b, nil)
		require.Equal(t, 401, r.Status)
		require.Equal(t, "AUTH_FAILED", r.code())
		if i == 0 {
			first = r.Body
		}
		require.Equal(t, string(first), string(r.Body), "unknown user and wrong secret are indistinguishable")
	}
	r := e.do("POST", "/v1/auth/demo-login", map[string]string{"username": "alice", "intent": "login"}, nil)
	require.Equal(t, 400, r.Status, "missing secret is a validation error")
}

func TestSec7_04_BootstrapTokenScopeAndTTL(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.demoLogin("alice", "login")
	for _, c := range []struct{ m, p string }{{"GET", "/v1/dashboard"}, {"GET", "/v1/devices"}, {"POST", "/v1/auth/logout"}, {"PUT", "/v1/pin"}} {
		var body any
		h := bearer(tok)
		if c.m == "PUT" {
			body, h = map[string]string{"oldPin": goodPIN, "newPin": otherPIN}, withIdem(h)
		}
		r := e.do(c.m, c.p, body, h)
		require.Equal(t, 403, r.Status, c.m+" "+c.p)
		require.Equal(t, "SCOPE_INSUFFICIENT", r.code())
	}
	r := e.do("POST", "/v1/transactions", e.txBody("1"), withIdem(bearer(tok)))
	require.Equal(t, 403, r.Status)
	require.Equal(t, "SCOPE_INSUFFICIENT", r.code())
	e.clk.Advance(601 * time.Second)
	r = e.do("POST", "/v1/devices", map[string]any{"name": "x", "platform": "ios"}, withIdem(bearer(tok)))
	require.Equal(t, 401, r.Status, "bootstrap token past its TTL")
}

// spec s7 test 12 (API level): weak PINs are refused by the server on set, change and reset.
func TestSec7_12_WeakPinsRejectedByServer(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.demoLogin("alice", "login")
	e.register(tok, "p")
	for _, weak := range []string{"123456", "000000", "111111", "654321", "121212", "123123", "520520", "987654"} {
		r := e.do("POST", "/v1/pin", map[string]string{"pin": weak}, withIdem(bearer(tok)))
		require.Equal(t, 422, r.Status, weak)
		require.Equal(t, "PIN_WEAK", r.code())
	}
	d := e.onboard("bob", goodPIN)
	r := e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": "123456"}, withIdem(bearer(d.access)))
	require.Equal(t, 422, r.Status)
	require.Equal(t, "PIN_WEAK", r.code())
	r = e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": goodPIN}, withIdem(bearer(d.access)))
	require.Equal(t, 422, r.Status)
	require.Equal(t, "PIN_UNCHANGED", r.code())
}

// Per-device block (SEC-009): N failures in the window block the device without touching the user counter.
// (With the default lock schedule 10 evaluated failures cannot happen inside 15 minutes, so the test lowers the limit.)
func TestSec9_DeviceBlockDoesNotTouchUserCounter(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.DeviceFailMax = 4 })
	d := e.onboard("alice", goodPIN)
	for i := 0; i < 4; i++ {
		require.Equal(t, 401, e.verifyPin(d, otherPIN).Status)
	}
	require.Equal(t, 4, e.failCount("alice"))
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 429, r.Status, string(r.Body))
	require.Equal(t, "RATE_LIMITED", r.code())
	require.NotEmpty(t, r.Header.Get("Retry-After"))
	require.Equal(t, 4, e.failCount("alice"), "blocked device never touches the user counter")
	require.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_events WHERE event_type='DEVICE_BLOCKED'"), 1)
	e.clk.Advance(61 * time.Minute)
	require.Equal(t, 200, e.verifyPin(d, goodPIN).Status, "block expires after an hour")
}

// PIN set must not return tokens on an idempotent replay (SEC-060).
func TestSec60_SetPinReplayReturnsNoTokens(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.demoLogin("alice", "login")
	e.register(tok, "p")
	h := withIdem(bearer(tok))
	r := e.do("POST", "/v1/pin", map[string]string{"pin": goodPIN}, h)
	require.Equal(t, 201, r.Status)
	r2 := e.do("POST", "/v1/pin", map[string]string{"pin": goodPIN}, h)
	require.Equal(t, 409, r2.Status, string(r2.Body))
	require.Equal(t, "IDEMPOTENT_REPLAY", r2.code())
	require.NotContains(t, string(r2.Body), "accessToken")
	require.NotContains(t, string(r2.Body), "refreshToken")
	r3 := e.do("POST", "/v1/pin", map[string]string{"pin": otherPIN}, h)
	require.Equal(t, 422, r3.Status)
	require.Equal(t, "IDEMPOTENCY_KEY_REUSED", r3.code())
}
