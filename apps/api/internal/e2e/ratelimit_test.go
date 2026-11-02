package e2e

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/config"
)

func lim(n int) config.Limit { return config.Limit{N: n, Window: time.Minute} }

func require429(t *testing.T, r resp, why string) {
	t.Helper()
	require.Equal(t, 429, r.Status, why+": "+string(r.Body))
	require.Equal(t, "RATE_LIMITED", r.code(), why)
	require.NotEmpty(t, r.Header.Get("Retry-After"), why)
	require.NotNil(t, r.errField("retryAfter"), why)
	require.NotEmpty(t, r.Header.Get("RateLimit-Limit"), why)
}

// spec s7 test 13 / SEC-057: every row of the table.
func TestSec7_13_DemoLoginLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.DemoLoginIPMin = lim(5) })
	body := map[string]string{"username": "alice", "secret": secretAlice, "intent": "login"}
	for i := 0; i < 5; i++ {
		r := e.do("POST", "/v1/auth/demo-login", body, nil)
		require.Equal(t, 200, r.Status)
		require.NotEmpty(t, r.Header.Get("RateLimit-Remaining"), "successful responses carry RateLimit-*")
	}
	require429(t, e.do("POST", "/v1/auth/demo-login", body, nil), "6th request/min/IP")
	e.clk.Advance(61 * time.Second)
	require.Equal(t, 200, e.do("POST", "/v1/auth/demo-login", body, nil).Status)

	h := newEnv(t, func(c *config.Config) { c.Limits.DemoLoginIPHour = config.Limit{N: 3, Window: time.Hour} })
	for i := 0; i < 3; i++ {
		require.Equal(t, 200, h.do("POST", "/v1/auth/demo-login", body, nil).Status)
	}
	require429(t, h.do("POST", "/v1/auth/demo-login", body, nil), "20/h/IP analogue")

	g := newEnv(t, func(c *config.Config) { c.Limits.DemoLoginGlobal = lim(2) })
	g.do("POST", "/v1/auth/demo-login", body, nil)
	g.do("POST", "/v1/auth/demo-login", body, nil)
	require429(t, g.do("POST", "/v1/auth/demo-login", body, nil), "global circuit breaker opens")
	g.clk.Advance(30 * time.Second)
	require429(t, g.do("POST", "/v1/auth/demo-login", body, nil), "still open")
	g.clk.Advance(31 * time.Second)
	require.Equal(t, 200, g.do("POST", "/v1/auth/demo-login", body, nil).Status, "closes after 60 s")
}

func TestSec7_13_PinVerifyDeviceAndIPLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.PinVerifyDevice = lim(3) })
	d := e.onboard("alice", goodPIN)
	for i := 0; i < 3; i++ {
		require.Equal(t, 401, e.verifyPin(d, otherPIN).Status)
	}
	r := e.verifyPin(d, otherPIN)
	require429(t, r, "10/min/device analogue")
	require.Equal(t, 3, e.failCount("alice"), "a rate-limited call does not touch the user counter")
	// the limiter sits behind the credential check: an attacker without credential cannot burn the device budget
	e2 := newEnv(t, func(c *config.Config) { c.Limits.PinVerifyDevice = lim(2) })
	d2 := e2.onboard("alice", goodPIN)
	for i := 0; i < 10; i++ {
		require.Equal(t, 401, e2.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": d2.id, "pin": goodPIN}, nil).Status)
	}
	require.Equal(t, 200, e2.verifyPin(d2, goodPIN).Status)

	ip := newEnv(t, func(c *config.Config) { c.Limits.PinVerifyIP = lim(4) })
	di := ip.onboard("alice", goodPIN)
	for i := 0; i < 4; i++ {
		require.Equal(t, 401, ip.verifyPin(di, otherPIN).Status)
	}
	require429(t, ip.verifyPin(di, otherPIN), "30/min/IP analogue")
}

func TestSec7_13_BiometricLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.BioChallengeDevice = lim(3); c.Limits.BioVerifyDevice = lim(3) })
	d := bioDevice(t, e, "alice")
	for i := 0; i < 3; i++ {
		require.Equal(t, 200, e.bioChallenge(d).Status)
	}
	require429(t, e.bioChallenge(d), "challenge per device")
	body := map[string]any{"challengeId": "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", "deviceId": d.id, "signature": "AAAA"}
	for i := 0; i < 3; i++ {
		require.Equal(t, 401, e.bioVerify(d, body).Status)
	}
	require429(t, e.bioVerify(d, body), "verify per device")

	ip := newEnv(t, func(c *config.Config) { c.Limits.BioChallengeIP = lim(2); c.Limits.BioVerifyIP = lim(2) })
	di := ip.onboard("alice", goodPIN)
	for i := 0; i < 2; i++ {
		require.Equal(t, 200, ip.bioChallenge(di).Status)
	}
	require429(t, ip.bioChallenge(di), "challenge per IP")
	for i := 0; i < 2; i++ {
		require.Equal(t, 401, ip.bioVerify(di, body).Status)
	}
	require429(t, ip.bioVerify(di, body), "verify per IP")
}

func TestSec7_13_RefreshStepUpEnrollPinTxLimits(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.RefreshDevice = lim(2)
		c.Limits.StepUpUser = lim(3)
		c.Limits.TxUser = lim(2)
		c.Limits.PinChangeUser = config.Limit{N: 2, Window: time.Hour}
		c.Limits.EnrollUser = config.Limit{N: 2, Window: time.Hour}
	})
	d := e.onboard("alice", goodPIN)
	for i := 0; i < 2; i++ {
		r := e.refresh(d)
		require.Equal(t, 200, r.Status)
		d.applySession(r.m())
	}
	require429(t, e.refresh(d), "refresh 6/min/device analogue")

	e.clk.Advance(61 * time.Second)
	e.unlock(d, goodPIN)
	for i := 0; i < 3; i++ {
		require.Equal(t, 200, e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access)).Status)
	}
	require429(t, e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access)), "stepup 10/min/user analogue")

	e.clk.Advance(61 * time.Second)
	e.unlock(d, goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	require.Equal(t, 202, e.postTx(d, tx, tok, newIdem()).Status)
	require.Equal(t, 403, e.postTx(d, e.txBody("0.1"), "", newIdem()).Status)
	require429(t, e.postTx(d, e.txBody("0.1"), tok, newIdem()), "transactions 20/min/user analogue")

	e.clk.Advance(61 * time.Second)
	e.unlock(d, goodPIN)
	for i := 0; i < 2; i++ {
		r := e.do("PUT", "/v1/pin", map[string]string{"oldPin": []string{goodPIN, "731905"}[i], "newPin": []string{"731905", goodPIN}[i]}, withIdem(bearer(d.access)))
		require.Equal(t, 200, r.Status, string(r.Body))
		d.applySession(r.m())
	}
	require429(t, e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": "731905"}, withIdem(bearer(d.access))), "PUT /pin 5/h/user analogue")

	e.clk.Advance(2 * time.Hour)
	e.unlock(d, goodPIN)
	for i := 0; i < 2; i++ {
		e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": MissingToken}))
	}
	require429(t, e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": MissingToken})), "enroll 5/h/user analogue")
}

// Rotating source IPs against one user still hit the user lock (SEC-009).
func TestSec9_RotatingIPsHitUserLock(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TrustedProxy = true })
	d := e.onboard("alice", goodPIN)
	var last resp
	for i := 0; i < 6; i++ {
		last = e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": d.id, "pin": otherPIN}, merge(bearer(d.refresh), map[string]string{"X-Forwarded-For": "203.0.113." + itoa(10+i)}))
	}
	require.Equal(t, 423, last.Status)
	require.Equal(t, 5, e.failCount("alice"))
	// X-Forwarded-For is ignored unless the proxy is trusted
	e2 := newEnv(t, func(c *config.Config) { c.Limits.PinVerifyIP = lim(3) })
	d2 := e2.onboard("alice", goodPIN)
	var n429 int
	for i := 0; i < 6; i++ {
		if e2.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": d2.id, "pin": otherPIN}, merge(bearer(d2.refresh), map[string]string{"X-Forwarded-For": "203.0.113." + itoa(10+i)})).Status == 429 {
			n429++
		}
	}
	require.Greater(t, n429, 0, "spoofed XFF does not evade the IP limit when TRUSTED_PROXY=false")
}

// SEC-005b: when the bounded Argon2 pool stays saturated the caller gets 429 and no attempt is consumed.
func TestSec5b_HashingSaturationReturns429WithoutCountingAttempt(t *testing.T) {
	e := newEnv(t, func(e *env) { e.hconc, e.hwait = 1, 50*time.Millisecond })
	d := e.onboard("alice", goodPIN)
	rel, err := e.app.Hasher.Acquire(t.Context())
	require.NoError(t, err)
	r := e.verifyPin(d, otherPIN)
	rel()
	require.Equal(t, 429, r.Status, string(r.Body))
	require.Equal(t, "RATE_LIMITED", r.code())
	require.Equal(t, 0, e.failCount("alice"), "nothing was reserved")
	require.Equal(t, 200, e.verifyPin(d, goodPIN).Status)
}

// 200 concurrent verifies complete and never exceed the semaphore.
func TestSec7_13_ConcurrentVerifiesBounded(t *testing.T) {
	e := newEnv(t, func(e *env) { e.hconc, e.hwait = 3, 30*time.Second })
	var ds []*device
	for i := 0; i < 1; i++ {
		ds = append(ds, e.onboard("alice", goodPIN))
	}
	d := ds[0]
	var wg sync.WaitGroup
	var bad atomic.Int64
	sem := make(chan struct{}, 40)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			r := e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": d.id, "pin": otherPIN}, bearer(d.refresh))
			if r.Status != http.StatusUnauthorized && r.Status != http.StatusLocked && r.Status != http.StatusTooManyRequests {
				bad.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 0, bad.Load())
	require.LessOrEqual(t, e.app.Hasher.MaxInflight(), int64(3))
}
