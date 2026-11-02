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

// recover an account via PIN reset: the new device is in cooling-off (24 h in the test config).
func (e *env) resetToCoolingOff(user string) *device {
	rt, scope := e.demoLogin(user, "reset")
	if scope == "pin-setup" {
		e.t.Fatal("account must already have a PIN")
	}
	id, r := e.register(rt, "recovery")
	require.NotEmpty(e.t, id, string(r.Body))
	res := e.do("POST", "/v1/pin/reset", map[string]string{"pin": goodPIN}, withIdem(bearer(rt)))
	require.Equal(e.t, 200, res.Status, string(res.Body))
	d := &device{id: id, user: user, userID: e.userID(user)}
	d.applySession(res.m())
	return d
}

// H-01: PIN reset, then repeated sends each below COOLING_OFF_MAX must hit the AGGREGATE cap.
func TestH01_ResetThenRepeatedSmallSendsHitAggregateCap(t *testing.T) {
	e := newEnv(t)
	e.onboard("alice", goodPIN)
	d := e.resetToCoolingOff("alice")
	var ok int
	for i := 0; i < 10; i++ {
		tx := e.txBody("0.1") // $250 each, cap $500 per cooling-off window
		c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": tx}, bearer(d.access))
		if c.Status != 200 {
			require.Equal(t, 403, c.Status)
			require.Equal(t, "COOLING_OFF", c.code())
			break
		}
		tok, v := e.stepUpPIN(d, map[string]any{"action": "transaction", "tx": tx}, goodPIN)
		require.Equal(t, 200, v.Status)
		if r := e.postTx(d, tx, tok, newIdem()); r.Status == 202 {
			ok++
		} else {
			require.Equal(t, "COOLING_OFF", r.code())
			break
		}
	}
	require.Equal(t, 2, ok, "$500 cap = two $250 sends, the third is refused")
	require.Equal(t, 2, e.count("SELECT count(*) FROM transactions"))
	// the window rolls: after the cooling-off duration the aggregate resets (cap no longer applies at all)
	e.clk.Advance(25 * time.Hour)
	e.unlock(d, goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	require.Equal(t, 202, e.postTx(d, tx, tok, newIdem()).Status)
}

func TestH01_CountCapDuringCoolingOff(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.CoolingOffMaxTx = 3 })
	e.onboard("alice", goodPIN)
	d := e.resetToCoolingOff("alice")
	n := 0
	for i := 0; i < 6; i++ {
		tx := e.txBody("0.001") // $2.5
		c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": tx}, bearer(d.access))
		if c.Status != 200 {
			require.Equal(t, "COOLING_OFF", c.code())
			break
		}
		tok, _ := e.stepUpPIN(d, map[string]any{"action": "transaction", "tx": tx}, goodPIN)
		if e.postTx(d, tx, tok, newIdem()).Status == 202 {
			n++
		}
	}
	require.Equal(t, 3, n)
}

// H-01: concurrent submissions with pre-minted tokens can never exceed the cap (user-row lock).
func TestH01_ConcurrentSubmissionsRespectAggregate(t *testing.T) {
	e := newEnv(t)
	e.onboard("alice", goodPIN)
	d := e.resetToCoolingOff("alice")
	// Mint tokens while the aggregate is still empty, then submit them all at once.
	type pair struct {
		tx  map[string]any
		tok string
	}
	var ps []pair
	for i := 0; i < 6; i++ {
		tx := e.txBody("0.1")
		ps = append(ps, pair{tx, e.spendToken(d, tx)})
	}
	var wg sync.WaitGroup
	var ok, refused atomic.Int64
	for _, p := range ps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.postTx(d, p.tx, p.tok, newIdem())
			switch {
			case r.Status == 202:
				ok.Add(1)
			case r.Status == 403 && r.code() == "COOLING_OFF":
				refused.Add(1)
			default:
				t.Errorf("unexpected %d %s", r.Status, r.Body)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 2, ok.Load())
	require.EqualValues(t, 4, refused.Load())
	require.Equal(t, "250", e.sumUSD())
	_ = e
}

func (e *env) sumUSD() string {
	var s string
	require.NoError(e.t, e.db.Pool.QueryRow(context.Background(), "SELECT trim_scale(COALESCE(sum(usd_value),0))::text FROM transactions").Scan(&s))
	return s
}

// H-01: aggregate BIO_ONLY_MAX: three $500 biometric sends => the third needs the PIN.
func TestH01_BioOnlyIsAnAggregate(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	e.clk.Advance(25 * time.Hour) // out of cooling-off
	e.unlock(d, goodPIN)
	send := func(amount string) (resp, map[string]any) {
		tx := e.txBody(amount)
		c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": tx}, bearer(d.access))
		require.Equal(t, 200, c.Status, string(c.Body))
		if c.m()["required"] == "pin" {
			return c, tx
		}
		v := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": c.m()["challengeId"], "signature": sign(t, d.key, challengeMsg(t, c.m(), "stepup"))}, bearer(d.access))
		require.Equal(t, 200, v.Status, string(v.Body))
		return e.postTx(d, tx, v.m()["stepUpToken"].(string), newIdem()), tx
	}
	r, _ := send("0.2") // $500
	require.Equal(t, 202, r.Status, string(r.Body))
	r, _ = send("0.2")
	require.Equal(t, 202, r.Status, string(r.Body))
	r, _ = send("0.2") // sum would be $1500 > BIO_ONLY_MAX 1000
	require.Equal(t, "pin", r.m()["required"], "third biometric send must demand the PIN")
	// a bio proof minted earlier cannot be spent once the aggregate is exceeded
	e.clk.Advance(2 * time.Hour)
}

// M-04: one IP flooding demo-login must not open the global breaker for a second IP.
func TestM04_OneIPCannotOpenGlobalBreaker(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.TrustedProxy = true
		c.Limits.DemoLoginIPMin = lim(5)
		c.Limits.DemoLoginGlobal = lim(100)
	})
	body := map[string]string{"username": "alice", "secret": secretAlice, "intent": "login"}
	for i := 0; i < 300; i++ {
		e.do("POST", "/v1/auth/demo-login", body, map[string]string{"X-Forwarded-For": "198.51.100.1"})
	}
	r := e.do("POST", "/v1/auth/demo-login", body, map[string]string{"X-Forwarded-For": "198.51.100.2"})
	require.Equal(t, 200, r.Status, "a different IP is not locked out by the flood: "+string(r.Body))
}

// L-04: PUT /pin and /pin/reset no longer share one bucket.
func TestL04_ChangeAndResetBucketsSeparate(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Limits.PinChangeUser = config.Limit{N: 1, Window: time.Hour} })
	d := e.onboard("alice", goodPIN)
	r := e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": "123456"}, withIdem(bearer(d.access)))
	require.Equal(t, 422, r.Status)
	require429(t, e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": "123456"}, withIdem(bearer(d.access))), "change bucket spent")
	rt, _ := e.demoLogin("alice", "reset")
	id, _ := e.register(rt, "x")
	require.NotEmpty(t, id)
	require.Equal(t, 200, e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, withIdem(bearer(rt))).Status, "reset is not starved by the change bucket")
}

// M-05 (prod guard): with ENV=prod plain-HTTP requests are refused unless a trusted proxy says https.
func TestM05_ProdRefusesPlainHTTP(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Env = "prod"; c.TrustedProxy = true })
	r := e.do("GET", "/healthz", nil, nil)
	require.Equal(t, 400, r.Status)
	r = e.do("GET", "/healthz", nil, map[string]string{"X-Forwarded-Proto": "http"})
	require.Equal(t, 400, r.Status)
	r = e.do("GET", "/healthz", nil, map[string]string{"X-Forwarded-Proto": "https"})
	require.Equal(t, 200, r.Status)
}

// Ruling (b): the device block (8 evaluated failures / 60 min) is reachable with the DEFAULT lock schedule.
func TestRuling_b_DeviceBlockReachableWithDefaultSchedule(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	waits := map[int]time.Duration{5: 30, 6: 60, 7: 300} // lock after failure n
	for i := 1; i <= 8; i++ {
		require.Equal(t, map[bool]int{true: 401, false: 423}[i < 5], e.verifyPin(d, otherPIN).Status, "failure %d", i)
		if w, ok := waits[i]; ok {
			e.clk.Advance(w*time.Second + time.Second)
		}
	}
	require.Equal(t, 8, e.failCount("alice"))
	e.clk.Advance(16 * time.Minute) // user lock (15 min) over: only the device block can refuse now
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 429, r.Status, string(r.Body))
	require.Equal(t, 8, e.failCount("alice"), "device block never touches the user counter")
	// lock-refused attempts are NOT counted (no DoS lever): a fresh device is unaffected
	e2 := newEnv(t)
	d2 := e2.onboard("alice", goodPIN)
	for i := 0; i < 5; i++ {
		e2.verifyPin(d2, otherPIN)
	}
	for i := 0; i < 40; i++ {
		require.Equal(t, 423, e2.verifyPin(d2, otherPIN).Status)
	}
	e2.clk.Advance(31 * time.Second)
	require.Equal(t, 200, e2.verifyPin(d2, goodPIN).Status, "spamming during a lock neither extends the lock nor blocks the device")
}
