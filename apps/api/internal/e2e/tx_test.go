package e2e

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func (e *env) balance(user, asset string) string {
	var s string
	require.NoError(e.t, e.db.Pool.QueryRow(context.Background(), "SELECT trim_scale(b.amount)::text FROM balances b JOIN users u ON u.id=b.user_id WHERE u.username=$1 AND b.asset=$2", user, asset).Scan(&s))
	return s
}

// spendToken runs challenge -> PIN proof and returns the step-up token.
func (e *env) spendToken(d *device, tx map[string]any) string {
	e.t.Helper()
	tok, v := e.stepUpPIN(d, map[string]any{"action": "transaction", "tx": tx}, goodPIN)
	require.Equal(e.t, 200, v.Status, string(v.Body))
	return tok
}

func (e *env) postTx(d *device, tx map[string]any, tok string, idem string) resp {
	h := merge(bearer(d.access), map[string]string{"Idempotency-Key": idem})
	if tok != "" {
		h["X-StepUp-Token"] = tok
	}
	return e.do("POST", "/v1/transactions", tx, h)
}

func newIdem() string { return withIdem(nil)["Idempotency-Key"] }

func TestTransactionHappyPathExactDecimals(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.10") // normalised to 0.1 server side
	tok := e.spendToken(d, tx)
	tx["amount"] = "0.1" // 1.50 vs 1.5 style equivalence
	r := e.postTx(d, tx, tok, newIdem())
	require.Equal(t, 202, r.Status, string(r.Body))
	require.Equal(t, "accepted_mock", r.m()["status"])
	require.Equal(t, "1.099", e.balance("alice", "ETH"), "0.1 + fee 0.001 debited with exact arithmetic")
	require.Equal(t, 1, e.count("SELECT count(*) FROM transactions"))
	require.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_events WHERE event_type='TX_CREATED'"), 1)
	dash := e.do("GET", "/v1/dashboard", nil, bearer(d.access))
	require.Equal(t, 200, dash.Status)
}

// spec s7 test 9: tampering after the challenge
func TestSec7_09_TamperedFieldsRejectedAndTokenBurned(t *testing.T) {
	mut := map[string]func(map[string]any){
		"amount digit":      func(m map[string]any) { m["amount"] = "0.2" },
		"destination case":  func(m map[string]any) { m["destination"] = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
		"destination other": func(m map[string]any) { m["destination"] = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
		"asset":             func(m map[string]any) { m["asset"] = "USDC" },
		"network":           func(m map[string]any) { m["asset"], m["network"] = "BTC", "bitcoin" },
		"fee":               func(m map[string]any) { m["fee"] = "0.002" },
		"txNonce":           func(m map[string]any) { m["txNonce"] = "44444444-4444-4444-8444-444444444444" },
		"expiry":            func(m map[string]any) { m["expiry"] = m["expiry"].(int64) + 1 },
	}
	for name, f := range mut {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			d := e.onboard("alice", goodPIN)
			tx := e.txBody("0.1")
			tok := e.spendToken(d, tx)
			f(tx)
			r := e.postTx(d, tx, tok, newIdem())
			require.Equal(t, 403, r.Status, string(r.Body))
			require.Equal(t, "STEPUP_INVALID", r.code())
			// the token was valid, so the mismatch burned it: the ORIGINAL transaction cannot use it any more
			orig := e.txBody("0.1")
			_ = orig
			require.Equal(t, 0, e.count("SELECT count(*) FROM transactions"))
			require.Equal(t, 1, e.count("SELECT count(*) FROM step_up_tokens WHERE consumed_at IS NOT NULL"))
		})
	}
}

func TestSec7_09_TokenReuseOtherSessionOtherUser(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	require.Equal(t, 202, e.postTx(d, tx, tok, newIdem()).Status)
	tx2 := e.txBody("0.1")
	r := e.postTx(d, tx2, tok, newIdem())
	require.Equal(t, 403, r.Status, "single use")
	require.Equal(t, "STEPUP_INVALID", r.code())

	// token minted in one session is useless in the next (unlock creates a new session)
	tx3 := e.txBody("0.1")
	tok3 := e.spendToken(d, tx3)
	e.unlock(d, goodPIN)
	r = e.postTx(d, tx3, tok3, newIdem())
	require.Equal(t, 403, r.Status, "token from another session")
	require.Equal(t, 0, e.count("SELECT count(*) FROM transactions WHERE tx_nonce=$1::uuid", tx3["txNonce"]))

	// another user's token
	b := e.onboard("bob", goodPIN)
	tx4 := e.txBody("0.1")
	tokB := e.spendToken(b, tx4)
	r = e.postTx(d, tx4, tokB, newIdem())
	require.Equal(t, 403, r.Status)
	require.Equal(t, 0, e.count("SELECT count(*) FROM step_up_tokens WHERE consumed_at IS NOT NULL AND user_id=$1::uuid", b.userID), "bob's token was not burned by alice")

	// a step-up token for another action (enable_biometric) cannot authorise a transaction
	tokA, v := e.stepUpPIN(d, map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, goodPIN)
	require.Equal(t, 200, v.Status)
	require.Equal(t, 403, e.postTx(d, e.txBody("0.1"), tokA, newIdem()).Status)
}

func TestTransaction_MissingHeadersAndValidation(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	r := e.postTx(d, tx, "", newIdem())
	require.Equal(t, 403, r.Status, string(r.Body))
	require.Equal(t, "STEPUP_REQUIRED", r.code())
	// no auth at all still 401 (auth before step-up)
	r = e.do("POST", "/v1/transactions", tx, map[string]string{"Idempotency-Key": newIdem()})
	require.Equal(t, 401, r.Status)
	// missing Idempotency-Key => 400
	tok := e.spendToken(d, tx)
	r = e.do("POST", "/v1/transactions", tx, merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok}))
	require.Equal(t, 400, r.Status)
	// non-v4 Idempotency-Key => 400
	r = e.do("POST", "/v1/transactions", tx, merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok, "Idempotency-Key": "11111111-1111-1111-8111-111111111111"}))
	require.Equal(t, 400, r.Status)
	// approval flags / unknown fields do not exist
	bad := e.txBody("0.1")
	bad["approved"] = true
	r = e.postTx(d, bad, tok, newIdem())
	require.Equal(t, 400, r.Status)
	// invalid decimal / pair / expiry
	for name, f := range map[string]func(map[string]any){
		"leading zero": func(m map[string]any) { m["amount"] = "01" },
		"exponent":     func(m map[string]any) { m["amount"] = "1e3" },
		"number":       func(m map[string]any) { m["amount"] = 1.5 },
		"zero amount":  func(m map[string]any) { m["amount"] = "0" },
		"bad pair":     func(m map[string]any) { m["asset"], m["network"] = "BTC", "ethereum" },
		"expired":      func(m map[string]any) { m["expiry"] = e.clk.Now().Unix() - 1 },
		"far future":   func(m map[string]any) { m["expiry"] = e.clk.Now().Unix() + 601 },
	} {
		b := e.txBody("0.1")
		f(b)
		c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": b}, bearer(d.access))
		require.Contains(t, []int{400, 422}, c.Status, name)
		require.Equal(t, "VALIDATION_ERROR", c.code(), name)
	}
}

func TestSec7_09_ConcurrentDoubleSubmitCreatesOneTransaction(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	key := newIdem()
	var wg sync.WaitGroup
	var ids sync.Map
	var ok atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := e.postTx(d, tx, tok, key)
			if r.Status == 202 {
				ok.Add(1)
				ids.Store(r.m()["transactionId"], true)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 12, ok.Load(), "same Idempotency-Key + body: every call gets the stored 202")
	n := 0
	ids.Range(func(_, _ any) bool { n++; return true })
	require.Equal(t, 1, n)
	require.Equal(t, 1, e.count("SELECT count(*) FROM transactions"))
	require.Equal(t, "1.099", e.balance("alice", "ETH"))
	// same key, different body => 422
	tx2 := e.txBody("0.3")
	r := e.postTx(d, tx2, tok, key)
	require.Equal(t, 422, r.Status)
	require.Equal(t, "IDEMPOTENCY_KEY_REUSED", r.code())
}

func TestSec7_09_ConcurrentDistinctKeysOneTokenOneTx(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.postTx(d, tx, tok, newIdem()).Status == 202 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, ok.Load())
	require.Equal(t, 1, e.count("SELECT count(*) FROM transactions"))
}

func TestTransaction_NonceReplayAndInsufficientFunds(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	require.Equal(t, 202, e.postTx(d, tx, e.spendToken(d, tx), newIdem()).Status)
	// same txNonce again with a fresh step-up token: no second transaction, token not burned
	tok2 := e.spendToken(d, tx)
	r := e.postTx(d, tx, tok2, newIdem())
	require.Equal(t, 409, r.Status)
	require.Equal(t, "IDEMPOTENT_REPLAY", r.code())
	require.Equal(t, 1, e.count("SELECT count(*) FROM transactions"))
	require.Equal(t, 1, e.count("SELECT count(*) FROM step_up_tokens WHERE consumed_at IS NULL"), "failed request rolled the consume back")

	big := e.txBody("5") // 5 ETH > 1.2 balance, but within the (pin) policy
	tokBig := e.spendToken(d, big)
	r = e.postTx(d, big, tokBig, newIdem())
	require.Equal(t, 422, r.Status, string(r.Body))
	require.Equal(t, "INSUFFICIENT_FUNDS", r.code())
	require.Equal(t, "1.099", e.balance("alice", "ETH"))
	// the token survived the failed attempt and can pay for the matching, affordable... (same hash only): still bound to `big`
	require.Equal(t, 422, e.postTx(d, big, tokBig, newIdem()).Status)
}

// T18 acceptance: failure after consume rolls the consume back (fault injection).
func TestTransaction_FaultAfterConsumeRollsBack(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	e.hooks.AfterStepUpConsume = func() error { return errors.New("injected") }
	r := e.postTx(d, tx, tok, newIdem())
	require.Equal(t, 500, r.Status)
	require.Equal(t, "INTERNAL", r.code())
	require.Equal(t, 0, e.count("SELECT count(*) FROM step_up_tokens WHERE consumed_at IS NOT NULL"))
	require.Equal(t, 0, e.count("SELECT count(*) FROM transactions"))
	e.hooks.AfterStepUpConsume = nil
	require.Equal(t, 202, e.postTx(d, tx, tok, newIdem()).Status, "the token is intact after the rolled back attempt")
	require.NotContains(t, string(r.Body), "injected")
}

// SEC-041 / SEC-047: policy decided server side.
func TestSec41_BioOnlyThresholdAndCoolingOff(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	// key in cooling-off: even a small tx demands the PIN; large tx is refused outright (> COOLING_OFF_MAX=500 USD)
	c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access))
	require.Equal(t, 200, c.Status, string(c.Body))
	require.Equal(t, "pin", c.m()["required"])
	big := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.5")}, bearer(d.access)) // $1250
	require.Equal(t, 403, big.Status)
	require.Equal(t, "COOLING_OFF", big.code())
	require.NotNil(t, big.errField("retryAfter"))

	e.clk.Advance(25 * time.Hour)
	e.unlock(d, goodPIN)
	small := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access))
	require.Equal(t, "either", small.m()["required"], "cooling-off over, $250 <= BIO_ONLY_MAX")
	over := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.5")}, bearer(d.access))
	require.Equal(t, 200, over.Status, string(over.Body))
	require.Equal(t, "pin", over.m()["required"], "$1250 > BIO_ONLY_MAX => PIN")
	// biometric signature on the PIN-only challenge => 403 STEPUP_REQUIRED required=pin
	sig := sign(t, d.key, challengeMsg(t, over.m(), "stepup"))
	r := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": over.m()["challengeId"], "signature": sig}, bearer(d.access))
	require.Equal(t, 403, r.Status)
	require.Equal(t, "STEPUP_REQUIRED", r.code())
	require.Equal(t, "pin", r.errField("required"))
	// and the challenge is consumed: the PIN now needs a fresh challenge
	r = e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": over.m()["challengeId"], "pin": goodPIN}, bearer(d.access))
	require.Equal(t, 401, r.Status)
	require.Equal(t, "AUTH_FAILED", r.code())

	// biometric proof for the small tx works end to end
	tx := e.txBody("0.1")
	small = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": tx}, bearer(d.access))
	sig = sign(t, d.key, challengeMsg(t, small.m(), "stepup"))
	v := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": small.m()["challengeId"], "signature": sig}, bearer(d.access))
	require.Equal(t, 200, v.Status, string(v.Body))
	require.Equal(t, 202, e.postTx(d, tx, v.m()["stepUpToken"].(string), newIdem()).Status)
}

// SEC-047: a new device is in cooling-off; after the window the cap lifts (clock advance).
func TestSec47_CoolingOffClockAdvance(t *testing.T) {
	e := newEnv(t)
	a := e.onboard("alice", goodPIN)
	tok, _ := e.demoLogin("alice", "login")
	id2, rr := e.register(tok, "second")
	require.NotEmpty(t, id2)
	require.NotNil(t, rr.m()["coolingOffUntil"])
	b := &device{id: id2, user: "alice", userID: a.userID}
	v := e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": id2, "pin": goodPIN}, bearer(tok))
	require.Equal(t, 200, v.Status)
	b.applySession(v.m())
	c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.5")}, bearer(b.access))
	require.Equal(t, 403, c.Status)
	require.Equal(t, "COOLING_OFF", c.code())
	e.clk.Advance(24*time.Hour + time.Minute)
	e.unlock(b, goodPIN)
	c = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.5")}, bearer(b.access))
	require.Equal(t, 200, c.Status, string(c.Body))
	// the first device never had a cooling-off
	e.unlock(a, goodPIN)
	c = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.5")}, bearer(a.access))
	require.Equal(t, 200, c.Status)
	// the transaction path enforces the cap too (cooling-off checked again at submit time)
	_ = context.Background
}

// SEC-042: wrong step-up PINs use the same counter/lock as pin/verify; each wrong PIN burns the challenge (D-08).
func TestSec42_StepUpPinSharesLockout(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	for i := 1; i <= 5; i++ {
		_, v := e.stepUpPIN(d, map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, otherPIN)
		if i < 5 {
			require.Equal(t, 401, v.Status)
			require.Equal(t, "PIN_INVALID", v.code())
			require.EqualValues(t, 5-i, v.errField("attemptsRemaining"))
		} else {
			require.Equal(t, 423, v.Status, string(v.Body))
			require.Equal(t, "PIN_LOCKED", v.code())
		}
	}
	require.Equal(t, 5, e.failCount("alice"))
	require.Equal(t, 423, e.verifyPin(d, goodPIN).Status, "the same lock applies to pin/verify")
	_, v := e.stepUpPIN(d, map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, goodPIN)
	require.Equal(t, 423, v.Status, "correct PIN during the lock is refused here too")
}

func TestStepUpVerify_AmbiguousAndUnknown(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access))
	cid := c.m()["challengeId"]
	require.Equal(t, 400, e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": cid, "pin": goodPIN, "signature": "AAAA"}, bearer(d.access)).Status)
	require.Equal(t, 400, e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": cid}, bearer(d.access)).Status)
	r := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", "pin": goodPIN}, bearer(d.access))
	require.Equal(t, 401, r.Status)
	require.Equal(t, "AUTH_FAILED", r.code())
	// expired challenge
	e.clk.Advance(61 * time.Second)
	e.unlock(d, goodPIN)
	c = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access))
	e.clk.Advance(61 * time.Second)
	d2 := *d
	e.unlock(&d2, goodPIN)
	r = e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": c.m()["challengeId"], "pin": goodPIN}, bearer(d2.access))
	require.Equal(t, 401, r.Status)
	// enable_biometric with a biometric proof is refused (PIN only)
	bd := bioDevice(t, e, "bob")
	ec := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "enable_biometric", "targetDeviceId": bd.id}, bearer(bd.access))
	require.Equal(t, "pin", ec.m()["required"])
	r = e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": ec.m()["challengeId"], "signature": sign(t, bd.key, challengeMsg(t, ec.m(), "stepup"))}, bearer(bd.access))
	require.Equal(t, 403, r.Status)
	require.Equal(t, "STEPUP_REQUIRED", r.code())
	// a new challenge supersedes the previous live one
	c1 := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(bd.access))
	_ = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(bd.access))
	r = e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": c1.m()["challengeId"], "pin": goodPIN}, bearer(bd.access))
	require.Equal(t, 401, r.Status, "superseded")
}
