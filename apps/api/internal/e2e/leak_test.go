package e2e

import (
	"context"
	"encoding/json"
	"math/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/config"
	"github.com/cryptoapp/api/internal/cryptomsg"
)

var uuidLike = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// secrets collects every token-like string value returned by the API (tokens, nonces, keys, hashes, signatures).
func collectSecrets(t *testing.T, bodies [][]byte) []string {
	var out []string
	var walk func(k string, v any)
	walk = func(k string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for kk, vv := range x {
				walk(kk, vv)
			}
		case []any:
			for _, vv := range x {
				walk(k, vv)
			}
		case string:
			if len(x) >= 20 && !uuidLike.MatchString(x) && k != "message" && !strings.Contains(x, " ") && !strings.HasPrefix(x, "0x") {
				out = append(out, x)
			}
		}
	}
	for _, b := range bodies {
		var v any
		if json.Unmarshal(b, &v) == nil {
			walk("", v)
		}
	}
	return out
}

// spec s7 test 11 / SEC-062: canary PIN, bearer and Idempotency-Key never reach logs or audit output.
func TestSec7_11_CanarySecretsNeverLogged(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	e.enableBio(d, goodPIN)

	// canary PIN as a wrong PIN, in change-PIN, in step-up PIN, and as a (weak) new PIN
	e.verifyPin(d, canaryPIN)
	e.do("PUT", "/v1/pin", map[string]string{"oldPin": canaryPIN, "newPin": "731905"}, withIdem(bearer(d.access)))
	e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": canaryPIN}, withIdem(bearer(d.access)))
	e.stepUpPIN(d, map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, canaryPIN)
	tok, _ := e.demoLogin("bob", "login")
	e.register(tok, "bob-phone")
	e.do("POST", "/v1/pin", map[string]string{"pin": canaryPIN}, withIdem(bearer(tok)))
	// canary bearer + canary idempotency key + canary secret
	e.do("GET", "/v1/dashboard", nil, bearer(canaryBearer))
	e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": d.id, "pin": canaryPIN}, bearer(canaryBearer))
	e.do("POST", "/v1/transactions", e.txBody("0.1"), map[string]string{"Authorization": "Bearer " + canaryBearer, "Idempotency-Key": canaryIdem, "X-StepUp-Token": canaryBearer})
	e.do("POST", "/v1/devices", map[string]any{"name": "x", "platform": "ios"}, map[string]string{"Authorization": "Bearer " + canaryBearer, "Idempotency-Key": canaryIdem})
	e.do("POST", "/v1/auth/demo-login", map[string]string{"username": "alice", "secret": canaryBearer + "-secret", "intent": "login"}, nil)
	e.do("POST", "/v1/auth/demo-login", map[string]string{"username": canaryBearer, "secret": "x", "intent": "login"}, map[string]string{"X-Request-Id": "req-abc-123"})
	e.do("GET", "/v1/devices?token="+canaryBearer+"&pin="+canaryPIN, nil, bearer(d.access))
	// a successful full flow too
	e.unlock(d, goodPIN)
	r := e.bioLogin(d)
	d.applySession(r.m())
	e.clk.Advance(25 * time.Hour)
	e.unlock(d, goodPIN)
	tx := e.txBody("0.1")
	e.postTx(d, tx, e.spendToken(d, tx), newIdem())

	logs := e.logs.String() + "\n" + e.audit.String()
	require.NotEmpty(t, e.audit.String(), "audit output exists")
	for _, c := range []string{canaryPIN, canaryBearer, canaryIdem, goodPIN, otherPIN, "731905", secretAlice, secretBob, string(e.cfg.Pepper)} {
		require.NotContains(t, logs, c)
	}
	// every token/nonce/signature/hash the API ever returned, plus DB-resident secrets
	secrets := collectSecrets(t, e.rec.all())
	var ph, spki string
	require.NoError(t, e.db.Pool.QueryRow(context.Background(), "SELECT pin_hash FROM users WHERE username='alice'").Scan(&ph))
	secrets = append(secrets, ph, cryptomsg.EncodeB64(d.spki), spki)
	require.Greater(t, len(secrets), 10)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		require.NotContains(t, logs, s, "a secret value leaked into logs/audit")
	}
	require.NotContains(t, logs, "Bearer")
	require.NotContains(t, strings.ToLower(logs), "authorization")
	// the request log is the allowlisted shape
	require.Contains(t, e.logs.String(), `"route"`)
	require.Contains(t, e.logs.String(), `"request_id"`)
}

// Responses never contain pin/hash/salt/pepper/private key properties.
func TestSec7_11_NoSecretPropertiesInResponses(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	e.verifyPin(d, otherPIN)
	e.do("GET", "/v1/devices", nil, bearer(d.access))
	e.bioChallenge(d)
	e.do("GET", "/v1/dashboard", nil, bearer(d.access))
	banned := regexp.MustCompile(`(?i)^(pin|pinhash|oldpin|newpin|hash|salt|pepper|privatekey|pin_hash|secret)$`)
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, vv := range x {
				require.False(t, banned.MatchString(k), "response property %q", k)
				walk(vv)
			}
		case []any:
			for _, vv := range x {
				walk(vv)
			}
		}
	}
	n := 0
	for _, b := range e.rec.all() {
		var v any
		if json.Unmarshal(b, &v) == nil {
			walk(v)
			n++
		}
	}
	require.Greater(t, n, 5)
}

func TestHeadersAndPanicRecovery(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/healthz", nil, nil)
	require.Equal(t, 200, r.Status)
	require.Equal(t, "nosniff", r.Header.Get("X-Content-Type-Options"))
	require.Equal(t, "no-store", r.Header.Get("Cache-Control"))
	require.NotEmpty(t, r.Header.Get("X-Request-Id"))
	require.Empty(t, r.Header.Get("Access-Control-Allow-Origin"))
	// client request ids: accepted only when well-formed
	r = e.do("GET", "/healthz", nil, map[string]string{"X-Request-Id": "abc-123"})
	require.Equal(t, "abc-123", r.Header.Get("X-Request-Id"))
	r = e.do("GET", "/healthz", nil, map[string]string{"X-Request-Id": "bad id with spaces/../"})
	require.NotEqual(t, "bad id with spaces/../", r.Header.Get("X-Request-Id"))
	// unknown routes use the contract error envelope
	r = e.do("GET", "/v1/nope", nil, nil)
	require.Equal(t, 404, r.Status)
	require.Equal(t, "NOT_FOUND", r.code())
	// panic in a handler => generic 500 body, no panic text
	e.hooks.AfterStepUpConsume = func() error { panic("secret-panic-text-should-not-leak") }
	d := e.onboard("alice", goodPIN)
	tx := e.txBody("0.1")
	tok := e.spendToken(d, tx)
	r = e.postTx(d, tx, tok, newIdem())
	require.Equal(t, 500, r.Status)
	require.Equal(t, "INTERNAL", r.code())
	require.NotContains(t, string(r.Body), "secret-panic")
	require.NotContains(t, e.logs.String(), "secret-panic")
	require.Contains(t, e.logs.String(), "panic recovered")
	e.hooks.AfterStepUpConsume = nil
	require.Equal(t, 202, e.postTx(d, tx, tok, newIdem()).Status, "panic rolled the transaction back")
}

// Malformed input never produces internals or a 5xx; every response validates against the contract (transport).
func TestErrorFuzz_NoInternalsLeak(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	rng := rand.New(rand.NewSource(42))
	paths := []struct{ m, p string }{
		{"POST", "/v1/auth/demo-login"}, {"POST", "/v1/devices"}, {"POST", "/v1/pin"}, {"PUT", "/v1/pin"}, {"POST", "/v1/pin/reset"},
		{"POST", "/v1/auth/pin/verify"}, {"POST", "/v1/auth/biometric/challenge"}, {"POST", "/v1/auth/biometric/verify"}, {"POST", "/v1/auth/refresh"},
		{"POST", "/v1/stepup/challenge"}, {"POST", "/v1/stepup/verify"}, {"POST", "/v1/transactions"},
		{"POST", "/v1/devices/" + d.id + "/biometric/enroll"}, {"POST", "/v1/devices/" + d.id + "/biometric/enroll/challenge"},
		{"DELETE", "/v1/devices/" + d.id + "/biometric"}, {"GET", "/v1/devices"}, {"GET", "/v1/dashboard"},
	}
	inj := []string{"' OR 1=1 --", "'; DROP TABLE users; --", "\x01\x02", "%00", "../../etc/passwd", "${jndi:ldap://x}", "{{7*7}}", strings.Repeat("A", 70000), "\u202e\u0000", "null", "[]", "1e999"}
	bodies := []func() any{
		func() any { return nil }, func() any { return "{" }, func() any { return "[]" }, func() any { return "null" }, func() any { return `{"a":}` },
		func() any { return strings.Repeat(`{"a":`, 5000) }, func() any { return `{"pin":123456}` }, func() any { return `{"pin":"123456","pin":"654321"}` },
		func() any { return []byte{0xff, 0xfe, 0x00, 0x01} },
		func() any {
			m := map[string]any{}
			for _, k := range []string{"username", "secret", "intent", "deviceId", "pin", "oldPin", "newPin", "challengeId", "signature", "publicKey", "name", "platform", "action", "targetDeviceId", "tx", "asset"} {
				if rng.Intn(2) == 0 {
					m[k] = inj[rng.Intn(len(inj))]
				}
			}
			return m
		},
	}
	hdrs := []map[string]string{
		nil, bearer(d.access), bearer(d.refresh), bearer("abc def"), {"Authorization": "Basic abc"}, {"Authorization": "Bearer"},
		merge(bearer(d.access), map[string]string{"Idempotency-Key": "%00%01", "X-StepUp-Token": "%27%20OR%201=1"}),
		merge(bearer(d.access), map[string]string{"Idempotency-Key": newIdem(), "X-StepUp-Token": MissingToken}),
		{"Content-Type": "text/plain"},
	}
	for i := 0; i < 500; i++ {
		p := paths[rng.Intn(len(paths))]
		r := e.do(p.m, p.p, bodies[rng.Intn(len(bodies))](), hdrs[rng.Intn(len(hdrs))])
		require.NotEqual(t, 500, r.Status, "%s %s -> %s", p.m, p.p, r.Body)
		require.NotEqual(t, 503, r.Status)
		if r.Status >= 400 {
			require.NotEmpty(t, r.code(), "%s %s %d %s", p.m, p.p, r.Status, r.Body)
		}
		low := strings.ToLower(string(r.Body))
		for _, bad := range []string{"panic", "goroutine", "pgx", "sql", "syntax", "unexpected", "json:", "cannot unmarshal", ".go:", "runtime"} {
			require.NotContains(t, low, bad, "%s %s -> %s", p.m, p.p, r.Body)
		}
	}
	// oversize body => 400 (contract: VALIDATION_ERROR), not a connection error
	r := e.do("POST", "/v1/devices", `{"name":"`+strings.Repeat("a", 17000)+`","platform":"ios"}`, withIdem(bearer(d.access)))
	require.Equal(t, 400, r.Status)
	require.Equal(t, "VALIDATION_ERROR", r.code())
}

// SEC-061: every event type is emitted by a scenario; the optional hash chain verifies and detects tampering.
func TestSec61_AuditEventCoverageAndChain(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.AuditChain = true
		c.LockSchedule = [5]int{1, 1, 1, 1, 1}
		c.Limits.DeviceFailMax = 1000
		c.Limits.DemoLoginIPMin = config.Limit{N: 40, Window: time.Minute}
	})
	// alice: PIN_SET, DEVICE_ADDED, LOGIN_OK, STEPUP_OK, BIO_ENROLLED, COOLING_OFF_STARTED
	a := bioDevice(t, e, "alice")
	// PIN_VERIFY_FAIL, PIN_LOCKED, PIN_UNLOCKED_AFTER_LOCK
	for i := 0; i < 5; i++ {
		e.verifyPin(a, otherPIN)
	}
	e.clk.Advance(2 * time.Second)
	e.unlock(a, goodPIN)
	// BIO_VERIFY_FAIL, BIO_KEY_INVALIDATED
	wrong, _ := newKey(t)
	for i := 0; i < 5; i++ {
		c := e.bioChallenge(a)
		e.bioVerify(a, map[string]any{"challengeId": c.m()["challengeId"], "deviceId": a.id, "signature": sign(t, wrong, challengeMsg(t, c.m(), "login"))})
	}
	// BIO_DISABLED
	e.enableBio(a, goodPIN)
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+a.id+"/biometric", nil, bearer(a.access)).Status)
	// REFRESH_REUSE
	old := *a
	r := e.refresh(a)
	require.Equal(t, 200, r.Status, string(r.Body))
	a.applySession(r.m())
	require.Equal(t, 401, e.refresh(&old).Status)
	// bob: TX_CREATED, STEPUP_FAIL, PIN_CHANGED, DEVICE_REVOKED
	b := e.onboard("bob", goodPIN)
	tx := e.txBody("0.1")
	require.Equal(t, 202, e.postTx(b, tx, e.spendToken(b, tx), newIdem()).Status)
	_, v := e.stepUpPIN(b, map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, otherPIN)
	require.Equal(t, 401, v.Status)
	pc := e.do("PUT", "/v1/pin", map[string]string{"oldPin": goodPIN, "newPin": "731905"}, withIdem(bearer(b.access)))
	require.Equal(t, 200, pc.Status, string(pc.Body))
	b.applySession(pc.m())
	b2 := e.addDevice("bob", "731905", "second")
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+b2.id, nil, bearer(b2.access)).Status)
	// PIN_HARD_LOCKED + DEVICE_BLOCKED (10 evaluated failures inside the window), then PIN_RESET
	for i := 0; i < 10; i++ {
		e.verifyPin(b, otherPIN)
		e.clk.Advance(2 * time.Second)
	}
	rt, _ := e.demoLogin("bob", "reset")
	nid, rr := e.register(rt, "recovery")
	require.NotEmpty(t, nid, string(rr.Body))
	rres := e.do("POST", "/v1/pin/reset", map[string]string{"pin": goodPIN}, withIdem(bearer(rt)))
	require.Equal(t, 200, rres.Status)
	// DEVICE_BLOCKED on the recovery device (2 evaluated failures with a lowered limit)
	e.cfg.Limits.DeviceFailMax = 2
	e.restart()
	rec := &device{id: nid}
	rec.applySession(rres.m())
	e.verifyPin(rec, otherPIN)
	e.verifyPin(rec, otherPIN)
	e.cfg.Limits.DeviceFailMax = 8
	// LOGIN_FAIL
	e.do("POST", "/v1/auth/demo-login", map[string]string{"username": "alice", "secret": "wrong-secret-value", "intent": "login"}, nil)
	// RATE_LIMITED
	e.cfg.Limits.DemoLoginIPMin = config.Limit{N: 1, Window: time.Minute}
	e.restart()
	e.demoLogin("alice", "login")
	require.Equal(t, 429, e.do("POST", "/v1/auth/demo-login", map[string]string{"username": "alice", "secret": secretAlice, "intent": "login"}, nil).Status)

	seen := map[string]int{}
	rows, err := e.db.Pool.Query(context.Background(), "SELECT event_type, count(*) FROM audit_events GROUP BY 1")
	require.NoError(t, err)
	for rows.Next() {
		var k string
		var n int
		require.NoError(t, rows.Scan(&k, &n))
		seen[k] = n
	}
	for _, typ := range audit.AllTypes {
		require.Greater(t, seen[typ], 0, "event type %s is never emitted", typ)
	}
	// audit rows carry the allowlisted fields only and never a secret
	require.Equal(t, 0, e.count(`SELECT count(*) FROM audit_events WHERE metadata::text ~* '"(pin|token|nonce|signature|hash|key|secret)":'`))

	// hash chain
	bad, err := audit.VerifyChain(context.Background(), e.app.Store.Q)
	require.NoError(t, err)
	require.EqualValues(t, 0, bad, "chain intact")
	owner, err := pgx.Connect(context.Background(), e.db.OwnerDSN)
	require.NoError(t, err)
	defer owner.Close(context.Background())
	_, err = owner.Exec(context.Background(), "UPDATE audit_events SET result = result || 'X' WHERE id=(SELECT min(id)+3 FROM audit_events)")
	require.NoError(t, err)
	bad, err = audit.VerifyChain(context.Background(), e.app.Store.Q)
	require.NoError(t, err)
	require.NotZero(t, bad, "tampering is detected")
}
