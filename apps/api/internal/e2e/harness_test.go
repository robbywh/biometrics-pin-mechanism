package e2e

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/legacy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/apigen"
	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/config"
	"github.com/cryptoapp/api/internal/cryptomsg"
	"github.com/cryptoapp/api/internal/handlers"
	"github.com/cryptoapp/api/internal/pin"
	logx "github.com/cryptoapp/api/internal/platform/log"
	"github.com/cryptoapp/api/internal/server"
	"github.com/cryptoapp/api/internal/testutil/pg"
)

func TestMain(m *testing.M) {
	code := m.Run()
	pg.Terminate()
	os.Exit(code)
}

// Canary secrets: none of these may ever appear in logs or audit output.
const (
	canaryPIN    = "987654"
	canaryBearer = "canary-bearer-token-must-never-be-logged-0123456789"
	canaryIdem   = "canary-idempotency-key-must-never-be-logged"
	secretAlice  = "alice-demo-secret-0001"
	secretBob    = "bob-demo-secret-00002"
	goodPIN      = "493017"
	otherPIN     = "508264"
)

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type env struct {
	t      *testing.T
	srv    *httptest.Server
	app    *server.App
	clk    *clock.Fake
	cfg    *config.Config
	db     *pg.DB
	logs   *syncBuf
	audit  *syncBuf
	hc     *http.Client
	hooks  *handlers.Hooks
	hconc  int
	hasher *pin.Hasher
	hwait  time.Duration
	rec    *recorder
}

// recorder keeps every response body for leak assertions.
type recorder struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (r *recorder) add(b []byte) {
	r.mu.Lock()
	r.bodies = append(r.bodies, append([]byte(nil), b...))
	r.mu.Unlock()
}
func (r *recorder) all() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.bodies...)
}

type envOpt = any // func(*config.Config) or func(*env)

func baseEnv(extra map[string]string) func(string) string {
	m := map[string]string{
		"ENV": "dev", "DEMO_MODE": "true", "DATABASE_URL": "postgres://u:p@127.0.0.1:5432/x?sslmode=disable",
		"PEPPER": strings.Repeat("p", 40), "ACCESS_SIGNING_KEY": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
		"DEMO_SECRETS": "alice=" + secretAlice + ",bob=" + secretBob, "COOLING_OFF_DURATION": "86400",
	}
	for k, v := range extra {
		m[k] = v
	}
	return func(k string) string { return m[k] }
}

func newEnv(t *testing.T, opts ...envOpt) *env {
	t.Helper()
	cfg, err := config.Load(baseEnv(nil))
	require.NoError(t, err)
	// Generous limits by default so functional tests are not throttled; rate-limit tests tighten them.
	big := config.Limit{N: 1_000_000, Window: time.Minute}
	cfg.Limits = config.Limits{DemoLoginIPMin: big, DemoLoginIPHour: big, DemoLoginGlobal: big, PinVerifyDevice: big, PinVerifyIP: big,
		BioChallengeDevice: big, BioChallengeIP: big, BioVerifyDevice: big, BioVerifyIP: big, RefreshDevice: big, RefreshIP: big,
		StepUpUser: big, EnrollUser: big, PinChangeUser: big, TxUser: big, GlobalIP: big, DemoBreakerOpenFor: time.Minute,
		DeviceFailMax: 8, DeviceFailWindow: time.Hour, DeviceBlockFor: time.Hour}
	d := pg.New(t)
	e := &env{t: t, cfg: cfg, db: d, clk: clock.NewFake(t0), logs: &syncBuf{}, audit: &syncBuf{}, hooks: &handlers.Hooks{}, hconc: 8, hwait: 10 * time.Second}
	for _, o := range opts {
		switch f := o.(type) {
		case func(*config.Config):
			f(cfg)
		case func(*env):
			f(e)
		}
	}
	e.build()
	return e
}

func (e *env) build() {
	t := e.t
	hasher := e.hasher
	if hasher == nil {
		var err error
		hasher, err = pin.NewHasher(map[int16][]byte{e.cfg.PepperVersion: e.cfg.Pepper}, e.cfg.PepperVersion, pin.Params{MemoryKiB: 64, Time: 1, Parallelism: 1}, e.hconc, e.hwait)
		require.NoError(t, err)
	}
	app, err := server.New(server.Options{Cfg: e.cfg, Pool: e.db.Pool, Clk: e.clk, Log: logx.New(e.logs, slog.LevelDebug), AuditLog: logx.New(e.audit, slog.LevelDebug),
		Hasher: hasher, Hooks: handlers.Hooks{AfterStepUpConsume: func() error {
			if e.hooks.AfterStepUpConsume != nil {
				return e.hooks.AfterStepUpConsume()
			}
			return nil
		}}})
	require.NoError(t, err)
	require.NoError(t, server.SeedDemo(context.Background(), app.Store, e.cfg, e.clk))
	e.app = app
	e.srv = httptest.NewServer(app.Handler)
	t.Cleanup(e.srv.Close)
	if e.rec == nil {
		e.rec = &recorder{}
	}
	cdoc, err := apigen.GetSpec() // contract copy for response validation; relative server URL cleared (paths are matched without /v1)
	require.NoError(t, err)
	cdoc.Servers = nil
	e.hc = &http.Client{Transport: &validatingTransport{t: t, base: http.DefaultTransport, doc: cdoc, rec: e.rec}}
}

// restart builds a brand new server instance on the same database (simulated process restart).
func (e *env) restart() {
	e.srv.Close()
	e.build()
}

// ---- response validation against the canonical contract (T21) ----

var (
	covMu    sync.Mutex
	cov      = map[string]bool{} // "opId status"
	covCodes = map[string]bool{}
)

type validatingTransport struct {
	t    *testing.T
	base http.RoundTripper
	doc  *openapi3.T
	rec  *recorder
}

func (v *validatingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(reqBody))
	}
	resp, err := v.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))
	v.rec.add(body)
	v.validate(r, reqBody, resp, body)
	return resp, nil
}

func (v *validatingTransport) validate(r *http.Request, reqBody []byte, resp *http.Response, body []byte) {
	router, err := legacy.NewRouter(v.doc)
	if err != nil {
		v.t.Errorf("router: %v", err)
		return
	}
	vr := r.Clone(r.Context())
	u := *r.URL
	u.Path = strings.TrimPrefix(r.URL.Path, "/v1")
	vr.URL = &u
	vr.Body = io.NopCloser(bytes.NewReader(reqBody))
	route, params, err := router.FindRoute(vr)
	if err != nil {
		if resp.StatusCode != http.StatusNotFound { // only deliberately unknown routes may miss the contract
			v.t.Errorf("request %s %s is not part of the contract but got %d", r.Method, r.URL.Path, resp.StatusCode)
		}
		return
	}
	opts := &openapi3filter.Options{AuthenticationFunc: openapi3filter.NoopAuthenticationFunc, IncludeResponseStatus: true}
	in := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: &openapi3filter.RequestValidationInput{Request: vr, PathParams: params, Route: route, Options: opts},
		Status:                 resp.StatusCode, Header: resp.Header, Options: opts,
	}
	in.SetBodyBytes(body)
	if err := openapi3filter.ValidateResponse(r.Context(), in); err != nil {
		v.t.Errorf("RESPONSE CONTRACT VIOLATION [%s] %s %s -> %d: %v\nbody: %.300s", route.Operation.OperationID, r.Method, r.URL.Path, resp.StatusCode, err, string(body))
	}
	if resp.StatusCode >= 400 && (strings.Contains(string(body), `"stack"`) || strings.Contains(strings.ToLower(string(body)), "sql") || strings.Contains(string(body), "pgx")) {
		v.t.Errorf("internal text leaked in response body: %.200s", string(body))
	}
	covMu.Lock()
	cov[strings.ToLower(route.Operation.OperationID)+" "+itoa(resp.StatusCode)] = true
	var eb struct {
		Error struct{ Code string } `json:"error"`
	}
	if json.Unmarshal(body, &eb) == nil && eb.Error.Code != "" {
		covCodes[eb.Error.Code] = true
	}
	covMu.Unlock()
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// ---- HTTP helpers ----

type resp struct {
	Status int
	Header http.Header
	Body   []byte
}

func (r resp) into(v any) { json.Unmarshal(r.Body, v) } //nolint
func (r resp) code() string {
	var e struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(r.Body, &e)
	return e.Error.Code
}
func (r resp) m() map[string]any {
	var m map[string]any
	_ = json.Unmarshal(r.Body, &m)
	return m
}
func (r resp) errField(k string) any {
	m := r.m()
	if e, ok := m["error"].(map[string]any); ok {
		return e[k]
	}
	return nil
}

func (e *env) do(method, path string, body any, hdr map[string]string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		var b []byte
		switch x := body.(type) {
		case []byte:
			b = x
		case string:
			b = []byte(x)
		default:
			b, _ = json.Marshal(body)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	require.NoError(e.t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := e.hc.Do(req)
	require.NoError(e.t, err)
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{Status: res.StatusCode, Header: res.Header, Body: b}
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }
func withIdem(h map[string]string) map[string]string {
	if h == nil {
		h = map[string]string{}
	}
	h["Idempotency-Key"] = uuid.NewString()
	return h
}
func merge(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// ---- domain helpers ----

type device struct {
	id      string
	userID  string
	user    string
	refresh string
	access  string
	key     *ecdsa.PrivateKey
	spki    []byte
}

func (e *env) demoLogin(user, intent string) (token, scope string) {
	secret := map[string]string{"alice": secretAlice, "bob": secretBob}[user]
	r := e.do("POST", "/v1/auth/demo-login", map[string]string{"username": user, "secret": secret, "intent": intent}, nil)
	require.Equal(e.t, 200, r.Status, string(r.Body))
	m := r.m()
	return m["bootstrapToken"].(string), m["scope"].(string)
}

func (e *env) register(token, name string) (id string, r resp) {
	r = e.do("POST", "/v1/devices", map[string]any{"name": name, "platform": "ios"}, withIdem(bearer(token)))
	if r.Status == 201 {
		id = r.m()["deviceId"].(string)
	}
	return
}

func (d *device) applySession(m map[string]any) {
	d.access, d.refresh = m["accessToken"].(string), m["refreshToken"].(string)
	if v, ok := m["deviceId"].(string); ok {
		d.id = v
	}
}

// onboard: demo-login -> register -> set PIN. Returns a device with a live session.
func (e *env) onboard(user, pinCode string) *device {
	e.t.Helper()
	tok, scope := e.demoLogin(user, "login")
	require.Equal(e.t, "pin-setup", scope)
	id, _ := e.register(tok, user+"-phone")
	require.NotEmpty(e.t, id)
	r := e.do("POST", "/v1/pin", map[string]string{"pin": pinCode}, withIdem(bearer(tok)))
	require.Equal(e.t, 201, r.Status, string(r.Body))
	d := &device{id: id, user: user}
	d.applySession(r.m())
	d.userID = e.userID(user)
	return d
}

func (e *env) userID(user string) string {
	var id string
	require.NoError(e.t, e.db.Pool.QueryRow(context.Background(), "SELECT id FROM users WHERE username=$1", user).Scan(&id))
	return id
}

func (e *env) verifyPin(d *device, pinCode string) resp {
	return e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": d.id, "pin": pinCode}, bearer(d.refresh))
}

// unlock re-establishes a session with the PIN (returns the new session map).
func (e *env) unlock(d *device, pinCode string) {
	r := e.verifyPin(d, pinCode)
	require.Equal(e.t, 200, r.Status, string(r.Body))
	d.applySession(r.m())
}

func newKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	spki, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	return k, spki
}

func sign(t *testing.T, k *ecdsa.PrivateKey, msg []byte) string {
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, k, h[:])
	require.NoError(t, err)
	return cryptomsg.EncodeB64(sig)
}

// challengeMsg rebuilds the signed message from a challenge response map (what the client does).
func challengeMsg(t *testing.T, c map[string]any, purpose string) []byte {
	nonce, err := cryptomsg.DecodeB64(c["nonce"].(string))
	require.NoError(t, err)
	var bh []byte
	if s, ok := c["boundHash"].(string); ok {
		bh, err = cryptomsg.DecodeB64(s)
		require.NoError(t, err)
	}
	return cryptomsg.ChallengeMessage(purpose, c["userId"].(string), c["deviceId"].(string), nonce, int64(c["expiresAt"].(float64)), bh)
}

func (e *env) stepUpPIN(d *device, body any, pinCode string) (token string, r resp) {
	c := e.do("POST", "/v1/stepup/challenge", body, bearer(d.access))
	if c.Status != 200 {
		return "", c
	}
	v := e.do("POST", "/v1/stepup/verify", map[string]string{"challengeId": c.m()["challengeId"].(string), "pin": pinCode}, bearer(d.access))
	if v.Status == 200 {
		token = v.m()["stepUpToken"].(string)
	}
	return token, v
}

// enableBio runs the complete two-step enrollment with a fresh P-256 key.
func (e *env) enableBio(d *device, pinCode string) resp {
	e.t.Helper()
	tok, v := e.stepUpPIN(d, map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, pinCode)
	require.Equal(e.t, 200, v.Status, string(v.Body))
	ch := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok}))
	require.Equal(e.t, 200, ch.Status, string(ch.Body))
	k, spki := newKey(e.t)
	sig := sign(e.t, k, challengeMsg(e.t, ch.m(), "enroll"))
	r := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", map[string]any{
		"challengeId": ch.m()["challengeId"], "publicKey": cryptomsg.EncodeB64(spki), "signature": sig,
		"attestation": map[string]any{"type": "none", "keySecurityLevel": "secure_enclave"}}, withIdem(bearer(d.access)))
	require.Equal(e.t, 201, r.Status, string(r.Body))
	d.key, d.spki = k, spki
	return r
}

// bioChallenge / bioVerify carry the device credential (refresh token) required since contract v1.1.
func (e *env) bioChallenge(d *device) resp {
	return e.do("POST", "/v1/auth/biometric/challenge", map[string]string{"deviceId": d.id}, bearer(d.refresh))
}

func (e *env) bioVerify(d *device, body any) resp {
	return e.do("POST", "/v1/auth/biometric/verify", body, bearer(d.refresh))
}

func (e *env) bioLogin(d *device) resp {
	c := e.bioChallenge(d)
	if c.Status != 200 { // e.g. stale/revoked device credential: the whole login fails
		return c
	}
	return e.bioVerify(d, map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id,
		"signature": sign(e.t, d.key, challengeMsg(e.t, c.m(), "login"))})
}

func (e *env) count(q string, args ...any) int {
	var n int
	require.NoError(e.t, e.db.Pool.QueryRow(context.Background(), q, args...).Scan(&n))
	return n
}

func (e *env) txBody(amount string) map[string]any {
	return map[string]any{"asset": "ETH", "network": "ethereum", "destination": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "amount": amount, "fee": "0.001",
		"txNonce": uuid.NewString(), "expiry": e.clk.Now().Unix() + 300}
}

type configT = config.Config
