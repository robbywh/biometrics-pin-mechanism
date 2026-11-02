package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/platform/httpx"
)

func validator(t testing.TB) http.Handler {
	r, err := validatorRouter()
	if err != nil {
		t.Fatal(err)
	}
	b := &builder{router: r}
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	return httpx.BodyLimit(MaxBody)(b.validate(ok))
}

const (
	uuid4  = "2f0c9a4e-5b1d-4c6e-9a3f-7d8e1b2c3d4e"
	tokenS = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4"
	txJSON = `{"asset":"ETH","network":"ethereum","destination":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","amount":"1.5","fee":"0.001","txNonce":"33333333-3333-4333-8333-333333333333","expiry":1767225900}`
)

func req(method, path, body string, hdr ...string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	return r
}

// T2: table-driven validation (>= 15 cases), including injection strings and ambiguous oneOf bodies.
func TestRequestValidationTable(t *testing.T) {
	h := validator(t)
	idem := []string{"Idempotency-Key", uuid4}
	cases := []struct {
		name string
		r    *http.Request
		want int
	}{
		{"valid demo-login", req("POST", "/v1/auth/demo-login", `{"username":"alice","secret":"s","intent":"login"}`), 204},
		{"unknown field", req("POST", "/v1/auth/demo-login", `{"username":"alice","secret":"s","intent":"login","x":1}`), 400},
		{"wrong type pin number", req("POST", "/v1/pin", `{"pin":123456}`, idem...), 400},
		{"pin too short", req("POST", "/v1/pin", `{"pin":"12345"}`, idem...), 400},
		{"pin letters", req("POST", "/v1/pin", `{"pin":"12345a"}`, idem...), 400},
		{"pin unicode digits", req("POST", "/v1/pin", `{"pin":"١٢٣٤٥٦"}`, idem...), 400},
		{"missing idempotency key", req("POST", "/v1/pin", `{"pin":"493017"}`), 400},
		{"idempotency key not uuid", req("POST", "/v1/pin", `{"pin":"493017"}`, "Idempotency-Key", "not-a-uuid"), 400},
		{"valid pin", req("POST", "/v1/pin", `{"pin":"493017"}`, idem...), 204},
		{"bad intent enum", req("POST", "/v1/auth/demo-login", `{"username":"alice","secret":"s","intent":"admin"}`), 400},
		{"sql injection username", req("POST", "/v1/auth/demo-login", `{"username":"alice' OR '1'='1","secret":"s","intent":"login"}`), 400},
		{"sql injection secret is just a string", req("POST", "/v1/auth/demo-login", `{"username":"alice","secret":"' OR 1=1 --","intent":"login"}`), 204},
		{"bad uuid in body", req("POST", "/v1/auth/pin/verify", `{"deviceId":"nope","pin":"493017"}`), 400},
		{"uppercase uuid rejected", req("POST", "/v1/auth/pin/verify", `{"deviceId":"2F0C9A4E-5B1D-4C6E-9A3F-7D8E1B2C3D4E","pin":"493017"}`), 400},
		{"valid pin verify", req("POST", "/v1/auth/pin/verify", `{"deviceId":"`+uuid4+`","pin":"493017"}`), 204},
		{"bad uuid in path", req("DELETE", "/v1/devices/not-a-uuid", ""), 400},
		{"stepup verify both proofs", req("POST", "/v1/stepup/verify", `{"challengeId":"`+uuid4+`","pin":"493017","signature":"AAAA"}`), 400},
		{"stepup verify pin only", req("POST", "/v1/stepup/verify", `{"challengeId":"`+uuid4+`","pin":"493017"}`), 204},
		{"stepup verify signature only", req("POST", "/v1/stepup/verify", `{"challengeId":"`+uuid4+`","signature":"AAAA"}`), 204},
		{"stepup verify neither", req("POST", "/v1/stepup/verify", `{"challengeId":"`+uuid4+`"}`), 400},
		{"stepup challenge tx", req("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+txJSON+`}`), 204},
		{"stepup challenge tx extra field", req("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+txJSON+`,"approved":true}`), 400},
		{"stepup challenge mixed shapes", req("POST", "/v1/stepup/challenge", `{"action":"transaction","targetDeviceId":"`+uuid4+`"}`), 400},
		{"stepup challenge enable", req("POST", "/v1/stepup/challenge", `{"action":"enable_biometric","targetDeviceId":"`+uuid4+`"}`), 204},
		{"amount exponent", req("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+strings.Replace(txJSON, `"1.5"`, `"1e3"`, 1)+`}`), 400},
		{"amount leading zero", req("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+strings.Replace(txJSON, `"1.5"`, `"01"`, 1)+`}`), 400},
		{"amount as number", req("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+strings.Replace(txJSON, `"1.5"`, `1.5`, 1)+`}`), 400},
		{"destination with injection", req("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+strings.Replace(txJSON, `0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`, `0x'; DROP TABLE users;--aaaaaaaaaaaaaaaaaa`, 1)+`}`), 400},
		{"transaction without step-up header is valid (optional; the handler answers 403)", req("POST", "/v1/transactions", txJSON, idem...), 204},
		{"transaction malformed step-up token passes validation (handler answers 403 STEPUP_INVALID)", req("POST", "/v1/transactions", txJSON, "Idempotency-Key", uuid4, "X-StepUp-Token", "short"), 204},
		{"wrong content type", func() *http.Request {
			r := req("POST", "/v1/pin", `{"pin":"493017"}`, idem...)
			r.Header.Set("Content-Type", "text/plain")
			return r
		}(), 400},
		{"empty body", req("POST", "/v1/auth/demo-login", ""), 400},
		{"malformed json", req("POST", "/v1/auth/demo-login", `{"username":`), 400},
		{"json array", req("POST", "/v1/auth/demo-login", `[]`), 400},
		{"body over 16 KiB", req("POST", "/v1/devices", `{"name":"`+strings.Repeat("a", 17000)+`","platform":"ios"}`, idem...), 400},
		{"name too long", req("POST", "/v1/devices", `{"name":"`+strings.Repeat("a", 65)+`","platform":"ios"}`, idem...), 400},
		{"bad platform", req("POST", "/v1/devices", `{"name":"x","platform":"windows"}`, idem...), 400},
		{"unknown route passes through", req("GET", "/v1/nope", ""), 204},
		{"healthz outside /v1 untouched", req("GET", "/healthz", ""), 204},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, c.r)
		require.Equal(t, c.want, rec.Code, c.name)
		if c.want == 400 {
			require.JSONEq(t, `{"error":{"code":"VALIDATION_ERROR","message":"Invalid request."}}`, rec.Body.String(), c.name)
		}
	}
}

// FuzzValidate: arbitrary bodies/headers/paths never panic and only ever yield pass-through or the generic 400.
func FuzzValidate(f *testing.F) {
	h := validator(f)
	f.Add("POST", "/v1/auth/demo-login", `{"username":"alice","secret":"s","intent":"login"}`, uuid4)
	f.Add("POST", "/v1/stepup/verify", `{"challengeId":"`+uuid4+`","pin":"493017","signature":"AAAA"}`, tokenS)
	f.Add("POST", "/v1/stepup/challenge", `{"action":"transaction","tx":`+txJSON+`}`, "")
	f.Add("PUT", "/v1/pin", `{"oldPin":"493017","newPin":"508264"}`, uuid4)
	f.Fuzz(func(t *testing.T, method, path, body, hdr string) {
		if method == "" || strings.ContainsAny(method, " \r\n\x00") || strings.ContainsAny(path, " \r\n\x00") || !strings.HasPrefix(path, "/") {
			return
		}
		defer func() {
			if p := recover(); p != nil {
				t.Fatalf("panic: %v", p)
			}
		}()
		r, err := http.NewRequest(method, "http://x"+path, strings.NewReader(body))
		if err != nil {
			return
		}
		r.Header.Set("Content-Type", "application/json")
		if !strings.ContainsAny(hdr, "\r\n\x00") {
			r.Header.Set("Idempotency-Key", hdr)
			r.Header.Set("X-StepUp-Token", hdr)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != http.StatusNoContent && rec.Code != http.StatusBadRequest {
			t.Fatalf("unexpected status %d", rec.Code)
		}
		if rec.Code == http.StatusBadRequest && !strings.Contains(rec.Body.String(), "VALIDATION_ERROR") {
			t.Fatalf("400 without contract body: %s", rec.Body.String())
		}
	})
}
