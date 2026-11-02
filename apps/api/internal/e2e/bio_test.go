package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/cryptomsg"
)

func bioDevice(t *testing.T, e *env, user string) *device {
	d := e.onboard(user, goodPIN)
	e.enableBio(d, goodPIN)
	return d
}

func TestBiometricHappyPathAndSessionShape(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	r := e.bioLogin(d)
	require.Equal(t, 200, r.Status, string(r.Body))
	m := r.m()
	require.Equal(t, "bio", m["amr"])
	require.Equal(t, true, m["biometricEnabled"])
	require.Equal(t, "no-store", r.Header.Get("Cache-Control"))
	d.applySession(m)
	require.Equal(t, 200, e.do("GET", "/v1/dashboard", nil, bearer(d.access)).Status)
	// exactly one live family per device after two unlocks
	e.unlock(d, goodPIN)
	require.Equal(t, 1, e.count("SELECT count(DISTINCT family_id) FROM sessions WHERE revoked_at IS NULL AND device_id=$1::uuid", d.id))
}

// spec s7 test 6
func TestSec7_06_ReplayConcurrentExpiredPurposeConfusion(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")

	// replay of a captured verify body
	c := e.bioChallenge(d.id)
	body := map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, d.key, challengeMsg(t, c.m(), "login"))}
	require.Equal(t, 200, e.do("POST", "/v1/auth/biometric/verify", body, nil).Status)
	r := e.do("POST", "/v1/auth/biometric/verify", body, nil)
	require.Equal(t, 401, r.Status)
	require.Equal(t, "AUTH_FAILED", r.code())

	// concurrent double verify of one nonce => exactly one 200
	c = e.bioChallenge(d.id)
	body = map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, d.key, challengeMsg(t, c.m(), "login"))}
	var wg sync.WaitGroup
	var ok atomic.Int64
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e.do("POST", "/v1/auth/biometric/verify", body, nil).Status == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, ok.Load())

	// expired nonce
	c = e.bioChallenge(d.id)
	sig := sign(t, d.key, challengeMsg(t, c.m(), "login"))
	e.clk.Advance(61 * time.Second)
	r = e.do("POST", "/v1/auth/biometric/verify", map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sig}, nil)
	require.Equal(t, 401, r.Status)

	// a signature made for purpose "stepup" or "enroll" does not log in
	for _, purpose := range []string{"stepup", "enroll"} {
		c = e.bioChallenge(d.id)
		sig = sign(t, d.key, challengeMsg(t, c.m(), purpose))
		r = e.do("POST", "/v1/auth/biometric/verify", map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sig}, nil)
		require.Equal(t, 401, r.Status, purpose)
	}
}

// Login signature must not satisfy a step-up verification (domain separation, SEC-027/043).
func TestSec7_06_LoginSignatureFailsAsStepUp(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	e.clk.Advance(25 * time.Hour) // leave cooling-off so "either" is offered for a small tx
	e.unlock(d, goodPIN)
	c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(d.access))
	require.Equal(t, 200, c.Status, string(c.Body))
	require.Equal(t, "either", c.m()["required"])
	sig := sign(t, d.key, challengeMsg(t, c.m(), "login")) // wrong purpose
	r := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": c.m()["challengeId"], "signature": sig}, bearer(d.access))
	require.Equal(t, 401, r.Status)
	require.Equal(t, "AUTH_FAILED", r.code())
}

// Unknown device, revoked key, bad signature, expired, replayed, no challenge: identical bodies and headers.
func TestSec7_06_FailureModesAreByteIdentical(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	other, _ := newKey(t)
	type outcome struct {
		body string
		hdr  []string
	}
	norm := func(r resp) outcome {
		var hs []string
		for k, v := range r.Header {
			if k == "X-Request-Id" || k == "Date" {
				continue
			}
			hs = append(hs, k+"="+strings.Join(v, ","))
		}
		sort.Strings(hs)
		return outcome{string(r.Body), hs}
	}
	verify := func(devID, chal string, k *ecdsa.PrivateKey, c map[string]any) resp {
		sig := "AAAA"
		if k != nil && c != nil {
			sig = sign(t, k, challengeMsg(t, c, "login"))
		}
		return e.do("POST", "/v1/auth/biometric/verify", map[string]any{"challengeId": chal, "deviceId": devID, "signature": sig}, nil)
	}
	var outs []outcome
	// bad signature
	c := e.bioChallenge(d.id)
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), other, c.m())))
	// replayed
	c = e.bioChallenge(d.id)
	good := verify(d.id, c.m()["challengeId"].(string), d.key, c.m())
	require.Equal(t, 200, good.Status)
	d.applySession(good.m())
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), d.key, c.m())))
	// expired
	c = e.bioChallenge(d.id)
	e.clk.Advance(2 * time.Minute)
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), d.key, c.m())))
	// no challenge at all
	outs = append(outs, norm(verify(d.id, "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", d.key, c.m())))
	// unknown device (decoy challenge)
	dc := e.bioChallenge("99999999-9999-4999-8999-999999999999")
	require.Equal(t, 200, dc.Status)
	outs = append(outs, norm(verify("99999999-9999-4999-8999-999999999999", dc.m()["challengeId"].(string), d.key, dc.m())))
	// revoked key (disable biometrics, then try with the old key on a leftover challenge)
	c = e.bioChallenge(d.id)
	e.unlock(d, goodPIN)
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+d.id+"/biometric", nil, bearer(d.access)).Status)
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), d.key, c.m())))
	for i := 1; i < len(outs); i++ {
		require.Equal(t, outs[0], outs[i], "failure mode %d differs from the bad-signature response", i)
	}
	require.Contains(t, outs[0].body, `"code":"AUTH_FAILED"`)
}

// Decoy challenge is indistinguishable in shape and headers from a real one, and nothing is stored for it.
func TestSec7_06_DecoyChallengeShape(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	real := e.bioChallenge(d.id)
	decoy := e.bioChallenge("99999999-9999-4999-8999-999999999999")
	var k1, k2 []string
	for k := range real.m() {
		k1 = append(k1, k)
	}
	for k := range decoy.m() {
		k2 = append(k2, k)
	}
	sort.Strings(k1)
	sort.Strings(k2)
	require.Equal(t, k1, k2)
	require.Equal(t, real.Header.Get("Cache-Control"), decoy.Header.Get("Cache-Control"))
	require.Equal(t, "99999999-9999-4999-8999-999999999999", decoy.m()["deviceId"], "decoy echoes the requested device id")
	require.Equal(t, 1, e.count("SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND purpose='login'"))
	// a not-enrolled device also gets a decoy
	d2 := e.onboard("bob", goodPIN)
	nr := e.bioChallenge(d2.id)
	require.Equal(t, 200, nr.Status)
	require.Equal(t, 1, e.count("SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND purpose='login'"))
}

// SEC-030: 5 consecutive bad signatures revoke the key; the PIN counter is untouched; a valid signature then fails.
func TestSec30_FiveBadSignaturesRevokeKey(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	wrong, _ := newKey(t)
	for i := 0; i < 5; i++ {
		c := e.bioChallenge(d.id)
		r := e.do("POST", "/v1/auth/biometric/verify", map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, wrong, challengeMsg(t, c.m(), "login"))}, nil)
		require.Equal(t, 401, r.Status)
	}
	require.Equal(t, 0, e.failCount("alice"))
	require.Equal(t, 0, e.count("SELECT count(*) FROM device_keys WHERE revoked_at IS NULL AND device_id=$1::uuid", d.id))
	require.Equal(t, 401, e.bioLogin(d).Status)
	require.Equal(t, 1, e.count("SELECT count(*) FROM audit_events WHERE event_type='BIO_KEY_INVALIDATED'"))
}

// A success resets the consecutive-failure counter.
func TestSec30_SuccessResetsFailureCounter(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	wrong, _ := newKey(t)
	for round := 0; round < 3; round++ {
		for i := 0; i < 4; i++ {
			c := e.bioChallenge(d.id)
			e.do("POST", "/v1/auth/biometric/verify", map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, wrong, challengeMsg(t, c.m(), "login"))}, nil)
		}
		require.Equal(t, 200, e.bioLogin(d).Status)
	}
}

// D-05 / SEC-011: biometric is allowed during a soft lock and refused during a hard lock.
func TestSec7_05_HardLockBlocksPinAndBiometric_ResetRecovers(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	for i := 0; i < 5; i++ {
		e.verifyPin(d, otherPIN)
	}
	require.Equal(t, 423, e.verifyPin(d, goodPIN).Status)
	br := e.bioLogin(d)
	require.Equal(t, 200, br.Status, "soft lock: biometrics still work")
	d.applySession(br.m())
	// escalate to hard lock
	for i := 0; i < 5; i++ {
		e.clk.Advance(2 * time.Hour)
		e.verifyPin(d, otherPIN)
	}
	r := e.verifyPin(d, goodPIN)
	require.Equal(t, 423, r.Status)
	require.Equal(t, "hard", r.errField("lockType"))
	require.Equal(t, 401, e.bioLogin(d).Status, "hard lock refuses biometric login")
	dc := e.bioChallenge(d.id) // decoy for a hard-locked user
	require.Equal(t, 200, dc.Status)

	// recovery: demo-login(reset) -> new device -> reset
	tok, scope := e.demoLogin("alice", "reset")
	require.Equal(t, "pin-reset", scope)
	newID, rr := e.register(tok, "new-phone")
	require.NotEmpty(t, newID, string(rr.Body))
	require.NotNil(t, rr.m()["coolingOffUntil"], "re-registered device is in cooling-off")
	res := e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, withIdem(bearer(tok)))
	require.Equal(t, 200, res.Status, string(res.Body))
	require.NotNil(t, res.m()["coolingOffUntil"])
	nd := &device{id: newID, user: "alice"}
	nd.applySession(res.m())
	// everything old is dead
	require.Equal(t, 401, e.do("POST", "/v1/auth/refresh", nil, bearer(d.refresh)).Status)
	require.Equal(t, 401, e.do("GET", "/v1/devices", nil, bearer(d.access)).Status, "old access token: session revoked")
	require.Equal(t, 401, e.bioLogin(d).Status, "old device key revoked")
	require.Equal(t, 0, e.count("SELECT count(*) FROM device_keys k JOIN devices dv ON dv.id=k.device_id WHERE k.revoked_at IS NULL AND dv.user_id=$1::uuid", d.userID))
	require.Equal(t, 1, e.count("SELECT count(*) FROM devices WHERE user_id=$1::uuid AND revoked_at IS NULL", d.userID))
	// new PIN works, old does not, counters cleared
	vr := e.verifyPin(nd, otherPIN)
	require.Equal(t, 200, vr.Status)
	nd.applySession(vr.m())
	require.Equal(t, 0, e.failCount("alice"))
	for _, ev := range []string{"PIN_RESET", "COOLING_OFF_STARTED", "PIN_HARD_LOCKED"} {
		require.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_events WHERE event_type=$1", ev), 1, ev)
	}
	// cooling-off cap enforced
	c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("1")}, bearer(nd.access))
	require.Equal(t, 403, c.Status)
	require.Equal(t, "COOLING_OFF", c.code())
}

// spec s7 test 7
func TestSec7_07_EnrollmentRequirements(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	// no step-up header => 403 STEPUP_REQUIRED
	r := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, bearer(d.access))
	require.Equal(t, 403, r.Status, string(r.Body))
	require.Equal(t, "STEPUP_REQUIRED", r.code())
	// garbage token => STEPUP_INVALID
	r = e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4"}))
	require.Equal(t, 403, r.Status)
	require.Equal(t, "STEPUP_INVALID", r.code())

	// valid flow up to the challenge, then replay of the step-up token => STEPUP_INVALID (D-14)
	tok, v := e.stepUpPIN(d, map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, goodPIN)
	require.Equal(t, 200, v.Status)
	h := merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok})
	ch := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, h)
	require.Equal(t, 200, ch.Status, string(ch.Body))
	require.Equal(t, "enroll", ch.m()["purpose"])
	replay := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, h)
	require.Equal(t, 403, replay.Status)
	require.Equal(t, "STEPUP_INVALID", replay.code())

	// wrong-key PoP => 401
	k1, spki1 := newKey(t)
	k2, _ := newKey(t)
	enroll := func(challenge map[string]any, pub []byte, signer *ecdsa.PrivateKey) resp {
		return e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", map[string]any{"challengeId": challenge["challengeId"], "publicKey": cryptomsg.EncodeB64(pub),
			"signature": sign(t, signer, challengeMsg(t, challenge, "enroll")), "attestation": map[string]any{"type": "none", "keySecurityLevel": "software"}}, withIdem(bearer(d.access)))
	}
	require.Equal(t, 401, enroll(ch.m(), spki1, k2).Status)
	// the challenge was consumed by the failed attempt
	require.Equal(t, 401, enroll(ch.m(), spki1, k1).Status)
}

func TestSec7_07_InvalidPublicKeys422(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	der384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	_, good := newKey(t)
	off := append([]byte{}, good...)
	off[len(off)-1] ^= 0xff
	bad := map[string][]byte{"p384": der384, "off-curve": off, "oversize": make([]byte, 201), "trailing": append(append([]byte{}, good...), 0), "garbage": []byte("not a key at all")}
	for name, spki := range bad {
		tok, _ := e.stepUpPIN(d, map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, goodPIN)
		ch := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok}))
		require.Equal(t, 200, ch.Status, name)
		r := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", map[string]any{"challengeId": ch.m()["challengeId"], "publicKey": cryptomsg.EncodeB64(spki),
			"signature": "AAAA", "attestation": map[string]any{"type": "none", "keySecurityLevel": "software"}}, withIdem(bearer(d.access)))
		require.Equal(t, 422, r.Status, name)
		require.Equal(t, "INVALID_PUBLIC_KEY", r.code(), name)
	}
}

func TestSec7_07_SecondEnrollReplacesFirst(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	e.enableBio(d, goodPIN)
	first := *d
	e.enableBio(d, goodPIN)
	require.Equal(t, 1, e.count("SELECT count(*) FROM device_keys WHERE revoked_at IS NULL AND device_id=$1::uuid", d.id))
	require.Equal(t, 200, e.bioLogin(d).Status)
	require.Equal(t, 401, e.bioLogin(&first).Status, "old key's signatures no longer verify")
}

// SEC-022: attestation is stored but never trusted in the demo; the claimed type is NOT stored as verified.
func TestSec22_AttestationStoredAsUnverified(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	tok, _ := e.stepUpPIN(d, map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, goodPIN)
	ch := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok}))
	k, spki := newKey(t)
	r := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", map[string]any{"challengeId": ch.m()["challengeId"], "publicKey": cryptomsg.EncodeB64(spki),
		"signature": sign(t, k, challengeMsg(t, ch.m(), "enroll")), "attestation": map[string]any{"type": "app_attest", "keySecurityLevel": "secure_enclave", "data": "AAAA"}}, withIdem(bearer(d.access)))
	require.Equal(t, 201, r.Status, string(r.Body))
	require.Equal(t, 1, e.count("SELECT count(*) FROM device_keys WHERE attestation_type='none' AND key_security_level='secure_enclave'"))
	require.Equal(t, cryptomsg.EncodeB64(cryptomsg.Fingerprint(spki)), r.m()["keyFingerprint"])
}

// SEC-023: disable needs a recent unlock; after disabling, biometric verify fails; idempotent 204.
func TestSec23_DisableBiometric(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	e.clk.Advance(6 * time.Minute)
	r := e.do("DELETE", "/v1/devices/"+d.id+"/biometric", nil, bearer(d.access))
	require.Equal(t, 401, r.Status, "access token itself expired after 5 minutes")
	e.unlock(d, goodPIN)
	e.clk.Advance(4 * time.Minute) // access token still valid (TTL 5 min) but last unlock is older than... 4 min: allowed
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+d.id+"/biometric", nil, bearer(d.access)).Status)
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+d.id+"/biometric", nil, bearer(d.access)).Status, "idempotent")
	require.Equal(t, 401, e.bioLogin(d).Status)
	var dummy http.Header
	_ = dummy
}

func TestSec23_DisableNeedsRecentUnlock(t *testing.T) {
	e := newEnv(t, func(c *configT) { c.AccessTTL = 10 * time.Minute })
	d := bioDevice(t, e, "alice")
	e.unlock(d, goodPIN)
	e.clk.Advance(6 * time.Minute)
	r := e.do("DELETE", "/v1/devices/"+d.id+"/biometric", nil, bearer(d.access))
	require.Equal(t, 403, r.Status, string(r.Body))
	require.Equal(t, "STEPUP_REQUIRED", r.code())
}
