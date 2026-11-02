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

	// replay of a captured verify body (the replayer holds the device's CURRENT refresh token)
	c := e.bioChallenge(d)
	body := map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, d.key, challengeMsg(t, c.m(), "login"))}
	first := e.bioVerify(d, body)
	require.Equal(t, 200, first.Status)
	d.applySession(first.m())
	r := e.bioVerify(d, body)
	require.Equal(t, 401, r.Status)
	require.Equal(t, "AUTH_FAILED", r.code())

	// concurrent double verify of one nonce => exactly one 200
	c = e.bioChallenge(d)
	body = map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, d.key, challengeMsg(t, c.m(), "login"))}
	var wg sync.WaitGroup
	var ok atomic.Int64
	var win sync.Map
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if r := e.bioVerify(d, body); r.Status == 200 {
				ok.Add(1)
				win.Store("m", r.m())
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, ok.Load())
	m, _ := win.Load("m")
	d.applySession(m.(map[string]any))

	// expired nonce
	c = e.bioChallenge(d)
	sig := sign(t, d.key, challengeMsg(t, c.m(), "login"))
	e.clk.Advance(61 * time.Second)
	r = e.bioVerify(d, map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sig})
	require.Equal(t, 401, r.Status)

	// a signature made for purpose "stepup" or "enroll" does not log in
	for _, purpose := range []string{"stepup", "enroll"} {
		c = e.bioChallenge(d)
		sig = sign(t, d.key, challengeMsg(t, c.m(), purpose))
		r = e.bioVerify(d, map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sig})
		require.Equal(t, 401, r.Status, purpose)
	}
}

// Contract v1.1 (D-18): without the device credential, or with another device's, challenge and verify give the uniform 401.
func TestD18_BiometricEndpointsRequireDeviceCredential(t *testing.T) {
	e := newEnv(t)
	a := bioDevice(t, e, "alice")
	b := bioDevice(t, e, "bob")
	for name, h := range map[string]map[string]string{"none": nil, "garbage": bearer("nope"), "access token": bearer(a.access), "other user's refresh": bearer(b.refresh)} {
		r := e.do("POST", "/v1/auth/biometric/challenge", map[string]string{"deviceId": a.id}, h)
		require.Equal(t, 401, r.Status, name)
		require.Equal(t, "AUTH_FAILED", r.code(), name)
		r = e.do("POST", "/v1/auth/biometric/verify", map[string]any{"challengeId": uuidStr, "deviceId": a.id, "signature": "AAAA"}, h)
		require.Equal(t, 401, r.Status, name)
	}
	require.Equal(t, 0, e.count("SELECT count(*) FROM challenges WHERE purpose='login' AND consumed_at IS NULL AND device_id=$1::uuid", a.id), "an anonymous caller cannot create or supersede challenges")
	require.Equal(t, 0, e.count("SELECT bio_fail_count FROM device_keys WHERE device_id=$1::uuid", a.id), "and cannot count failures")
	// the credential is resolved without side effects: still usable as refresh token afterwards
	e.bioChallenge(a)
	require.Equal(t, 200, e.refresh(a).Status)
}

const uuidStr = "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d"

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
		return e.bioVerify(d, map[string]any{"challengeId": chal, "deviceId": devID, "signature": sig})
	}
	var outs []outcome
	// bad signature
	c := e.bioChallenge(d)
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), other, c.m())))
	// replayed
	c = e.bioChallenge(d)
	good := verify(d.id, c.m()["challengeId"].(string), d.key, c.m())
	require.Equal(t, 200, good.Status)
	d.applySession(good.m())
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), d.key, c.m())))
	// expired
	c = e.bioChallenge(d)
	e.clk.Advance(2 * time.Minute)
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), d.key, c.m())))
	// no challenge at all
	outs = append(outs, norm(verify(d.id, "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", d.key, c.m())))
	// device id that does not belong to the presented credential (unknown device)
	outs = append(outs, norm(verify("99999999-9999-4999-8999-999999999999", "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", d.key, c.m())))
	// suspended-by-failures key path is covered in TestSec30; hard-locked user:
	_ = 0
	// revoked key (disable biometrics, then try with the old key on a leftover challenge)
	c = e.bioChallenge(d)
	e.unlock(d, goodPIN)
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+d.id+"/biometric", nil, bearer(d.access)).Status)
	outs = append(outs, norm(verify(d.id, c.m()["challengeId"].(string), d.key, c.m())))
	for i := 1; i < len(outs); i++ {
		require.Equal(t, outs[0], outs[i], "failure mode %d differs from the bad-signature response", i)
	}
	require.Contains(t, outs[0].body, `"code":"AUTH_FAILED"`)
}

// Decoy challenge (not enrolled / suspended / hard locked) is indistinguishable in shape and headers from a real one.
func TestSec7_06_DecoyChallengeShape(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	real := e.bioChallenge(d)
	d2 := e.onboard("bob", goodPIN) // not enrolled => decoy
	decoy := e.bioChallenge(d2)
	require.Equal(t, 200, decoy.Status)
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
	require.Equal(t, d2.id, decoy.m()["deviceId"], "decoy echoes the device id")
	require.Equal(t, 1, e.count("SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND purpose='login'"), "nothing stored for the decoy")
	// L-02: the decoy userId is stable per device (HMAC), so calling twice reveals nothing; and it is not the real user id
	again := e.bioChallenge(d2)
	require.Equal(t, decoy.m()["userId"], again.m()["userId"])
	require.NotEqual(t, decoy.m()["nonce"], again.m()["nonce"])
	require.NotEqual(t, d2.userID, decoy.m()["userId"])
	require.Equal(t, real.m()["userId"], e.bioChallenge(d).m()["userId"], "real challenge userId is stable too")
}

// SEC-030 / D-19: 5 consecutive bad signatures SUSPEND biometrics (key kept) until the next PIN unlock.
func TestSec30_FiveBadSignaturesSuspendKeyUntilPinUnlock(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	wrong, _ := newKey(t)
	for i := 0; i < 5; i++ {
		c := e.bioChallenge(d)
		r := e.bioVerify(d, map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, wrong, challengeMsg(t, c.m(), "login"))})
		require.Equal(t, 401, r.Status)
	}
	require.Equal(t, 0, e.failCount("alice"))
	require.Equal(t, 1, e.count("SELECT count(*) FROM device_keys WHERE revoked_at IS NULL AND bio_suspended_at IS NOT NULL AND device_id=$1::uuid", d.id), "key kept, suspended")
	require.Equal(t, 401, e.bioLogin(d).Status, "a valid signature is refused while suspended")
	require.Equal(t, 1, e.count("SELECT count(*) FROM audit_events WHERE event_type='BIO_SUSPENDED'"))
	// the decoy path is taken for a suspended key (no live login challenge is stored)
	before := e.count("SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND purpose='login'")
	e.bioChallenge(d)
	require.Equal(t, before, e.count("SELECT count(*) FROM challenges WHERE consumed_at IS NULL AND purpose='login'"))
	// PIN unlock lifts the suspension; the key was never revoked, no re-enrolment
	e.unlock(d, goodPIN)
	r := e.bioLogin(d)
	require.Equal(t, 200, r.Status, string(r.Body))
	require.Equal(t, 1, e.count("SELECT count(*) FROM device_keys WHERE device_id=$1::uuid", d.id))
}

// L-05 / L-06
func TestL05_L06_HardLockBioStepUpAndDisableOtherDevice(t *testing.T) {
	e := newEnv(t, func(c *configT) { c.LockSchedule = [5]int{1, 1, 1, 1, 1}; c.Limits.DeviceFailMax = 1000 })
	a := bioDevice(t, e, "alice")
	b := e.addDevice("alice", goodPIN, "tab")
	r := e.do("DELETE", "/v1/devices/"+b.id+"/biometric", nil, bearer(a.access))
	require.Equal(t, 403, r.Status, "another device's key needs the PIN step-up route")
	require.Equal(t, "STEPUP_REQUIRED", r.code())
	e.clk.Advance(25 * time.Hour)
	e.unlock(a, goodPIN)
	c := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(a.access))
	require.Equal(t, "either", c.m()["required"])
	for i := 0; i < 10; i++ {
		e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": b.id, "pin": otherPIN}, bearer(b.refresh))
		e.clk.Advance(2 * time.Second)
	}
	v := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": c.m()["challengeId"], "signature": sign(t, a.key, challengeMsg(t, c.m(), "stepup"))}, bearer(a.access))
	require.Equal(t, 401, v.Status, string(v.Body))
}

// A success resets the consecutive-failure counter.
func TestSec30_SuccessResetsFailureCounter(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")
	wrong, _ := newKey(t)
	for round := 0; round < 3; round++ {
		for i := 0; i < 4; i++ {
			c := e.bioChallenge(d)
			e.bioVerify(d, map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, wrong, challengeMsg(t, c.m(), "login"))})
		}
		r := e.bioLogin(d)
		require.Equal(t, 200, r.Status)
		d.applySession(r.m())
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
	dc := e.bioChallenge(d) // decoy for a hard-locked user
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
	short := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": "short"}))
	require.Equal(t, 403, short.Status, "malformed step-up token is STEPUP_INVALID, not a validation error (D-21)")
	require.Equal(t, "STEPUP_INVALID", short.code())
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
