package e2e

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// registerExtra registers another device for the user using a pin-verify bootstrap token and unlocks it with the PIN.
func (e *env) addDevice(user, pinCode, name string) *device {
	tok, scope := e.demoLogin(user, "login")
	require.Equal(e.t, "pin-verify", scope)
	id, r := e.register(tok, name)
	require.NotEmpty(e.t, id, string(r.Body))
	d := &device{id: id, user: user, userID: e.userID(user)}
	v := e.do("POST", "/v1/auth/pin/verify", map[string]string{"deviceId": id, "pin": pinCode}, bearer(tok))
	require.Equal(e.t, 200, v.Status, string(v.Body))
	d.applySession(v.m())
	return d
}

func TestSec48_DeviceCapAndResetExemption(t *testing.T) {
	e := newEnv(t)
	first := e.onboard("alice", goodPIN)
	var devs = []*device{first}
	for i := 0; i < 4; i++ {
		devs = append(devs, e.addDevice("alice", goodPIN, "extra"))
	}
	require.Equal(t, 5, e.count("SELECT count(*) FROM devices WHERE revoked_at IS NULL AND user_id=$1::uuid", first.userID))
	tok, _ := e.demoLogin("alice", "login")
	id, r := e.register(tok, "sixth")
	require.Empty(t, id)
	require.Equal(t, 409, r.Status)
	require.Equal(t, "DEVICE_LIMIT", r.code())
	// recovery path: a pin-reset token is exempt from the cap and the reset frees the budget again
	rt, scope := e.demoLogin("alice", "reset")
	require.Equal(t, "pin-reset", scope)
	nid, rr := e.register(rt, "recovery")
	require.NotEmpty(t, nid, string(rr.Body))
	res := e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, withIdem(bearer(rt)))
	require.Equal(t, 200, res.Status, string(res.Body))
	require.Equal(t, 1, e.count("SELECT count(*) FROM devices WHERE revoked_at IS NULL AND user_id=$1::uuid", first.userID))
	_ = devs
}

func TestDeviceRegistration_IdempotencyAndCooling(t *testing.T) {
	e := newEnv(t)
	tok, _ := e.demoLogin("alice", "login")
	h := withIdem(bearer(tok))
	body := map[string]any{"name": "My phone", "platform": "android"}
	r1 := e.do("POST", "/v1/devices", body, h)
	require.Equal(t, 201, r1.Status, string(r1.Body))
	require.Nil(t, r1.m()["coolingOffUntil"], "first device: no cooling-off")
	r2 := e.do("POST", "/v1/devices", body, h)
	require.Equal(t, 200, r2.Status, string(r2.Body))
	require.Equal(t, r1.m()["deviceId"], r2.m()["deviceId"])
	r3 := e.do("POST", "/v1/devices", map[string]any{"name": "Other", "platform": "android"}, h)
	require.Equal(t, 422, r3.Status)
	require.Equal(t, "IDEMPOTENCY_KEY_REUSED", r3.code())
	require.Equal(t, 1, e.count("SELECT count(*) FROM devices"))
	// a bound token cannot register a second device
	r4 := e.do("POST", "/v1/devices", body, withIdem(bearer(tok)))
	require.Equal(t, 403, r4.Status)
	// server generated v4 id, never client supplied
	id, err := uuid.Parse(r1.m()["deviceId"].(string))
	require.NoError(t, err)
	require.EqualValues(t, 4, id.Version())
	// client-chosen id is not an accepted field
	tok2, _ := e.demoLogin("bob", "login")
	r5 := e.do("POST", "/v1/devices", map[string]any{"name": "x", "platform": "ios", "deviceId": "11111111-1111-4111-8111-111111111111"}, withIdem(bearer(tok2)))
	require.Equal(t, 400, r5.Status)
}

func TestListDevicesOnlyOwnWithCurrentFlag(t *testing.T) {
	e := newEnv(t)
	a := e.onboard("alice", goodPIN)
	a2 := e.addDevice("alice", goodPIN, "tablet")
	b := e.onboard("bob", goodPIN)
	e.enableBio(a, goodPIN)
	r := e.do("GET", "/v1/devices", nil, bearer(a2.access))
	require.Equal(t, 200, r.Status)
	devs := r.m()["devices"].([]any)
	require.Len(t, devs, 2)
	for _, x := range devs {
		m := x.(map[string]any)
		require.NotEqual(t, b.id, m["id"])
		require.Equal(t, m["id"] == a2.id, m["current"])
		require.Equal(t, m["id"] == a.id, m["biometricEnabled"])
		for _, banned := range []string{"pin", "hash", "salt", "publicKey", "spki", "userId"} {
			require.NotContains(t, m, banned)
		}
	}
}

// spec s7 test 10: IDOR
func TestSec7_10_IDOR(t *testing.T) {
	e := newEnv(t)
	a := bioDevice(t, e, "alice")
	b := e.onboard("bob", goodPIN)
	h := bearer(b.access)
	for _, c := range []struct{ m, p string }{
		{"DELETE", "/v1/devices/" + a.id},
		{"DELETE", "/v1/devices/" + a.id + "/biometric"},
	} {
		r := e.do(c.m, c.p, nil, h)
		require.Equal(t, 404, r.Status, c.m+" "+c.p)
		require.Equal(t, "NOT_FOUND", r.code())
	}
	r := e.do("POST", "/v1/devices/"+a.id+"/biometric/enroll/challenge", nil, merge(h, map[string]string{"X-StepUp-Token": MissingToken}))
	require.Equal(t, 404, r.Status, "path id must be the caller's own device")
	r = e.do("POST", "/v1/devices/"+a.id+"/biometric/enroll", map[string]any{"challengeId": uuid.NewString(), "publicKey": "AAAA", "signature": "AAAA",
		"attestation": map[string]any{"type": "none", "keySecurityLevel": "software"}}, withIdem(h))
	require.Equal(t, 404, r.Status)
	r = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "revoke_device", "targetDeviceId": a.id}, h)
	require.Equal(t, 404, r.Status)
	r = e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "revoke_device", "targetDeviceId": uuid.NewString()}, h)
	require.Equal(t, 404, r.Status, "unknown id is indistinguishable from a foreign one")
	// alice is untouched
	br := e.bioLogin(a)
	require.Equal(t, 200, br.Status)
	a.applySession(br.m())
	// a step-up challenge/verify id from another user is unusable
	ac := e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "transaction", "tx": e.txBody("0.1")}, bearer(a.access))
	r = e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": ac.m()["challengeId"], "pin": goodPIN}, h)
	require.Equal(t, 401, r.Status, string(r.Body))
	v := e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": ac.m()["challengeId"], "pin": goodPIN}, bearer(a.access))
	require.Equal(t, 200, v.Status, "bob's attempt did not burn alice's challenge")
}

const MissingToken = "Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4Zm9vYmFyYmF6cXV4"

func TestSec38_RevokeOtherDeviceNeedsPinStepUp(t *testing.T) {
	e := newEnv(t)
	a := e.onboard("alice", goodPIN)
	b := e.addDevice("alice", goodPIN, "tablet")
	e.enableBio(b, goodPIN)
	// no header
	r := e.do("DELETE", "/v1/devices/"+b.id, nil, bearer(a.access))
	require.Equal(t, 403, r.Status, string(r.Body))
	require.Equal(t, "STEPUP_REQUIRED", r.code())
	require.Equal(t, "pin", r.errField("required"))
	// token for a different target does not authorise it
	tokOther, _ := e.stepUpPIN(a, map[string]any{"action": "revoke_device", "targetDeviceId": a.id}, goodPIN)
	r = e.do("DELETE", "/v1/devices/"+b.id, nil, merge(bearer(a.access), map[string]string{"X-StepUp-Token": tokOther}))
	require.Equal(t, 403, r.Status)
	require.Equal(t, "STEPUP_INVALID", r.code())
	require.Equal(t, 1, e.count("SELECT count(*) FROM devices WHERE id=$1::uuid AND revoked_at IS NULL", b.id))
	// proper token
	tok, v := e.stepUpPIN(a, map[string]any{"action": "revoke_device", "targetDeviceId": b.id}, goodPIN)
	require.Equal(t, 200, v.Status, string(v.Body))
	h := merge(bearer(a.access), map[string]string{"X-StepUp-Token": tok})
	require.Equal(t, 204, e.do("DELETE", "/v1/devices/"+b.id, nil, h).Status)
	require.Equal(t, 404, e.do("DELETE", "/v1/devices/"+b.id, nil, h).Status)
	// the revoked device is dead: refresh, PIN, biometric, access token
	require.Equal(t, 401, e.refresh(b).Status)
	require.Equal(t, 401, e.verifyPin(b, goodPIN).Status)
	require.Equal(t, 401, e.bioLogin(b).Status)
	require.Equal(t, 401, e.do("GET", "/v1/dashboard", nil, bearer(b.access)).Status)
	require.GreaterOrEqual(t, e.count("SELECT count(*) FROM audit_events WHERE event_type='DEVICE_REVOKED'"), 1)
}
