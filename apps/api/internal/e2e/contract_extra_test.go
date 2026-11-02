package e2e

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/config"
	"github.com/cryptoapp/api/internal/cryptomsg"
)

// TestContractRemainingStatuses drives the (operation, status) pairs the other scenarios do not reach.
func TestContractRemainingStatuses(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Limits.EnrollUser = config.Limit{N: 2, Window: time.Hour}
		c.Limits.StepUpUser = lim(3)
	})
	d := e.onboard("alice", goodPIN)

	// biometricEnroll 200: idempotent replay of the same request
	tok, _ := e.stepUpPIN(d, map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, goodPIN)
	ch := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll/challenge", nil, merge(bearer(d.access), map[string]string{"X-StepUp-Token": tok}))
	require.Equal(t, 200, ch.Status, string(ch.Body))
	k, spki := newKey(t)
	body := map[string]any{"challengeId": ch.m()["challengeId"], "publicKey": cryptomsg.EncodeB64(spki), "signature": sign(t, k, challengeMsg(t, ch.m(), "enroll")),
		"attestation": map[string]any{"type": "none", "keySecurityLevel": "tee"}}
	h := withIdem(bearer(d.access))
	first := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", body, h)
	require.Equal(t, 201, first.Status, string(first.Body))
	again := e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", body, h)
	require.Equal(t, 200, again.Status, string(again.Body))
	require.Equal(t, first.m()["keyId"], again.m()["keyId"])
	require.Equal(t, 1, e.count("SELECT count(*) FROM device_keys WHERE device_id=$1::uuid", d.id))
	// same key, different body => 422 IDEMPOTENCY_KEY_REUSED
	body2 := map[string]any{"challengeId": body["challengeId"], "publicKey": body["publicKey"], "signature": "AAAA", "attestation": body["attestation"]}
	require.Equal(t, 422, e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", body2, h).Status)

	// biometricEnroll 429: enroll limit (2/h in this env; one used above)
	e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", body, withIdem(bearer(d.access)))
	require429(t, e.do("POST", "/v1/devices/"+d.id+"/biometric/enroll", body, withIdem(bearer(d.access))), "enroll limit")

	// resetPin 403 (wrong scope), 422 (weak), 409 (replay)
	vt, _ := e.demoLogin("alice", "login") // pin-verify scope
	e.register(vt, "x")
	r := e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, withIdem(bearer(vt)))
	require.Equal(t, 403, r.Status)
	rt, _ := e.demoLogin("alice", "reset")
	nid, _ := e.register(rt, "recovery")
	require.NotEmpty(t, nid)
	require.Equal(t, 422, e.do("POST", "/v1/pin/reset", map[string]string{"pin": "123456"}, withIdem(bearer(rt))).Status)
	rh := withIdem(bearer(rt))
	require.Equal(t, 200, e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, rh).Status)
	rr := e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, rh)
	require.Equal(t, 409, rr.Status, string(rr.Body))
	require.Equal(t, "IDEMPOTENT_REPLAY", rr.code())
	require.NotContains(t, string(rr.Body), "Token")
	// the reset token is single use even with a fresh key
	require.Equal(t, 401, e.do("POST", "/v1/pin/reset", map[string]string{"pin": otherPIN}, withIdem(bearer(rt))).Status)

	// revokeDevice 401, stepupChallenge 401
	require.Equal(t, 401, e.do("DELETE", "/v1/devices/"+d.id, nil, nil).Status)
	require.Equal(t, 401, e.do("POST", "/v1/stepup/challenge", map[string]any{"action": "enable_biometric", "targetDeviceId": d.id}, nil).Status)
	require.Equal(t, 401, e.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", "pin": goodPIN}, nil).Status)

	// stepupVerify 429 (user limit 3 in this env)
	e2 := newEnv(t, func(c *config.Config) { c.Limits.StepUpUser = lim(3) })
	d2 := e2.onboard("bob", goodPIN)
	for i := 0; i < 3; i++ {
		e2.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", "pin": goodPIN}, bearer(d2.access))
	}
	require429(t, e2.do("POST", "/v1/stepup/verify", map[string]any{"challengeId": "7b1f0f3e-8d2a-4b53-a1c4-5e6f7a8b9c0d", "pin": goodPIN}, bearer(d2.access)), "stepup verify limit")
}
