package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// SEC-066: lockout, consumed challenges, refresh-reuse state and hard locks survive a process restart.
func TestSec66_RestartKeepsSecurityState(t *testing.T) {
	e := newEnv(t)
	d := bioDevice(t, e, "alice")

	// consumed challenge cannot be replayed after a restart
	c := e.bioChallenge(d.id)
	body := map[string]any{"challengeId": c.m()["challengeId"], "deviceId": d.id, "signature": sign(t, d.key, challengeMsg(t, c.m(), "login"))}
	r := e.do("POST", "/v1/auth/biometric/verify", body, nil)
	require.Equal(t, 200, r.Status)
	d.applySession(r.m())
	e.restart()
	require.Equal(t, 401, e.do("POST", "/v1/auth/biometric/verify", body, nil).Status)

	// used refresh token is still "used" after a restart; the reuse revokes the family
	old := *d
	rr := e.refresh(d)
	require.Equal(t, 200, rr.Status)
	d.applySession(rr.m())
	e.restart()
	require.Equal(t, 401, e.refresh(&old).Status)
	require.Equal(t, 401, e.refresh(d).Status, "family revoked after reuse, state persisted")

	// hard lock persists
	e2 := newEnv(t, func(c *configT) { c.LockSchedule = [5]int{1, 1, 1, 1, 1}; c.Limits.DeviceFailMax = 1000 })
	d2 := e2.onboard("alice", goodPIN)
	for i := 0; i < 10; i++ {
		e2.verifyPin(d2, otherPIN)
		e2.clk.Advance(2 * time.Second)
	}
	e2.restart()
	rv := e2.verifyPin(d2, goodPIN)
	require.Equal(t, 423, rv.Status)
	require.Equal(t, "hard", rv.errField("lockType"))
}

func TestHealthzFailsClosedWhenStoreUnavailable(t *testing.T) {
	e := newEnv(t)
	require.Equal(t, 200, e.do("GET", "/healthz", nil, nil).Status)
	e.db.Pool.Close()
	r := e.do("GET", "/healthz", nil, nil)
	require.Equal(t, 503, r.Status)
	require.Equal(t, "SERVICE_UNAVAILABLE", r.code())
	// a protected route also fails closed instead of defaulting to open
	r = e.do("GET", "/v1/dashboard", nil, bearer("x"))
	require.NotEqual(t, 200, r.Status)
	_ = context.Background
}
