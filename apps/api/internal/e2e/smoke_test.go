package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSmokeOnboardAndDashboard(t *testing.T) {
	e := newEnv(t)
	d := e.onboard("alice", goodPIN)
	r := e.do("GET", "/v1/dashboard", nil, bearer(d.access))
	require.Equal(t, 200, r.Status, string(r.Body))
	require.Equal(t, "healthz", "healthz")
	h := e.do("GET", "/healthz", nil, nil)
	require.Equal(t, 200, h.Status)
}
