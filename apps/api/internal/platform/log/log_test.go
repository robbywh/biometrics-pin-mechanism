package log

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowlistAndRedaction(t *testing.T) {
	var b bytes.Buffer
	l := New(&b, slog.LevelDebug)
	l.Info("request", "method", "POST", "route", "/pin", "pin", "987654", "authorization", "Bearer canary-token", "body", "987654",
		"nonce", "n", "idempotency_key", "canary-idem", "request_id", "abc", slog.Group("meta", slog.String("token", "canary-token"), slog.String("fingerprint", "ok")))
	out := b.String()
	for _, c := range []string{"987654", "canary-token", "canary-idem"} {
		require.NotContains(t, out, c)
	}
	require.Contains(t, out, `"route":"/pin"`)
	require.Contains(t, out, `"request_id":"abc"`)
	require.Contains(t, out, "fingerprint")
	require.False(t, strings.Contains(out, `"pin"`))
}
