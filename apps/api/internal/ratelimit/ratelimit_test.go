package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/config"
)

func TestFixedWindow(t *testing.T) {
	c := clock.NewFake(time.Unix(1_700_000_000, 0))
	l := New(c)
	lim := config.Limit{N: 3, Window: time.Minute}
	for i := 0; i < 3; i++ {
		r := l.Allow("k", lim)
		require.True(t, r.Allowed)
		require.Equal(t, 2-i, r.Remaining)
	}
	r := l.Allow("k", lim)
	require.False(t, r.Allowed)
	require.Positive(t, r.RetryAfter)
	require.True(t, l.Allow("other", lim).Allowed, "keys are independent")
	c.Advance(61 * time.Second)
	require.True(t, l.Allow("k", lim).Allowed)
}

func TestBreaker(t *testing.T) {
	c := clock.NewFake(time.Unix(1_700_000_000, 0))
	l := New(c)
	lim := config.Limit{N: 2, Window: time.Minute}
	require.True(t, l.Breaker(lim, time.Minute).Allowed)
	require.True(t, l.Breaker(lim, time.Minute).Allowed)
	r := l.Breaker(lim, time.Minute)
	require.False(t, r.Allowed)
	require.Equal(t, 60, r.RetryAfter)
	c.Advance(30 * time.Second)
	require.False(t, l.Breaker(lim, time.Minute).Allowed)
	c.Advance(31 * time.Second)
	require.True(t, l.Breaker(lim, time.Minute).Allowed)
}

func TestDisabled(t *testing.T) {
	require.True(t, New(clock.System{}).Allow("x", config.Limit{}).Allowed)
}
