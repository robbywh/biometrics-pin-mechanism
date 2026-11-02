package lockout

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// D-06 table: failures 1-4 => 401 PIN_INVALID; 5-9 => 423 soft; 10 => 423 hard.
func TestErrorMappingTable(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sched := []int{30, 60, 300, 900, 3600}
	for f := 1; f <= 10; f++ {
		var until *time.Time
		if f >= 5 && f < 10 {
			u := now.Add(time.Duration(sched[f-5]) * time.Second)
			until = &u
		}
		e := Error(Result{Kind: Invalid, FailCount: f, LockedUntil: until, Hard: f >= 10}, now)
		switch {
		case f < 5:
			require.Equal(t, 401, e.Status)
			require.Equal(t, "PIN_INVALID", e.Code)
			require.Equal(t, 5-f, *e.AttemptsRemaining)
			require.Nil(t, e.RetryAfter)
		case f < 10:
			require.Equal(t, 423, e.Status)
			require.Equal(t, "PIN_LOCKED", e.Code)
			require.Equal(t, "soft", e.LockType)
			require.Equal(t, sched[f-5], *e.RetryAfter)
			require.Equal(t, 10-f, *e.AttemptsUntilHardLock)
			require.Nil(t, e.AttemptsRemaining)
		default:
			require.Equal(t, 423, e.Status)
			require.Equal(t, "hard", e.LockType)
			require.Nil(t, e.RetryAfter)
		}
	}
	// refused while locked (no evaluation): retryAfter is the time left, never below 1 s
	u := now.Add(400 * time.Millisecond)
	e := Error(Result{Kind: Locked, FailCount: 5, LockedUntil: &u}, now)
	require.Equal(t, 1, *e.RetryAfter)
	e = Error(Result{Kind: Locked, FailCount: 10, Hard: true}, now)
	require.Equal(t, "hard", e.LockType)
}
