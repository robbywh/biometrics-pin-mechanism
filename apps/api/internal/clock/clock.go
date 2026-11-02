// Package clock provides an injectable time source. All security-relevant time comparisons (locks, TTLs, windows)
// use a Clock value that is passed to SQL as a parameter, never now() inside the database.
package clock

import (
	"sync"
	"time"
)

type Clock interface{ Now() time.Time }

// System is the production clock (UTC, truncated to Postgres microsecond precision).
type System struct{}

func (System) Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }

// Fake is a manually advanced clock for tests.
type Fake struct {
	mu sync.Mutex
	t  time.Time
}

func NewFake(t time.Time) *Fake { return &Fake{t: t.UTC().Truncate(time.Microsecond)} }

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.t
}

func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	f.t = f.t.Add(d)
	f.mu.Unlock()
}
