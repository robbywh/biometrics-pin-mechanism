// Package ratelimit implements the in-memory fixed-window limiter of SEC-057 (decisions.md D-12). State is kept in
// process memory by design: the durable control is the per-user lockout in Postgres, these buckets only shed load.
package ratelimit

import (
	"sync"
	"time"

	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/config"
)

type Result struct {
	Allowed    bool
	Limit      int
	Remaining  int
	ResetSec   int
	RetryAfter int
}

type window struct {
	start time.Time
	n     int
}

type Limiter struct {
	clk       clock.Clock
	mu        sync.Mutex
	m         map[string]*window
	ops       int
	breakerAt time.Time // open until
	breakerW  window
}

func New(clk clock.Clock) *Limiter { return &Limiter{clk: clk, m: map[string]*window{}} }

// Allow counts one request against key under lim. A zero Limit disables the rule.
func (l *Limiter) Allow(key string, lim config.Limit) Result {
	if lim.N <= 0 {
		return Result{Allowed: true, Limit: 0, Remaining: 0}
	}
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ops++
	if l.ops%2048 == 0 {
		for k, w := range l.m {
			if now.Sub(w.start) > 2*time.Hour {
				delete(l.m, k)
			}
		}
	}
	w := l.m[key]
	if w == nil || now.Sub(w.start) >= lim.Window {
		w = &window{start: now}
		l.m[key] = w
	}
	reset := int((lim.Window - now.Sub(w.start)).Seconds() + 0.999)
	if reset < 1 {
		reset = 1
	}
	if w.n >= lim.N {
		return Result{Allowed: false, Limit: lim.N, Remaining: 0, ResetSec: reset, RetryAfter: reset}
	}
	w.n++
	return Result{Allowed: true, Limit: lim.N, Remaining: lim.N - w.n, ResetSec: reset}
}

// Breaker is the demo-login global circuit breaker: more than lim.N requests per window opens it for openFor.
func (l *Limiter) Breaker(lim config.Limit, openFor time.Duration) Result {
	if lim.N <= 0 {
		return Result{Allowed: true}
	}
	now := l.clk.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.breakerAt) {
		ra := int(l.breakerAt.Sub(now).Seconds() + 0.999)
		return Result{Allowed: false, Limit: lim.N, ResetSec: ra, RetryAfter: ra}
	}
	if now.Sub(l.breakerW.start) >= lim.Window {
		l.breakerW = window{start: now}
	}
	l.breakerW.n++
	if l.breakerW.n > lim.N {
		l.breakerAt = now.Add(openFor)
		l.breakerW = window{}
		ra := int(openFor.Seconds())
		return Result{Allowed: false, Limit: lim.N, ResetSec: ra, RetryAfter: ra}
	}
	return Result{Allowed: true, Limit: lim.N, Remaining: lim.N - l.breakerW.n}
}
