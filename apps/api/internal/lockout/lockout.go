// Package lockout is the single implementation of PIN attempt accounting shared by pin/verify, PUT /pin (old PIN)
// and step-up PIN proofs (SEC-008, SEC-010, SEC-042). The attempt is RESERVED by one conditional UPDATE before any
// hashing, so parallel guesses cannot all pass the lock check; at most 5 hash evaluations start from a fresh counter.
package lockout

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/cryptoapp/api/internal/audit"
	"github.com/cryptoapp/api/internal/clock"
	"github.com/cryptoapp/api/internal/pin"
	"github.com/cryptoapp/api/internal/platform/httpx"
	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
)

type Kind int

const (
	OK      Kind = iota // PIN correct, counters cleared
	Invalid             // PIN wrong, reservation stands
	Locked              // lock active: no hashing happened, nothing changed
)

type Result struct {
	Kind           Kind
	FailCount      int // reserved count (Invalid) or current count (Locked)
	LockedUntil    *time.Time
	Hard           bool
	RecentFailures int // OK: failures since last unlock (reported once)
	WasLocked      bool
}

type Service struct {
	St       *store.Store
	Hasher   *pin.Hasher
	Clk      clock.Clock
	Audit    *audit.Writer
	Schedule [5]int
}

func ptr[T any](v T) *T { return &v }

func (s *Service) sched() []int32 {
	out := make([]int32, 5)
	for i, v := range s.Schedule {
		out[i] = int32(v)
	}
	return out
}

// Attempt verifies pinPlain for the user. The error is pin.ErrBusy when the bounded hashing pool is saturated
// (nothing has been reserved then) or an infrastructure error.
func (s *Service) Attempt(ctx context.Context, userID uuid.UUID, pinPlain string, deviceID *uuid.UUID, clearNotice bool) (Result, error) {
	rel, err := s.Hasher.Acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer rel()

	now := s.Clk.Now()
	res, err := s.St.Q.ReserveAttempt(ctx, db.ReserveAttemptParams{ID: userID, Now: now, Schedule: s.sched()})
	if err != nil {
		if !store.NotFound(err) {
			return Result{}, err
		}
		st, err := s.St.Q.GetLockState(ctx, userID)
		if err != nil {
			return Result{}, err
		}
		return Result{Kind: Locked, FailCount: int(st.FailCount), LockedUntil: st.LockedUntil, Hard: st.HardLocked}, nil
	}
	u, err := s.St.Q.GetUserByID(ctx, userID)
	if err != nil {
		return Result{}, err
	}
	if u.PinHash == nil {
		s.Hasher.DummyLocked()
		return s.wrong(ctx, userID, deviceID, now, res.FailCount, res.LockedUntil, res.HardLocked)
	}
	ok, rehash, err := s.Hasher.VerifyLocked(pinPlain, *u.PinHash)
	if err != nil {
		return Result{}, errors.New("lockout: stored hash unusable")
	}
	if !ok {
		return s.wrong(ctx, userID, deviceID, now, res.FailCount, res.LockedUntil, res.HardLocked)
	}
	cf, err := s.St.Q.ClearFailures(ctx, db.ClearFailuresParams{ID: userID, ClearNotice: clearNotice})
	if err != nil {
		return Result{}, err
	}
	if rehash { // upgrade-on-login (pepper version / Argon2 params); compare-and-set on the old hash
		if nh, err := s.Hasher.HashLocked(pinPlain); err == nil {
			_ = s.St.Q.RehashPin(ctx, db.RehashPinParams{ID: userID, PinHash: u.PinHash, PinHash_2: &nh, PepperVersion: ptr(s.Hasher.CurrentVersion())})
		}
	}
	wasLocked := cf.PrevFailCount >= 5
	if wasLocked {
		s.Audit.Emit(ctx, audit.Event{Type: audit.PinUnlockedAfterLock, UserID: &userID, DeviceID: deviceID, Meta: map[string]any{"fail_count": int(cf.PrevFailCount)}})
	}
	return Result{Kind: OK, RecentFailures: int(cf.RecentFailures), WasLocked: wasLocked}, nil
}

func (s *Service) wrong(ctx context.Context, userID uuid.UUID, deviceID *uuid.UUID, now time.Time, f int16, until *time.Time, hard bool) (Result, error) {
	if err := s.St.Q.AddFailureSinceUnlock(ctx, db.AddFailureSinceUnlockParams{ID: userID, LastFailureAt: ptr(now)}); err != nil {
		return Result{}, err
	}
	s.Audit.Emit(ctx, audit.Event{Type: audit.PinVerifyFail, UserID: &userID, DeviceID: deviceID, Result: "fail", Meta: map[string]any{"fail_count": int(f)}})
	switch {
	case hard:
		s.Audit.Emit(ctx, audit.Event{Type: audit.PinHardLocked, UserID: &userID, DeviceID: deviceID, Result: "fail", Meta: map[string]any{"lock_type": "hard"}})
	case f == 5:
		s.Audit.Emit(ctx, audit.Event{Type: audit.PinLocked, UserID: &userID, DeviceID: deviceID, Result: "fail", Meta: map[string]any{"lock_type": "soft", "fail_count": int(f)}})
	}
	return Result{Kind: Invalid, FailCount: int(f), LockedUntil: until, Hard: hard}, nil
}

// Error maps a non-OK result to the contract error (D-06): failures 1-4 -> 401 PIN_INVALID with attemptsRemaining;
// failure 5 and later -> 423 PIN_LOCKED soft with retryAfter and attemptsUntilHardLock; failure 10 -> hard lock.
func Error(r Result, now time.Time) *httpx.Error {
	switch {
	case r.Hard || r.FailCount >= 10:
		e := httpx.New(423, "PIN_LOCKED")
		e.Message = "Reset required."
		e.LockType = "hard"
		return e
	case r.Kind == Invalid && r.FailCount < 5:
		e := httpx.New(401, "PIN_INVALID")
		e.AttemptsRemaining = httpx.Ptr(5 - r.FailCount)
		return e
	default:
		e := httpx.New(423, "PIN_LOCKED")
		e.LockType = "soft"
		ra := 1
		if r.LockedUntil != nil {
			if d := int(r.LockedUntil.Sub(now).Seconds() + 0.999); d > ra {
				ra = d
			}
		}
		e.RetryAfter = &ra
		e.AttemptsUntilHardLock = httpx.Ptr(10 - r.FailCount)
		return e
	}
}
