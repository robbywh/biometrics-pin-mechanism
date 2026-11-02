package store_test

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/cryptoapp/api/internal/store"
	"github.com/cryptoapp/api/internal/store/db"
	"github.com/cryptoapp/api/internal/testutil/pg"
)

func TestMain(m *testing.M) {
	code := m.Run()
	pg.Terminate()
	os.Exit(code)
}

var t0 = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func seed(t *testing.T, s *store.Store, name string) uuid.UUID {
	id, err := s.Q.SeedUser(context.Background(), db.SeedUserParams{ID: uuid.New(), Username: name, CreatedAt: t0})
	require.NoError(t, err)
	return id
}

// Expected tables/columns derived from docs/features/biometric-pin-login/diagrams/erd/.
var erd = map[string][]string{
	"users":               {"id", "username", "pin_hash", "pepper_version", "pin_set_at", "fail_count", "locked_until", "hard_locked", "failures_since_unlock", "last_failure_at", "cooling_off_until", "created_at"},
	"devices":             {"id", "user_id", "platform", "name", "risk", "created_at", "last_seen_at", "cooling_off_until", "revoked_at"},
	"device_pin_failures": {"device_id", "window_started_at", "fail_count", "blocked_until"},
	"device_keys":         {"id", "device_id", "spki", "fingerprint", "attestation_type", "key_security_level", "bio_fail_count", "cooling_off_until", "created_at", "revoked_at", "revoke_reason", "bio_suspended_at"},
	"challenges":          {"id", "user_id", "device_id", "session_id", "purpose", "action", "nonce", "bound_hash", "required_proof", "expires_at", "consumed_at", "created_at"},
	"sessions":            {"id", "user_id", "device_id", "family_id", "parent_id", "refresh_hash", "amr", "created_at", "last_unlock_at", "last_seen_at", "expires_at", "used_at", "revoked_at", "revoke_reason"},
	"bootstrap_tokens":    {"token_hash", "user_id", "device_id", "scope", "expires_at", "used_at", "created_at"},
	"step_up_tokens":      {"token_hash", "user_id", "session_id", "device_id", "action", "bound_hash", "proof", "expires_at", "consumed_at"},
	"idempotency_keys":    {"user_id", "endpoint", "key_hash", "request_hash", "response_status", "response_body", "created_at", "expires_at"},
	"audit_events":        {"id", "ts", "user_id", "device_id", "event_type", "result", "ip", "user_agent", "request_id", "metadata", "prev_hash"},
	"transactions":        {"id", "user_id", "session_id", "device_id", "step_up_token_hash", "tx_nonce", "tx_hash", "asset", "network", "destination", "amount", "fee", "status", "created_at"},
	"balances":            {"user_id", "asset", "amount"},
}

func TestSchemaMatchesERD(t *testing.T) {
	d := pg.New(t)
	rows, err := d.Pool.Query(context.Background(), `SELECT table_name, column_name FROM information_schema.columns WHERE table_schema='public' AND table_name <> 'schema_migrations'`)
	require.NoError(t, err)
	got := map[string][]string{}
	for rows.Next() {
		var tn, cn string
		require.NoError(t, rows.Scan(&tn, &cn))
		got[tn] = append(got[tn], cn)
	}
	require.NoError(t, rows.Err())
	require.Len(t, got, len(erd))
	for tn, cols := range erd {
		require.ElementsMatch(t, cols, got[tn], tn)
	}
}

func TestReserveAttemptConcurrent50(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	uid := seed(t, s, "alice")
	var ok, locked atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.Q.ReserveAttempt(context.Background(), db.ReserveAttemptParams{ID: uid, Now: t0, Schedule: []int32{30, 60, 300, 900, 3600}})
			switch {
			case err == nil:
				ok.Add(1)
			case store.NotFound(err):
				locked.Add(1)
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 5, ok.Load())
	require.EqualValues(t, 45, locked.Load())
	st, err := s.Q.GetLockState(context.Background(), uid)
	require.NoError(t, err)
	require.EqualValues(t, 5, st.FailCount)
	require.NotNil(t, st.LockedUntil)
	require.Equal(t, t0.Add(30*time.Second), st.LockedUntil.UTC())
	require.False(t, st.HardLocked)
}

func TestReserveScheduleAndHardLock(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	uid := seed(t, s, "alice")
	sched := []int32{30, 60, 300, 900, 3600}
	now := t0
	wantLock := []int32{0, 0, 0, 0, 30, 60, 300, 900, 3600}
	for i := 1; i <= 9; i++ {
		r, err := s.Q.ReserveAttempt(context.Background(), db.ReserveAttemptParams{ID: uid, Now: now, Schedule: sched})
		require.NoError(t, err, i)
		require.EqualValues(t, i, r.FailCount)
		if wantLock[i-1] == 0 {
			require.Nil(t, r.LockedUntil)
		} else {
			require.Equal(t, now.Add(time.Duration(wantLock[i-1])*time.Second), r.LockedUntil.UTC())
			now = r.LockedUntil.UTC() // lock expires exactly now: allowed again
		}
	}
	r, err := s.Q.ReserveAttempt(context.Background(), db.ReserveAttemptParams{ID: uid, Now: now, Schedule: sched})
	require.NoError(t, err)
	require.True(t, r.HardLocked)
	require.Nil(t, r.LockedUntil)
	_, err = s.Q.ReserveAttempt(context.Background(), db.ReserveAttemptParams{ID: uid, Now: now.Add(100 * 24 * time.Hour), Schedule: sched})
	require.True(t, store.NotFound(err), "hard lock never expires")
	// correct PIN path (f=10 reserved then success) clears even the hard lock set by the reservation
	cf, err := s.Q.ClearFailures(context.Background(), db.ClearFailuresParams{ID: uid, ClearNotice: true})
	require.NoError(t, err)
	require.EqualValues(t, 10, cf.PrevFailCount)
	st, _ := s.Q.GetLockState(context.Background(), uid)
	require.False(t, st.HardLocked)
	require.EqualValues(t, 0, st.FailCount)
}

func TestConsumeChallengeConcurrent50(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	ctx := context.Background()
	uid := seed(t, s, "alice")
	dev, err := s.Q.InsertDevice(ctx, db.InsertDeviceParams{ID: uuid.New(), UserID: uid, Platform: "ios", Name: "d", CreatedAt: t0})
	require.NoError(t, err)
	cid := uuid.New()
	_, err = s.Q.InsertChallenge(ctx, db.InsertChallengeParams{ID: cid, UserID: uid, DeviceID: dev.ID, Purpose: "login", Nonce: make([]byte, 32), ExpiresAt: t0.Add(time.Minute), CreatedAt: t0})
	require.NoError(t, err)
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Q.ConsumeChallenge(ctx, db.ConsumeChallengeParams{ID: cid, DeviceID: dev.ID, Purpose: "login", ConsumedAt: ptr(t0)}); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
	// wrong device / purpose / expired cannot consume
	c2 := uuid.New()
	_, err = s.Q.InsertChallenge(ctx, db.InsertChallengeParams{ID: c2, UserID: uid, DeviceID: dev.ID, Purpose: "enroll", Nonce: make([]byte, 32), ExpiresAt: t0.Add(time.Minute), CreatedAt: t0})
	require.NoError(t, err)
	_, err = s.Q.ConsumeChallenge(ctx, db.ConsumeChallengeParams{ID: c2, DeviceID: uuid.New(), Purpose: "enroll", ConsumedAt: ptr(t0)})
	require.True(t, store.NotFound(err))
	_, err = s.Q.ConsumeChallenge(ctx, db.ConsumeChallengeParams{ID: c2, DeviceID: dev.ID, Purpose: "login", ConsumedAt: ptr(t0)})
	require.True(t, store.NotFound(err))
	_, err = s.Q.ConsumeChallenge(ctx, db.ConsumeChallengeParams{ID: c2, DeviceID: dev.ID, Purpose: "enroll", ConsumedAt: ptr(t0.Add(2 * time.Minute))})
	require.True(t, store.NotFound(err), "expired")
}

func ptr[T any](v T) *T { return &v }

func TestRefreshRotationCAS(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	ctx := context.Background()
	uid := seed(t, s, "alice")
	dev, _ := s.Q.InsertDevice(ctx, db.InsertDeviceParams{ID: uuid.New(), UserID: uid, Platform: "ios", Name: "d", CreatedAt: t0})
	h := []byte("0123456789abcdef0123456789abcdef")
	require.NoError(t, s.Q.InsertSession(ctx, db.InsertSessionParams{ID: uuid.New(), UserID: uid, DeviceID: dev.ID, FamilyID: uuid.New(), RefreshHash: h, Amr: "pin", CreatedAt: t0, LastUnlockAt: t0, ExpiresAt: t0.Add(time.Hour)}))
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Q.MarkSessionUsed(ctx, db.MarkSessionUsedParams{RefreshHash: h, UsedAt: ptr(t0)}); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, wins.Load())
}

func TestAPIRoleLeastPrivilege(t *testing.T) {
	d := pg.New(t)
	ctx := context.Background()
	s := store.New(d.Pool)
	require.NoError(t, s.Q.InsertAudit(ctx, db.InsertAuditParams{Ts: t0, EventType: "PIN_SET", Result: "ok"}))
	for _, q := range []string{
		"UPDATE audit_events SET result='x'", "DELETE FROM audit_events", "TRUNCATE audit_events",
		"CREATE TABLE evil(id int)", "DROP TABLE users", "ALTER TABLE users ADD COLUMN x int",
	} {
		_, err := d.Pool.Exec(ctx, q)
		require.Error(t, err, q)
	}
	// the owner can (sanity: the test is meaningful)
	owner, err := pgx.Connect(ctx, d.OwnerDSN)
	require.NoError(t, err)
	defer owner.Close(ctx)
	_, err = owner.Exec(ctx, "UPDATE audit_events SET result='x'")
	require.NoError(t, err)
}

func TestRestartKeepsState(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	ctx := context.Background()
	uid := seed(t, s, "alice")
	for i := 0; i < 5; i++ {
		_, err := s.Q.ReserveAttempt(ctx, db.ReserveAttemptParams{ID: uid, Now: t0, Schedule: []int32{30, 60, 300, 900, 3600}})
		require.NoError(t, err)
	}
	d.Pool.Close() // "process restart"
	p2, err := pgxpool.New(ctx, d.DSN)
	require.NoError(t, err)
	defer p2.Close()
	st, err := store.New(p2).Q.GetLockState(ctx, uid)
	require.NoError(t, err)
	require.EqualValues(t, 5, st.FailCount)
	require.NotNil(t, st.LockedUntil)
}

func TestSQLInjectionPayloadIsInert(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	ctx := context.Background()
	seed(t, s, "alice")
	for _, p := range []string{"alice' OR '1'='1", "'; DROP TABLE users; --", "alice\x00", "\" OR \"\"=\""} {
		_, err := s.Q.GetUserByUsername(ctx, p)
		require.Error(t, err) // not found (or invalid text for NUL), never a match
	}
	u, err := s.Q.GetUserByUsername(ctx, "alice")
	require.NoError(t, err)
	require.Equal(t, "alice", u.Username)
}

func TestInTxRollsBack(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	ctx := context.Background()
	err := s.InTx(ctx, func(q *db.Queries) error {
		_, err := q.SeedUser(ctx, db.SeedUserParams{ID: uuid.New(), Username: "ghost", CreatedAt: t0})
		require.NoError(t, err)
		return context.Canceled
	})
	require.Error(t, err)
	_, err = s.Q.GetUserByUsername(ctx, "ghost")
	require.True(t, store.NotFound(err))
}

// No string-built SQL anywhere in non-test, non-generated code (sqlc only).
func TestNoStringBuiltSQL(t *testing.T) {
	re := regexp.MustCompile(`(?i)(Sprintf|Sprint|\+)\s*\(?\s*"(select|insert|update|delete)\s`)
	root := "../.."
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
			strings.Contains(p, "/store/db/") || strings.Contains(p, "/testutil/") || strings.Contains(p, "/apigen/") {
			return nil
		}
		b, _ := os.ReadFile(p)
		require.False(t, re.Match(b), p)
		return nil
	})
}

func TestRuntimeRoleCannotModifyAudit(t *testing.T) {
	d := pg.New(t)
	can, err := store.New(d.Pool).Q.CanModifyAudit(context.Background())
	require.NoError(t, err)
	require.False(t, can)
}

func TestSumTxByAssetEmpty(t *testing.T) {
	d := pg.New(t)
	s := store.New(d.Pool)
	uid := seed(t, s, "alice")
	rows, err := s.Q.SumTxByAsset(context.Background(), db.SumTxByAssetParams{UserID: uid, CreatedAt: t0.Add(-time.Hour), Proof: "bio"})
	require.NoError(t, err)
	require.Empty(t, rows)
}
