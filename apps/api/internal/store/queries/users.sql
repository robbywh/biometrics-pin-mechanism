-- name: SeedUser :one
INSERT INTO users (id, username, created_at) VALUES ($1, $2, $3)
ON CONFLICT (username) DO UPDATE SET username = EXCLUDED.username
RETURNING id;

-- name: SeedBalance :exec
INSERT INTO balances (user_id, asset, amount) VALUES ($1, $2, $3)
ON CONFLICT (user_id, asset) DO NOTHING;

-- name: GetUserByID :one
SELECT * FROM users WHERE id = $1;

-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: LockUserRow :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: SetInitialPin :one
UPDATE users SET pin_hash = $2, pepper_version = $3, pin_set_at = $4
WHERE id = $1 AND pin_hash IS NULL
RETURNING id;

-- name: ReplacePin :exec
UPDATE users SET pin_hash = $2, pepper_version = $3, pin_set_at = $4 WHERE id = $1;

-- name: RehashPin :exec
UPDATE users SET pin_hash = $3, pepper_version = $4 WHERE id = $1 AND pin_hash = $2;

-- name: ReserveAttempt :one
-- Reserve-before-hash: ONE conditional statement (SEC-008). Zero rows => locked. Schedule array holds the lock seconds for failures 5..9.
UPDATE users SET
  fail_count   = fail_count + 1,
  locked_until = CASE
                   WHEN fail_count + 1 >= 10 THEN NULL
                   WHEN fail_count + 1 >= 5 THEN sqlc.arg(now)::timestamptz + make_interval(secs => (sqlc.arg(schedule)::int[])[fail_count + 1 - 4])
                   ELSE locked_until END,
  hard_locked  = (fail_count + 1 >= 10)
WHERE id = sqlc.arg(id) AND NOT hard_locked AND (locked_until IS NULL OR locked_until <= sqlc.arg(now)::timestamptz)
RETURNING fail_count, locked_until, hard_locked;

-- name: ClearFailures :one
-- Correct PIN: reset the lock state (incl. a hard lock set by the reservation itself) and return the counters as they were.
-- clear_notice also zeroes the "failed attempts since last login" notice counter (unlock responses only).
WITH old AS (SELECT id, failures_since_unlock, fail_count FROM users WHERE users.id = sqlc.arg(id) FOR UPDATE)
UPDATE users SET fail_count = 0, locked_until = NULL, hard_locked = false,
  failures_since_unlock = CASE WHEN sqlc.arg(clear_notice)::boolean THEN 0 ELSE users.failures_since_unlock END
FROM old WHERE users.id = old.id
RETURNING old.failures_since_unlock AS recent_failures, old.fail_count AS prev_fail_count;

-- name: TakeRecentFailures :one
-- Biometric unlock: report and clear the notice counter; the lock counter is NOT touched.
WITH old AS (SELECT id, failures_since_unlock FROM users WHERE users.id = $1 FOR UPDATE)
UPDATE users SET failures_since_unlock = 0 FROM old WHERE users.id = old.id
RETURNING old.failures_since_unlock AS recent_failures;

-- name: AddFailureSinceUnlock :exec
UPDATE users SET failures_since_unlock = failures_since_unlock + 1, last_failure_at = $2 WHERE id = $1;

-- name: GetLockState :one
SELECT fail_count, locked_until, hard_locked FROM users WHERE id = $1;

-- name: ResetLockStateAndCoolOff :exec
UPDATE users SET fail_count = 0, locked_until = NULL, hard_locked = false, failures_since_unlock = 0, cooling_off_until = $2
WHERE id = $1;

-- name: GetBalances :many
SELECT asset, amount::text AS amount FROM balances WHERE user_id = $1 ORDER BY asset;

-- name: DebitBalance :one
UPDATE balances SET amount = amount - $3::text::numeric
WHERE user_id = $1 AND asset = $2 AND amount >= $3::text::numeric
RETURNING amount::text AS amount;

-- name: GetBalanceForUpdate :one
SELECT amount::text AS amount FROM balances WHERE user_id = $1 AND asset = $2 FOR UPDATE;
