-- name: SupersedeChallenges :exec
UPDATE challenges SET consumed_at = $3 WHERE device_id = $1 AND purpose = $2 AND consumed_at IS NULL;

-- name: InsertChallenge :one
INSERT INTO challenges (id, user_id, device_id, session_id, purpose, action, nonce, bound_hash, required_proof, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: ConsumeChallenge :one
-- SEC-026: atomic consume on first attempt; scoped to the presenting device and purpose.
UPDATE challenges SET consumed_at = $4
WHERE id = $1 AND device_id = $2 AND purpose = $3 AND consumed_at IS NULL AND expires_at > $4
RETURNING *;

-- name: InvalidateDeviceChallenges :exec
UPDATE challenges SET consumed_at = $2 WHERE device_id = $1 AND consumed_at IS NULL;

-- name: InvalidateUserChallenges :exec
UPDATE challenges SET consumed_at = $2 WHERE user_id = $1 AND consumed_at IS NULL;

-- name: PurgeChallenges :execrows
DELETE FROM challenges WHERE created_at < $1;

-- name: ConsumeSessionChallenge :one
-- Step-up / enroll challenges are additionally bound to the user and session that requested them.
UPDATE challenges SET consumed_at = $6
WHERE id = $1 AND device_id = $2 AND purpose = $3 AND user_id = $4 AND session_id = $5 AND consumed_at IS NULL AND expires_at > $6
RETURNING *;
