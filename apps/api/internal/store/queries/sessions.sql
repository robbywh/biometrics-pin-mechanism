-- name: InsertSession :exec
INSERT INTO sessions (id, user_id, device_id, family_id, parent_id, refresh_hash, amr, created_at, last_unlock_at, last_seen_at, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $8, $10);

-- name: GetSessionByRefreshHash :one
SELECT * FROM sessions WHERE refresh_hash = $1;

-- name: TouchSession :one
-- Access-token validation + idle-window bookkeeping in ONE statement. Zero rows => revoked/expired/device revoked.
UPDATE sessions s SET last_seen_at = $2
WHERE s.id = $1 AND s.user_id = $3 AND s.revoked_at IS NULL AND s.expires_at > $2
  AND EXISTS (SELECT 1 FROM devices d WHERE d.id = s.device_id AND d.revoked_at IS NULL)
RETURNING s.*;

-- name: GetSessionRaw :one
SELECT * FROM sessions WHERE id = $1 AND user_id = $2;

-- name: MarkSessionUsed :one
UPDATE sessions SET used_at = $2 WHERE refresh_hash = $1 AND used_at IS NULL AND revoked_at IS NULL RETURNING *;

-- name: RevokeFamily :exec
UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE family_id = $1 AND revoked_at IS NULL;

-- name: RevokeDeviceSessions :exec
UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE device_id = $1 AND revoked_at IS NULL;

-- name: RevokeUserSessions :exec
UPDATE sessions SET revoked_at = $2, revoke_reason = $3 WHERE user_id = $1 AND revoked_at IS NULL;

-- name: SetSessionUnlock :exec
UPDATE sessions SET last_unlock_at = $2, last_seen_at = $2 WHERE id = $1;

-- name: CountLiveFamilies :one
SELECT count(DISTINCT family_id) FROM sessions WHERE device_id = $1 AND revoked_at IS NULL;
