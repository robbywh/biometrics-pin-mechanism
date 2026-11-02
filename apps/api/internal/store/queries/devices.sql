-- name: InsertDevice :one
INSERT INTO devices (id, user_id, platform, name, risk, created_at, last_seen_at, cooling_off_until)
VALUES ($1, $2, $3, $4, $5, $6, $6, $7)
RETURNING *;

-- name: GetDeviceForUser :one
SELECT * FROM devices WHERE id = $1 AND user_id = $2;

-- name: GetDeviceByID :one
-- Unauthenticated biometric flows only: the device id is the lookup handle, the owner is read from the row.
SELECT * FROM devices WHERE id = $1;

-- name: ListActiveDevices :many
SELECT d.*, EXISTS (SELECT 1 FROM device_keys k WHERE k.device_id = d.id AND k.revoked_at IS NULL) AS biometric_enabled
FROM devices d WHERE d.user_id = $1 AND d.revoked_at IS NULL ORDER BY d.created_at;

-- name: CountActiveDevices :one
SELECT count(*) FROM devices WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeDevice :execrows
UPDATE devices SET revoked_at = $3 WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL;

-- name: RevokeOtherDevices :exec
UPDATE devices SET revoked_at = $3 WHERE user_id = $1 AND id <> $2 AND revoked_at IS NULL;

-- name: TouchDevice :exec
UPDATE devices SET last_seen_at = $2 WHERE id = $1;

-- name: GetDevicePinFailure :one
SELECT * FROM device_pin_failures WHERE device_id = $1;

-- name: RecordDevicePinFailure :one
INSERT INTO device_pin_failures (device_id, window_started_at, fail_count, blocked_until)
VALUES ($1, $2, 1, NULL)
ON CONFLICT (device_id) DO UPDATE SET
  window_started_at = CASE WHEN device_pin_failures.window_started_at <= sqlc.arg(window_floor)::timestamptz THEN sqlc.arg(now)::timestamptz ELSE device_pin_failures.window_started_at END,
  fail_count = CASE WHEN device_pin_failures.window_started_at <= sqlc.arg(window_floor)::timestamptz THEN 1 ELSE device_pin_failures.fail_count + 1 END,
  blocked_until = CASE
     WHEN (CASE WHEN device_pin_failures.window_started_at <= sqlc.arg(window_floor)::timestamptz THEN 1 ELSE device_pin_failures.fail_count + 1 END) >= sqlc.arg(max_fails)::int
       THEN sqlc.arg(block_until)::timestamptz
     ELSE device_pin_failures.blocked_until END
RETURNING *;

-- name: InsertDeviceKey :one
INSERT INTO device_keys (id, device_id, spki, fingerprint, attestation_type, key_security_level, cooling_off_until, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: GetActiveKey :one
SELECT * FROM device_keys WHERE device_id = $1 AND revoked_at IS NULL;

-- name: RevokeActiveKey :execrows
UPDATE device_keys SET revoked_at = $2, revoke_reason = $3 WHERE device_id = $1 AND revoked_at IS NULL;

-- name: RevokeKeysOnOtherDevices :exec
UPDATE device_keys SET revoked_at = $3, revoke_reason = $4
WHERE revoked_at IS NULL AND device_id <> $2 AND device_id IN (SELECT id FROM devices WHERE user_id = $1);

-- name: RevokeAllUserKeys :exec
UPDATE device_keys SET revoked_at = $2, revoke_reason = $3
WHERE revoked_at IS NULL AND device_id IN (SELECT id FROM devices WHERE user_id = $1);

-- name: RecordBioFailure :one
UPDATE device_keys SET bio_fail_count = bio_fail_count + 1 WHERE id = $1 AND revoked_at IS NULL RETURNING bio_fail_count;

-- name: ResetBioFailures :exec
UPDATE device_keys SET bio_fail_count = 0 WHERE id = $1 AND bio_fail_count <> 0;

-- name: UpdateDeviceRisk :exec
UPDATE devices SET risk = $3, last_seen_at = $4 WHERE id = $1 AND user_id = $2;

-- name: CountAllDevices :one
SELECT count(*) FROM devices WHERE user_id = $1;
