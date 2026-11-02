-- name: InsertBootstrap :exec
INSERT INTO bootstrap_tokens (token_hash, user_id, scope, expires_at, created_at) VALUES ($1, $2, $3, $4, $5);

-- name: GetBootstrap :one
SELECT * FROM bootstrap_tokens WHERE token_hash = $1;

-- name: BindBootstrap :execrows
UPDATE bootstrap_tokens SET device_id = $2 WHERE token_hash = $1 AND device_id IS NULL AND used_at IS NULL AND expires_at > $3;

-- name: UseBootstrap :execrows
UPDATE bootstrap_tokens SET used_at = $2 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > $2;

-- name: InsertStepUpToken :exec
INSERT INTO step_up_tokens (token_hash, user_id, session_id, device_id, action, bound_hash, proof, expires_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8);

-- name: ConsumeStepUpToken :one
-- Atomic single use, scoped to user + session + device. Action / bound hash are compared by the caller so that a
-- mismatch still burns a token that was otherwise valid.
UPDATE step_up_tokens SET consumed_at = $5
WHERE token_hash = $1 AND user_id = $2 AND session_id = $3 AND device_id = $4 AND consumed_at IS NULL AND expires_at > $5
RETURNING action, bound_hash, proof;

-- name: GetIdempotency :one
SELECT * FROM idempotency_keys WHERE user_id = $1 AND endpoint = $2 AND key_hash = $3 AND expires_at > $4;

-- name: InsertIdempotency :one
INSERT INTO idempotency_keys (user_id, endpoint, key_hash, request_hash, response_status, response_body, created_at, expires_at)
VALUES ($1, $2, $3, $4, 0, NULL, $5, $6)
ON CONFLICT (user_id, endpoint, key_hash) DO NOTHING
RETURNING user_id;

-- name: CompleteIdempotency :exec
UPDATE idempotency_keys SET response_status = $4, response_body = $5 WHERE user_id = $1 AND endpoint = $2 AND key_hash = $3;

-- name: PurgeIdempotency :execrows
DELETE FROM idempotency_keys WHERE expires_at <= $1;

-- name: PurgeExpiredBootstrap :execrows
DELETE FROM bootstrap_tokens WHERE expires_at <= $1 AND device_id IS NULL;

-- name: DeleteIdempotency :exec
DELETE FROM idempotency_keys WHERE user_id = $1 AND endpoint = $2 AND key_hash = $3;
