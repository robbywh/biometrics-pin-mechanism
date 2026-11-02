-- name: InsertTransaction :one
INSERT INTO transactions (id, user_id, session_id, device_id, step_up_token_hash, tx_nonce, tx_hash, asset, network, destination, amount, fee, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::text::numeric, $12::text::numeric, 'accepted_mock', $13)
RETURNING id;

-- name: InsertAudit :exec
INSERT INTO audit_events (ts, user_id, device_id, event_type, result, ip, user_agent, request_id, metadata, prev_hash)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10);

-- name: LastAudit :one
SELECT id, ts, user_id, device_id, event_type, result, host(ip) AS ip, user_agent, request_id, metadata, prev_hash
FROM audit_events ORDER BY id DESC LIMIT 1;

-- name: ListAuditSince :many
SELECT id, ts, user_id, device_id, event_type, result, host(ip) AS ip, user_agent, request_id, metadata, prev_hash
FROM audit_events WHERE id > $1 ORDER BY id LIMIT $2;

-- name: AuditChainLock :exec
SELECT pg_advisory_xact_lock(739100);

-- name: PurgeAudit :execrows
DELETE FROM audit_events WHERE ts < $1;
