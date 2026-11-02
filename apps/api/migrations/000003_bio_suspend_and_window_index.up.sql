-- Contract v1.1 / erd.md: device_keys.bio_suspended_at (D-19) and the transactions (user_id, created_at) index (SEC-069).
ALTER TABLE device_keys ADD COLUMN bio_suspended_at timestamptz;
CREATE INDEX transactions_user_created_idx ON transactions(user_id, created_at);
