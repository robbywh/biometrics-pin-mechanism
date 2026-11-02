-- Schema per docs/features/biometric-pin-login/erd.md (authoritative). Time comparisons use app-supplied clock values.
CREATE TABLE users (
    id                    uuid PRIMARY KEY,
    username              text NOT NULL UNIQUE,
    pin_hash              text,
    pepper_version        smallint,
    pin_set_at            timestamptz,
    fail_count            smallint NOT NULL DEFAULT 0 CHECK (fail_count >= 0),
    locked_until          timestamptz,
    hard_locked           boolean NOT NULL DEFAULT false,
    failures_since_unlock integer NOT NULL DEFAULT 0 CHECK (failures_since_unlock >= 0),
    last_failure_at       timestamptz,
    cooling_off_until     timestamptz,
    created_at            timestamptz NOT NULL
);

CREATE TABLE devices (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL REFERENCES users(id),
    platform          text NOT NULL CHECK (platform IN ('ios','android')),
    name              text NOT NULL,
    risk              jsonb,
    created_at        timestamptz NOT NULL,
    last_seen_at      timestamptz NOT NULL,
    cooling_off_until timestamptz,
    revoked_at        timestamptz
);
CREATE INDEX devices_user_idx ON devices(user_id);

CREATE TABLE device_pin_failures (
    device_id         uuid PRIMARY KEY REFERENCES devices(id),
    window_started_at timestamptz NOT NULL,
    fail_count        smallint NOT NULL DEFAULT 0,
    blocked_until     timestamptz
);

CREATE TABLE device_keys (
    id                uuid PRIMARY KEY,
    device_id         uuid NOT NULL REFERENCES devices(id),
    spki              bytea NOT NULL,
    fingerprint       bytea NOT NULL,
    attestation_type  text NOT NULL CHECK (attestation_type IN ('none','android_key','app_attest','play_integrity')),
    key_security_level text NOT NULL,
    bio_fail_count    smallint NOT NULL DEFAULT 0,
    cooling_off_until timestamptz,
    created_at        timestamptz NOT NULL,
    revoked_at        timestamptz,
    revoke_reason     text
);
CREATE UNIQUE INDEX device_keys_one_active ON device_keys(device_id) WHERE revoked_at IS NULL;

CREATE TABLE sessions (
    id             uuid PRIMARY KEY,
    user_id        uuid NOT NULL REFERENCES users(id),
    device_id      uuid NOT NULL REFERENCES devices(id),
    family_id      uuid NOT NULL,
    parent_id      uuid REFERENCES sessions(id),
    refresh_hash   bytea NOT NULL UNIQUE,
    amr            text NOT NULL CHECK (amr IN ('pin','bio')),
    created_at     timestamptz NOT NULL,
    last_unlock_at timestamptz NOT NULL,
    last_seen_at   timestamptz NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    revoked_at     timestamptz,
    revoke_reason  text
);
CREATE INDEX sessions_family_idx ON sessions(family_id);
CREATE INDEX sessions_device_idx ON sessions(device_id);
CREATE INDEX sessions_user_idx ON sessions(user_id);

CREATE TABLE challenges (
    id             uuid PRIMARY KEY,
    user_id        uuid NOT NULL REFERENCES users(id),
    device_id      uuid NOT NULL REFERENCES devices(id),
    session_id     uuid REFERENCES sessions(id),
    purpose        text NOT NULL CHECK (purpose IN ('login','enroll','stepup')),
    action         text CHECK (action IN ('transaction','enable_biometric','revoke_device')),
    nonce          bytea NOT NULL,
    bound_hash     bytea,
    required_proof text CHECK (required_proof IN ('bio','pin','either')),
    expires_at     timestamptz NOT NULL,
    consumed_at    timestamptz,
    created_at     timestamptz NOT NULL
);
CREATE UNIQUE INDEX challenges_one_live ON challenges(device_id, purpose) WHERE consumed_at IS NULL;

CREATE TABLE bootstrap_tokens (
    token_hash bytea PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users(id),
    device_id  uuid REFERENCES devices(id),
    scope      text NOT NULL CHECK (scope IN ('pin-setup','pin-verify','pin-reset')),
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL
);

CREATE TABLE step_up_tokens (
    token_hash  bytea PRIMARY KEY,
    user_id     uuid NOT NULL REFERENCES users(id),
    session_id  uuid NOT NULL REFERENCES sessions(id),
    device_id   uuid NOT NULL REFERENCES devices(id),
    action      text NOT NULL CHECK (action IN ('transaction','enable_biometric','revoke_device')),
    bound_hash  bytea NOT NULL,
    proof       text NOT NULL CHECK (proof IN ('bio','pin')),
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz
);

CREATE TABLE idempotency_keys (
    user_id         uuid NOT NULL REFERENCES users(id),
    endpoint        text NOT NULL,
    key_hash        bytea NOT NULL,
    request_hash    bytea NOT NULL,
    response_status smallint NOT NULL,
    response_body   jsonb,
    created_at      timestamptz NOT NULL,
    expires_at      timestamptz NOT NULL,
    PRIMARY KEY (user_id, endpoint, key_hash)
);

-- Deliberate deviation from erd.md: no FKs on audit_events (events may reference ids that do not exist, e.g. unknown device ids).
CREATE TABLE audit_events (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts         timestamptz NOT NULL,
    user_id    uuid,
    device_id  uuid,
    event_type text NOT NULL,
    result     text NOT NULL,
    ip         inet,
    user_agent text,
    request_id text,
    metadata   jsonb,
    prev_hash  bytea
);
CREATE INDEX audit_events_ts_idx ON audit_events(ts);

CREATE TABLE transactions (
    id                  uuid PRIMARY KEY,
    user_id             uuid NOT NULL REFERENCES users(id),
    session_id          uuid NOT NULL REFERENCES sessions(id),
    device_id           uuid NOT NULL REFERENCES devices(id),
    step_up_token_hash  bytea NOT NULL UNIQUE REFERENCES step_up_tokens(token_hash),
    tx_nonce            uuid NOT NULL,
    tx_hash             bytea NOT NULL,
    asset               text NOT NULL,
    network             text NOT NULL,
    destination         text NOT NULL,
    amount              numeric(38,18) NOT NULL CHECK (amount > 0),
    fee                 numeric(38,18) NOT NULL CHECK (fee >= 0),
    status              text NOT NULL,
    created_at          timestamptz NOT NULL,
    UNIQUE (user_id, tx_nonce)
);

CREATE TABLE balances (
    user_id uuid NOT NULL REFERENCES users(id),
    asset   text NOT NULL,
    amount  numeric(38,18) NOT NULL CHECK (amount >= 0),
    PRIMARY KEY (user_id, asset)
);
