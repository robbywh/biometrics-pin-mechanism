-- Least privilege for the runtime role. The role itself is created out of band (docker init script / test helper).
-- No DDL; audit_events is INSERT (+SELECT for the optional hash chain) only: no UPDATE, no DELETE.
DO $$
DECLARE r text := 'cryptoapp_api';
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
    EXECUTE format('GRANT USAGE ON SCHEMA public TO %I', r);
    EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON users, devices, device_pin_failures, device_keys, sessions, challenges, bootstrap_tokens, step_up_tokens, idempotency_keys, transactions, balances TO %I', r);
    EXECUTE format('GRANT SELECT, INSERT ON audit_events TO %I', r);
    EXECUTE format('GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO %I', r);
  END IF;
END $$;
