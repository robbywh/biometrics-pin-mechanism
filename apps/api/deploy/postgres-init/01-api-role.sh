#!/bin/sh
# Creates the least-privilege role used by the API at runtime (no DDL, INSERT-only on audit_events;
# grants are applied by the migrations). Runs only on first initialisation of the volume.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE "$API_DB_USER" LOGIN PASSWORD '$API_DB_PASSWORD' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT CONNECT ON DATABASE "$POSTGRES_DB" TO "$API_DB_USER";
SQL
