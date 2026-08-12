#!/bin/bash
# Run all schema migrations and seed data on first PostgreSQL startup.
set -euo pipefail

echo "==> Running core-graph schema migrations"

for f in /docker-entrypoint-initdb.d/migrations/*.sql; do
    echo "  -> Applying $(basename "$f")"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
done

echo "==> Running seed data"

for f in /docker-entrypoint-initdb.d/seed/*.sql; do
    [ -f "$f" ] || continue
    [[ "$(basename "$f")" == ".gitkeep" ]] && continue
    echo "  -> Loading $(basename "$f")"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$f"
done

# Migration 038 creates cg_app (LOGIN NOSUPERUSER NOBYPASSRLS) deliberately
# without a password: a migration is the wrong place for a credential, and a
# role shipped with a default one is worse than a role that cannot yet connect.
# Setting the password is what activates the role, and it belongs to whoever
# runs the deployment. This is that step for the local stack.
#
# Dev-only. A real deployment sets it from its own secret store; nothing here
# is a credential anyone should reuse.
#
# The SQL arrives on stdin rather than through -c. psql does NOT expand
# variables in a -c string -- it is sent to the server verbatim, so :'pw'
# reaches the parser as literal text and fails with `syntax error at or near
# ":"`. Under `set -e` that exits the entrypoint and the container dies before
# the database is ever reachable. Verified against psql 16.
#
# :'pw' rather than the value inline is what quotes and escapes the password
# safely, which matters here more than anywhere: this is the one place a real
# deployment's secret is interpolated into SQL.
if [ -n "${CG_APP_PASSWORD:-}" ]; then
    echo "==> Activating the cg_app application role"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
        -v pw="$CG_APP_PASSWORD" <<'SQL'
alter role cg_app login password :'pw';
SQL
else
    echo "==> CG_APP_PASSWORD unset; cg_app stays inactive and the API will" \
         "fall back to $POSTGRES_USER, which bypasses RLS"
fi

echo "==> Schema initialization complete"
