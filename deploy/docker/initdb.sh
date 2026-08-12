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
if [ -n "${CG_APP_PASSWORD:-}" ]; then
    echo "==> Activating the cg_app application role"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
        -v pw="$CG_APP_PASSWORD" \
        -c "alter role cg_app login password :'pw'"
else
    echo "==> CG_APP_PASSWORD unset; cg_app stays inactive and the API will" \
         "fall back to $POSTGRES_USER, which bypasses RLS"
fi

echo "==> Schema initialization complete"
