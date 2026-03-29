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

echo "==> Schema initialization complete"
