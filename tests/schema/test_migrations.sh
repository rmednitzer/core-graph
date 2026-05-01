#!/usr/bin/env bash
# tests/schema/test_migrations.sh
# Run all schema migrations in order, then verify idempotency.
# Requires PGHOST, PGPORT, PGUSER, PGPASSWORD, PGDATABASE to be set.

set -euo pipefail

MIGRATIONS_DIR="schema/migrations"

apply_or_dump() {
  # Apply one migration. On failure, print the file content with line numbers
  # so the CI log makes the failing line obvious without needing artifacts.
  local file="$1"
  if ! psql -v ON_ERROR_STOP=1 --echo-errors -f "$file"; then
    echo "==> Migration FAILED: $(basename "$file")" >&2
    echo "==> File content (line-numbered):" >&2
    nl -ba "$file" >&2
    exit 3
  fi
}

echo "==> Running migrations from ${MIGRATIONS_DIR}"

mapfile -t files < <(ls "${MIGRATIONS_DIR}"/*.sql 2>/dev/null | sort)

if [ "${#files[@]}" -eq 0 ]; then
  echo "ERROR: no migration files found in ${MIGRATIONS_DIR}"
  exit 1
fi

for f in "${files[@]}"; do
  echo "  -> Applying $(basename "$f") (first pass)"
  apply_or_dump "$f"
done

echo "==> Idempotency check: running all migrations a second time"

for f in "${files[@]}"; do
  echo "  -> Applying $(basename "$f") (idempotency check)"
  apply_or_dump "$f"
done

echo "==> Verifying expected extensions"

required_extensions=(age vector pgaudit pg_cron)

for ext in "${required_extensions[@]}"; do
  result=$(psql -tAc "SELECT extname FROM pg_extension WHERE extname = '${ext}';")
  if [ "${result}" != "${ext}" ]; then
    echo "ERROR: extension '${ext}' is not installed"
    exit 1
  fi
  echo "  OK: ${ext}"
done

echo "==> All migrations passed"
