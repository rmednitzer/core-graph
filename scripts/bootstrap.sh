#!/usr/bin/env bash
# scripts/bootstrap.sh — First-run setup for core-graph local development.
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# -- Step 1: Check prerequisites -----------------------------------------------

info "Checking prerequisites..."

missing=0

for cmd in docker psql python3; do
    if ! command -v "$cmd" &>/dev/null; then
        error "Required command not found: $cmd"
        missing=1
    fi
done

# Check docker compose (v2 plugin)
if ! docker compose version &>/dev/null; then
    error "docker compose (v2 plugin) not found"
    missing=1
fi

# Check Python version (3.12+)
py_version=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
py_major=$(echo "$py_version" | cut -d. -f1)
py_minor=$(echo "$py_version" | cut -d. -f2)
if [ "$py_major" -lt 3 ] || { [ "$py_major" -eq 3 ] && [ "$py_minor" -lt 12 ]; }; then
    error "Python 3.12+ required, found $py_version"
    missing=1
fi

if [ "$missing" -ne 0 ]; then
    error "Missing prerequisites. Please install them and try again."
    exit 1
fi

info "All prerequisites found."

# -- Step 2: Start Docker Compose stack ----------------------------------------

info "Starting local development stack..."
docker compose -f deploy/docker/docker-compose.yml up -d --build

# -- Step 3: Wait for PostgreSQL healthcheck -----------------------------------

info "Waiting for PostgreSQL to be ready..."
retries=30
until docker exec cg-postgres pg_isready -U cg_admin -d core_graph &>/dev/null; do
    retries=$((retries - 1))
    if [ "$retries" -le 0 ]; then
        error "PostgreSQL did not become ready in time"
        exit 1
    fi
    sleep 2
done
info "PostgreSQL is ready."

# -- Step 4: Run migrations ----------------------------------------------------

info "Running schema migrations..."
export PGHOST=localhost PGPORT=5432 PGUSER=cg_admin PGPASSWORD=cg_dev_only PGDATABASE=core_graph

for f in schema/migrations/*.sql; do
    info "  -> Applying $(basename "$f")"
    psql -v ON_ERROR_STOP=1 -f "$f"
done

# -- Step 5: Run seeds ---------------------------------------------------------

info "Loading seed data..."
for f in schema/seed/*.sql; do
    [ -f "$f" ] || continue
    [[ "$(basename "$f")" == ".gitkeep" ]] && continue
    info "  -> Loading $(basename "$f")"
    psql -v ON_ERROR_STOP=1 -f "$f"
done

# -- Step 6: Print connection info ---------------------------------------------

echo ""
info "=== core-graph local development stack is ready ==="
echo ""
echo "  PostgreSQL:  postgresql://cg_admin:cg_dev_only@localhost:5432/core_graph"
echo "  NATS:        nats://localhost:4222  (monitoring: http://localhost:8222)"
echo "  Valkey:      redis://localhost:6379"
echo ""
echo "  Quick start:"
echo "    make psql       # interactive SQL shell"
echo "    make test       # run tests"
echo "    make validate   # lint and validate"
echo ""
