# PostgreSQL major version upgrade procedure

Apache AGE uses `reg*` column types in its internal catalog tables which
block `pg_upgrade`. A full dump/restore is required for major version
upgrades.

## Pre-upgrade checklist

- [ ] Verify backup integrity (`pg_dump` completes without errors)
- [ ] Run `make verify-chain` — audit hash chain must be intact
- [ ] Run `make verify-merkle` — Merkle roots must be valid
- [ ] Confirm target PostgreSQL version supports:
  - Apache AGE (check AGE release notes for version compatibility)
  - pgvector (HNSW index support requires pgvector >= 0.5.0)
  - pg_cron (check pg_cron compatibility matrix)
  - pgaudit (check pgaudit release matrix)
- [ ] Test the upgrade on a staging environment first
- [ ] Notify downstream consumers of planned downtime
- [ ] Ensure MinIO WORM evidence store is accessible for post-upgrade
  verification

## Procedure

### 1. Stop writes

```bash
# Stop graph writer and ingest workers
make graph-writer-stop  # or scale deployment to 0
# Drain NATS consumers
nats consumer pause DLQ dlq_processor
```

### 2. Final backup

```bash
pg_dump -Fc -d core_graph -f core_graph_pre_upgrade.dump
# Verify the dump
pg_restore --list core_graph_pre_upgrade.dump | head -20
```

### 3. Dump schema and data separately

AGE internal tables require special handling:

```bash
# Schema only (includes AGE graph definitions)
pg_dump -s -d core_graph -f schema_only.sql

# Data only (excludes AGE internal tables, dumped separately)
pg_dump -a --exclude-table='core_graph.*' -d core_graph -f data_only.sql

# AGE graph data via Cypher EXPORT or COPY
psql -d core_graph -c "COPY (
    SELECT * FROM ag_catalog.cypher('core_graph', \$\$
        MATCH (v) RETURN properties(v)
    \$\$) AS (props agtype)
) TO '/tmp/vertices.csv' CSV"
```

### 4. Install new PostgreSQL version

```bash
# Install target version (e.g., PostgreSQL 17)
# Install extensions in the new cluster
CREATE EXTENSION IF NOT EXISTS age;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pgaudit;
CREATE EXTENSION IF NOT EXISTS pg_cron;
```

### 5. Restore

```bash
# Full restore from custom format dump
pg_restore -d core_graph core_graph_pre_upgrade.dump

# Or restore schema then data:
psql -d core_graph -f schema_only.sql
psql -d core_graph -f data_only.sql
```

### 6. Run migrations

```bash
make migrate
```

This ensures any new migrations for the target PostgreSQL version are
applied.

## Post-upgrade verification

### Schema validation

```bash
python scripts/validate.py
```

### Hash chain integrity

```bash
make verify-chain
make verify-merkle
```

### Query template smoke test

```bash
pytest -m "not integration" -v
```

### Integration test (if Docker stack available)

```bash
make integration-test
```

### Extension verification

```sql
SELECT extname, extversion FROM pg_extension
WHERE extname IN ('age', 'vector', 'pgcrypto', 'pgaudit', 'pg_cron');
```

## Estimated downtime

Downtime depends on database size:

| Database size | Dump time | Restore time | Total (estimate) |
|---------------|-----------|--------------|------------------|
| < 1 GB        | ~1 min    | ~2 min       | 10 min           |
| 1-10 GB       | ~5 min    | ~15 min      | 30 min           |
| 10-50 GB      | ~20 min   | ~60 min      | 2 hours          |
| 50-100 GB     | ~45 min   | ~2 hours     | 4 hours          |

These are rough estimates. Actual times depend on I/O performance,
number of indexes (especially HNSW), and AGE graph complexity.

## Rollback

If the upgrade fails:

1. Stop the new PostgreSQL instance.
2. Start the old PostgreSQL instance from the pre-upgrade data directory.
3. Verify with `make verify-chain`.

The pre-upgrade dump file (`core_graph_pre_upgrade.dump`) must be
retained until the upgrade is verified successful.
