# Database Migration Runbook

## Prechecks
1. Confirm maintenance window and replication health.
2. Check for temporal overlap violations before applying migration 020:
   - Query for overlapping `valid_range` rows grouped by `(source_id,target_id,edge_label,fact_type)`.
3. Confirm application principals can supply `mutation_actor` and `mutation_reason`.

## Backup
1. Take physical backup and WAL archiving checkpoint.
2. Take logical backup of `temporal_facts`:
   - `pg_dump --table=temporal_facts --data-only`.

## Migration command
- Apply migrations in order (repo standard):
  - `tests/schema/test_migrations.sh` (or deployment migration job equivalent).

## Verification commands
1. Validate constraints/indexes exist:
   - `\d+ temporal_facts`
2. Validate delete protection:
   - execute a controlled `DELETE` in transaction and confirm trigger exception.
3. Validate insert requirements:
   - insert without `mutation_actor`/`mutation_reason` should fail.

## Rollback strategy
1. Stop writers.
2. Restore from physical backup for full rollback **or** run compensating migration that:
   - drops exclusion/unique constraints,
   - drops added NOT NULL columns/constraints (if policy permits),
   - drops delete-block trigger.
3. Replay WAL/logical delta per incident policy.

## Stop conditions
- Any constraint validation error in migration.
- Trigger creation failure.
- Elevated write latency or lock wait exceeding SLO during rollout.

## Evidence to retain
- Migration execution logs.
- `pg_stat_activity`/lock snapshots during rollout.
- Pre/post schema metadata (`\d+ temporal_facts`).
- Backup artifact IDs and checksum attestations.
