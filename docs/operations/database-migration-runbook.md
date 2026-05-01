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

## Migration 011 — vector dimension change (destructive opt-in)

Migration `011_vector_dimensions.sql` changes the embeddings column dimension.
If the table contains rows the migration **refuses** unless the operator
explicitly authorises a truncate via the `app.allow_embedding_truncate` GUC.

### Required precheck

1. Inventory current embedding rows: `select count(*), model from embeddings group by model`.
2. Confirm an embedding regeneration job is queued (re-embedding is mandatory after
   a dimension change — vectors at the old dimension are lost).
3. Confirm the change-control ticket includes the truncate authorisation.

### Authorising the truncate

Run inside a single transaction so the GUC scope is bounded:

```sql
begin;
set local app.allow_embedding_truncate = 'true';
\i schema/migrations/011_vector_dimensions.sql
commit;
```

If the GUC is not set the migration raises:

```
ERROR: Refusing to truncate <N> embedding(s) at dimension <X> ...
```

On a fresh database (zero rows) the migration is a no-op truncate path and
applies without any flag.

### Rollback

There is no in-place rollback for a dimension change. Restore from physical
backup and re-run the embedding regeneration job at the original dimension.

## Evidence to retain

- Migration execution logs.
- `pg_stat_activity`/lock snapshots during rollout.
- Pre/post schema metadata (`\d+ temporal_facts`).
- Backup artifact IDs and checksum attestations.
