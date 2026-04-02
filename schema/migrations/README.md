# Schema migrations

Numbered SQL files that evolve the PostgreSQL schema. No ORM — all DDL
is hand-written, reviewed, and applied in order.

## Conventions

- **Naming:** `NNN_short_description.sql` (zero-padded three-digit prefix).
- **Idempotency:** Every migration must be safe to re-run (`CREATE ... IF NOT
  EXISTS`, `DO $$ ... END $$` guards). CI validates this.
- **Encoding:** UTF-8 without BOM; files must end with a trailing newline.
- **Parameterised queries only.** No string concatenation for user-supplied
  values (CVE-2022-45786 mitigation).
- **Reversibility:** Prefer additive changes (new tables, columns, indices).
  Destructive changes (drops, type alterations) require explicit justification
  in the commit message.

## Running migrations

```bash
make migrate        # Apply all pending migrations in order
make reset          # Drop database, recreate, migrate, and seed
```

Migrations are applied by the `Makefile` target, which iterates `*.sql` files
in lexicographic order using `psql -v ON_ERROR_STOP=1`.

## Rollback strategy

Migrations are designed to be additive. If a migration must be reverted:

1. Write a new migration that undoes the change (never edit an existing file).
2. Number it as the next in sequence.
3. Document the rollback rationale in the commit message.

## Current migrations

| File | Purpose |
|------|---------|
| `001_extensions.sql` | PostgreSQL extensions (AGE, pgvector, pgcrypto, pgaudit, pg_cron) |
| `002_graph_schema.sql` | Core graph entities, STIX object tables |
| `003_vector_tables.sql` | pgvector embeddings and HNSW index |
| `004_rls_policies.sql` | Row-level security for TLP enforcement |
| `005_audit_tables.sql` | Append-only audit log |
| `006_temporal.sql` | Bitemporal fact tables (t_valid, t_invalid, t_recorded, t_superseded) |
| `007_dlq_archive.sql` | Dead-letter queue and archive tables |
| `008_audit_immutability.sql` | Hash chain verification for audit integrity |
| `009_infra_layer.sql` | Infrastructure and asset model (Layer 7) |
| `010_iam_layer.sql` | Identity and access management model (Layer 8) |
| `011_vector_dimensions.sql` | Vector dimension configuration and tuning |
| `012_scheduled_jobs.sql` | pg_cron jobs for Merkle root, stale embedding cleanup, DLQ archive |
| `013_dlq_first_failed_default.sql` | Add default `now()` to `dlq_archive.first_failed` |
| `014_rls_nullif_guard.sql` | Add NULLIF guard to RLS `current_setting` calls |

## CI validation

The `lint.yml` workflow validates:

- Sequential numbering (no gaps or duplicates)
- UTF-8 encoding
- Trailing newline
- File naming pattern
