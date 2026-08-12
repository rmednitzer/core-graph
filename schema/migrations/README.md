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
| `015_merkle_root_table.sql` | Periodic Merkle root storage for audit log integrity |
| `016_merkle_scheduled_job.sql` | Proper Merkle tree computation cron job (replaces 012 hash concat) |
| `017_age_indexes.sql` | Performance indexes on AGE vertex property columns |
| `018_dlq_error_class.sql` | Error classification column on DLQ archive |
| `019_embedding_metadata.sql` | Model version and timestamp tracking for embeddings |
| `020_temporal_invariants.sql` | Bitemporal append-only guards: NOT-NULL mutation attribution, no-overlap exclusion, delete-block trigger |
| `021_embedding_models_and_hybrid.sql` | Embedding model registry, per-model partial HNSW indexes, halfvec column + trigger, tsvector + GIN for BM25 |
| `022_edge_tlp_denormalization.sql` | Denormalised `tlp_level smallint` on all AGE edge label tables, BEFORE-trigger derivation from endpoints, deferred vertex cascade, per-edge RLS policy |
| `023_memory_layer.sql` | Layer 5 (AI memory): AGE labels Session/Episode/ExtractedFact/ConceptEntity + edges, relational shadow tables for sequence/supersession/salience, pg_cron salience refresh job |
| `024_audit_log_integrity_hardening.sql` | Audit tamper-evidence: TRUNCATE block, hash-chain trigger hardening |
| `025_merkle_domain_separation.sql` | Merkle leaf/node domain separation (second-preimage fix) |
| `026_temporal_overlap_predicate_fix.sql` | Partial no-overlap EXCLUDE on active temporal facts (supersession-safe) |
| `027_pgvector_iterative_scan.sql` | pgvector 0.8 HNSW iterative scans (fixes RLS overfiltering) |
| `028_rls_write_path_policies.sql` | RLS everywhere + TLP INSERT/UPDATE/DELETE policies, IAM AMBER write floor |
| `029_processed_messages_dedup.sql` | Graph-writer replay idempotency ledger (content-derived delivery keys) |
| `030_stix_sdo_indexes.sql` | stix_id / stix_type btree indexes for the SDO labels |
| `031_uuidv7_audit_correlation.sql` | PG18 `uuidv7()` time-ordered audit correlation ids |
| `032_edge_tlp_writer_resync.sql` | Edge-TLP resync helpers for the Cypher write path (trigger-less AGE writes) |
| `033_stix_sdo_completion.sql` | Final STIX SDO labels (IntrusionSet/Identity/Location/Report): vlabels, RLS policies + grants, stix indexes |
| `034_retrieval_model_registry.sql` | Retrieval model provenance: kind/provider/repo/revision/dim, register + deactivate helpers, pg_trgm |
| `035_retrieval_lifecycle.sql` | Subject retrieval lifecycle (`retrieval_active`, `pinned`, `expires_at`, `retention_class`) + parity views |
| `036_retrieval_serving_tier.sql` | Native `halfvec` serving tier `retrieval_embeddings (graph_id, model_id)`, per-model partial HNSW, hot-set backfill (ADR-0011) |
| `037_vector_tlp_enforcement.sql` | `tlp_level` + RLS read/write policies on both vector tables, fail-closed at 4 |
| `038_application_role.sql` | `cg_app`: a `LOGIN NOSUPERUSER NOBYPASSRLS` application role so RLS is actually evaluated (ADR-0012) |
| `039_serving_tier_lifecycle.sql` | Serving-tier prune trigger (fixes orphans left by 012's cleanup), duplicate-reporting view, `cg_sync_serving_tier()`, `cg_expire_retrieval()` + pg_cron maintenance (ADR-0013) |
| `040_clearance_role_assumption.sql` | `cg_app` may SET ROLE to each `cg_*` clearance (`inherit false, set true`) + the grants those roles need to serve a request (ADR-0015) |

## CI validation

The `lint.yml` workflow validates:

- Sequential numbering (no gaps or duplicates)
- UTF-8 encoding
- Trailing newline
- File naming pattern
