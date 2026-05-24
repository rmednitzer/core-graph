# Database Optimization Report

## Current-state findings

- `temporal_facts` lacked enforced bitemporal window checks and mutation attribution metadata.
- `temporal_facts` allowed physical deletes, which weakens evidentiary posture.
- `api/db.py` used a broad exception while resetting RLS session context.

## Risks identified

- Overlapping active facts could be inserted for same `(source_id,target_id,edge_label,fact_type)`.
- Mutation operations on bitemporal facts had no mandatory actor/reason fields.
- Delete operations on evidentiary facts were not blocked at database layer.
- Broad exception handling could mask unexpected non-database faults in authorization context teardown.

## Changes made

- Added migration `020_temporal_invariants.sql`.
- Enforced temporal validity constraints and no-overlap exclusion for fact windows.
- Added required `mutation_actor` and `mutation_reason` fields.
- Added append-only protection by blocking deletes from `temporal_facts`.
- Tightened Python exception handling in `api/db.py` from `Exception` to `psycopg.Error`.

## Invariants now enforced in DB

- `t_valid <= t_invalid` when `t_invalid` is present.
- `t_recorded <= t_superseded` when `t_superseded` is present.
- No overlapping `valid_range` for identical source/target/edge/fact_type tuples.
- At most one active unsuperseded fact version per tuple (partial unique index).
- Mandatory mutation attribution (`mutation_actor`, `mutation_reason`).
- No physical deletes from `temporal_facts`.

## RLS / graph / vector / ingest / audit notes

- This patch is intentionally scoped to bitemporal integrity hardening and session-reset exception precision.
- No AGE model, pgvector index, or ingest path modifications were made in this change set.

## Performance and operations

- Added one partial unique index and one exclusion constraint to improve correctness-first semantics.
- Write overhead increases slightly for `temporal_facts` inserts due to new integrity checks.

## Residual risks

- Existing data may violate new constraints and require cleanup before migration application.
- AGE traversal authorization boundaries and vector candidate prefiltering remain to be deepened in follow-up work.

## Future work

- Add migration-data validation script to precheck overlap violations prior to deployment.
- Add integration tests for RLS fail-closed behavior in graph/vector cross-paths.
- Add benchmark delta analysis for temporal insert throughput under exclusion constraints.

## Phase 0 follow-up (2026-05)

- Migration 020 hardened: invalid `ADD CONSTRAINT IF NOT EXISTS` syntax replaced
  with `pg_constraint` catalog lookups; required NOT-NULL columns now backfilled
  with sentinel values before promotion.
- Migration 011 now refuses silent destructive truncate; requires
  `app.allow_embedding_truncate=true` GUC, documented in
  `docs/operations/database-migration-runbook.md`.
- Cypher templates `asset_security_events` and `identity_audit_trail` now bind
  the time-threshold parameter Python-side (AGE openCypher does not support `+`
  string concatenation).
- `api/db.py` enforces `statement_timeout` uniformly for all callers from
  `age_query_guard.query_timeout_ms`, eliminating the REST/ingest/TAXII gap.
- `policies/resource/threat_entity.yaml` aligned to integer `tlp_level` (0..4).
- `api/mcp/tools/identity_attribution.py` widens session compartments before
  writing TLP:RED `same_as` edges so the writer can read its own row under RLS.

## Commands run and results

- `pytest tests/test_migration_numbering.py` (pass)
- `python -m compileall api/db.py` (pass)

## Validation pass (2026-05-24)

A full code index and cross-check against authoritative upstream
documentation was performed and recorded in
[ADR-0006](adr/ADR-0006-codebase-validation-2026-05.md). Schema-layer
outcomes relevant to this report:

- **Migration count.** 26 numbered files (`001_` through
  `026_`). No anti-patterns surfaced: every migration is idempotent
  (`IF NOT EXISTS`, `DO`-block catalog lookups where `ADD CONSTRAINT IF
  NOT EXISTS` is unavailable), every trigger body uses function calls
  rather than string-concat DDL.
- **Bitemporal invariants.** Migration `020` (window + overlap
  exclusion + mandatory mutation attribution) is in force; `026`
  corrects the predicate on the single-active-fact partial unique
  index. The contract from this report stands.
- **Vector layer.** Migration `021` (model registry, halfvec column,
  tsvector, GIN, and per-model partial HNSW pair) is the canonical
  vector path. Model-id validation (`cg_validate_model_suffix`) gates
  the DDL interpolation, mitigating injection in the per-model index
  helper.
- **AGE-RLS edge gap.** Closed by `022` (denormalised `tlp_level` on
  every edge label table with trigger + RLS policy). Documented in
  `rls-age-integration.md`.
- **Audit-log integrity.** `008` enforces append-only via
  `BEFORE UPDATE / BEFORE DELETE` triggers that always raise; `024`
  hardens the hash-chain computation; `025` adds Merkle
  domain-separation aligned with RFC 6962. Verified by
  `tests/test_merkle.py` (CVE-2012-2459 second-preimage) and
  `tests/test_audit_chain_verify.py`.

No new findings required schema changes. ADR-0006 records the
documentation drift fixes shipped alongside this appendix.
