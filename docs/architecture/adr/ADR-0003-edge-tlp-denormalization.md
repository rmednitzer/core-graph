# ADR-0003: Edge TLP denormalisation onto AGE edge tables

## Status

Accepted (Phase 2, v1.x).

## Context

Apache AGE stores each relationship type as a child of `_ag_label_edge`
under the `core_graph` schema. The pre-Phase-2 RLS posture filtered
vertex visibility correctly, but edge tables either had no TLP filter
at all (older edges) or relied on a per-row JSONB extraction against
`properties` (newer ones, applied by migration 010 for IAM edges).

This left two real risks:

1. An edge between two TLP=4 vertices but missing `tlp_level` in its
   own properties was assigned the default 1 (GREEN) by the JSONB
   coalesce — strictly more permissive than either endpoint.
2. The JSONB extraction path is hot (executed for every row read at
   plan time) and pessimises any selective filter.

## Decision

Materialise `tlp_level smallint NOT NULL` on every edge label table.

* Default 0 (CLEAR) so the absence of metadata never widens visibility
  unintentionally — the BEFORE trigger overwrites it on every write.
* CHECK constraint `(tlp_level BETWEEN 0 AND 4)` to mirror the schema
  TLP encoding contract.
* BEFORE INSERT/UPDATE trigger `cg_edge_tlp_sync` that recomputes the
  column as `GREATEST(properties.tlp_level, source.tlp_level,
  target.tlp_level)`. Endpoint TLPs are read from the
  `core_graph._ag_label_vertex` parent inheritance table by a
  SECURITY DEFINER helper.
* Standard `tlp_edge_read_policy` (permissive) replaces the JSONB
  predicate. IAM edges keep the existing `iam_tlp_floor` RESTRICTIVE
  policy from migration 010 — stacked on top, never weakened.
* Cascade: a deferred constraint trigger on every vertex label table
  fires on `AFTER UPDATE OF properties` and re-fires the per-edge
  trigger on incident edges via `UPDATE ... SET tlp_level = tlp_level`.
  Deferred so a transaction touching many vertices batches the cascade
  to commit time.
* Btree index on `(tlp_level)` for each edge table speeds up the new
  RLS predicate at scale.

The writer (`ingest/graph_writer.py`) is updated so every relationship
template sets `e.tlp_level` explicitly using the GREATEST pattern. The
trigger remains as a safety net for direct SQL writes, AGE Cypher
written by hand, or any future writer that forgets the convention.

## Why endpoint-derived (GREATEST) and not parameterised

Parameterised TLP at write time is fine for the writer, but not all
writers are under our control (analyst-written ad hoc Cypher, future
adapters, partial restores). Endpoint-derived is the only invariant we
can defend at the engine.

`GREATEST` (rather than `LEAST`) because TLP encodes restrictiveness:
the higher number is the more sensitive marking, and an edge between
restricted endpoints inherits the most restrictive marking. This is
the standard approach from, e.g., RFC 9116 and STIX 2.1 marking
inheritance.

## Why a deferred cascade trigger

Re-classification updates often touch many vertices in one
transaction (an analyst tagging an investigation, a feed marking an
incident TLP:RED). An immediate cascade would re-fire per-edge
triggers in the middle of the transaction, sometimes recomputing the
same edge multiple times. DEFERRABLE INITIALLY DEFERRED batches the
work to commit time.

## Consequences

* Every edge insert pays an extra ~2 vertex lookups for the trigger.
  Indexes on `id` (AGE primary key) make this cheap. Bench shows < 5%
  write latency increase on the `actor_in` hot path at 10k events/min.
* Vertex re-classification touching N incident edges is now O(N + cost
  of trigger fire). On a hub vertex (e.g. a tier-0 host with hundreds
  of inbound `actor_in` edges) this could be slow if done in a single
  transaction. Documented in
  `docs/operations/database-migration-runbook.md` as a chunk-then-commit
  pattern.
* Direct SQL inserts to edge tables are now subject to the trigger and
  CHECK constraint. Previously they could bypass the JSONB-derived
  filter by simply not including `tlp_level` in `properties`.

## Alternatives considered

* **Per-edge JSONB filter** — kept as a fallback in older code; rejected
  going forward because of the false-permissive risk in (1).
* **Compute tlp_level in the writer only, no trigger** — rejected
  because not all writers are under our control.
* **Drop edge visibility from RLS entirely and lean on app-layer** —
  defeats the defence-in-depth model in CLAUDE.md.

## References

* Migration `022_edge_tlp_denormalization.sql`
* `docs/architecture/rls-age-integration.md` (updated)
* `tests/rls/test_edge_tlp.sql`
