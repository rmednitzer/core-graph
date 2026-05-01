# ADR-0005: Memory layer supersession detection

## Status

Accepted (Phase 3, v1.x).

## Context

Layer-5 ExtractedFact vertices are `(subject, predicate, object)`
triples. The agent learns new objects for the same subject+predicate
over time ("the host's primary IP is X" → later "the host's primary IP
is Y"). Older facts are not deleted — the bitemporal contract keeps
them invalidated, never deleted.

We need:

1. Cheap detection of "is there an active fact for this
   (subject, predicate)?" without full-graph scan.
2. Atomic invalidation of the old fact when a new contradictory one
   lands.
3. A SUPERSEDES edge that records the new→old replacement so any
   downstream graph traversal can follow the supersession chain.

## Decision

Two-table approach:

* AGE keeps the canonical ExtractedFact vertices and SUPERSEDES edges.
* A relational shadow `memory_extracted_fact_index(subject_hash,
  predicate_hash, fact_graph_id, object_hash, t_recorded, t_superseded)`
  with a partial index on `(subject_hash, predicate_hash) WHERE
  t_superseded IS NULL` for hot-path lookup of active facts.

Detection happens in `memory_remember.tool_record_extracted_fact`:

1. SELECT the active row from the shadow before insert.
2. CREATE the new ExtractedFact vertex + EXTRACTED_FROM edge in AGE.
3. INSERT the new row into the shadow. A trigger
   (`memory_mark_supersession`) marks any prior row for the same
   `(subject_hash, predicate_hash)` as superseded by setting
   `t_superseded = now()`.
4. If a prior row was found, write a SUPERSEDES edge in AGE and set
   `old_fact.t_superseded = now()`.

The whole sequence happens inside a single transaction so the
relational shadow and the AGE state can never disagree.

## Why hash the subject and predicate

Subject and predicate strings can be arbitrarily long. SHA-256 hashes
are 64 chars and indexable. Equality semantics are exact, which is what
supersession detection needs (semantic similarity is a different
problem solved by entity resolution upstream).

## Why a relational shadow at all

Apache AGE Cypher does not yet expose a fast index on a property pair
across an entire vertex label. Lookup-by-property in AGE means scanning
the label table and casting properties to JSONB — fine for occasional
analyst queries, too slow for "every memory write does this lookup".

The shadow makes the detection an O(1) index lookup. The AGE state
remains the canonical source of truth.

## Consequences

* Every new ExtractedFact does one extra `INSERT` into the shadow. The
  partial index keeps lookup O(log n) on the active set.
* Direct AGE writes (analysts hand-rolling Cypher) bypass the shadow.
  Documented as a known limitation; the runbook recommends going
  through `tool_record_extracted_fact` for analyst supersession events.
* The trigger marks superseded *only when* the new object differs.
  Re-asserting the same fact (subject, predicate, object identical) is
  a no-op for supersession but still records the new ExtractedFact
  vertex (audit/replay value).

## Alternatives considered

* **Pure-AGE supersession via Cypher** — too slow for hot paths.
* **Embedding-based supersession (cosine on object)** — rejected as
  semantic; we want exact-match supersession only.
* **Soft delete + tombstone** — rejected as it conflicts with the
  bitemporal contract that nothing is deleted.

## References

* `schema/migrations/023_memory_layer.sql`
* `api/mcp/tools/memory_remember.py`
