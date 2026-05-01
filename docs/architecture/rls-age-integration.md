# RLS and Apache AGE integration

How PostgreSQL Row-Level Security interacts with Apache AGE graph
queries in core-graph.

## How RLS applies to AGE internal tables

Apache AGE stores each vertex label as a table in the `core_graph`
schema (e.g. `core_graph."Host"`, `core_graph."ThreatActor"`). RLS
policies defined on these tables apply to `SELECT` operations including
those issued internally by the `ag_catalog.cypher()` function.

When a Cypher `MATCH (v:Host)` executes, AGE translates this into a
`SELECT` on `core_graph."Host"`. If an RLS policy filters rows where
`(properties::text)::jsonb->>'tlp_level' > current_setting('app.max_tlp')`,
matching vertices are silently excluded from the result set.

## Verified behaviour

Integration tests (`tests/integration/test_rls_age.py`) confirm:

- **Vertex filtering works.** A `MATCH (v:Indicator)` with `app.max_tlp`
  set to `2` (AMBER) returns only TLP:WHITE, TLP:GREEN, and TLP:AMBER
  indicators. TLP:RED indicators are excluded.
- **Path traversals respect RLS.** A multi-hop query like
  `MATCH (h:Host)-[:observed_as]->(ip)-[:indicates]->(v:Vulnerability)`
  excludes any path where an intermediate vertex is filtered by RLS.
- **Aggregate functions reflect filtering.** `count()` and `collect()`
  operate on the post-RLS result set.

## Edge label tables (closed in v1.x — migration 022)

Migration `022_edge_tlp_denormalization.sql` adds a denormalised
`tlp_level smallint NOT NULL` column to every AGE edge label table in
the `core_graph` schema. The column is:

* Backfilled to `GREATEST(source.tlp_level, target.tlp_level, properties.tlp_level)`
  for every existing edge.
* Maintained by a `BEFORE INSERT/UPDATE` trigger
  (`cg_edge_tlp_sync`) that re-derives the value on every write so the
  edge can never be more permissive than either endpoint.
* Cascaded from vertex tlp_level changes via a deferred constraint
  trigger (`cg_vertex_tlp_cascade`) that re-fires the per-edge trigger
  on incident edges.
* Filtered by a new permissive RLS policy (`tlp_edge_read_policy`) using
  the column directly — faster than the JSONB extraction used on vertex
  tables and impossible to bypass by omitting the property from the
  edge's agtype payload.
* IAM edges keep their RESTRICTIVE TLP:AMBER floor from migration 010;
  the new permissive policy is AND'd with the floor.

The writer (`ingest/graph_writer.py`) sets `e.tlp_level = GREATEST(...)`
explicitly in every relationship MERGE template — the trigger remains as
the safety net, not the sole path.

### Verified behaviour

The new test `tests/rls/test_edge_tlp.sql` exercises:

* A caller with `app.max_tlp = 2` cannot SELECT an edge between two
  TLP=3 vertices even when it can see both endpoints.
* Updating a vertex's `tlp_level` causes incident edges to be re-evaluated
  inside the same transaction (deferred trigger).
* IAM edges remain hidden when `app.max_tlp < 2` regardless of the
  edge's own tlp_level.

## Mitigation strategy

core-graph uses a defence-in-depth approach:

1. **Application-layer authorization** (Cerbos ABAC + SpiceDB ReBAC)
   evaluates before any AGE query executes. The MCP tools and REST API
   enforce authorization checks prior to issuing Cypher queries.
2. **RLS as defence-in-depth.** Even if application-layer checks are
   bypassed (bug, misconfiguration), RLS prevents data leakage at the
   PostgreSQL engine level.
3. **Statement timeout.** The `age_query_guard` module sets
   `statement_timeout` per role to prevent runaway traversals that might
   probe RLS boundaries.

## Tested failure mode: mid-traversal vertex filtering

When RLS blocks a vertex in the middle of a traversal path:

- The entire path is excluded from results (AGE treats the filtered
  vertex as non-existent).
- No error is raised — the query returns fewer results.
- `OPTIONAL MATCH` returns `null` for the filtered segment rather than
  the vertex data.

This behaviour is correct for confidentiality but may confuse analysts
who expect complete paths. The MCP skills report `gaps` in their
`SkillResult` to surface when data may be missing due to access
restrictions.

## Recommendations

- Always set `app.max_tlp` before AGE queries (enforced by `api/db.py`).
- Never grant direct SQL access to `core_graph.*` tables; route all
  graph access through `ag_catalog.cypher()` to ensure RLS applies.
- Monitor for RLS policy changes that might inadvertently expose AGE
  internal tables.
