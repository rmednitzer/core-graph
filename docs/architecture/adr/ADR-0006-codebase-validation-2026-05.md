# ADR-0006: Code-base validation against authoritative sources (2026-05)

## Status

Accepted (Phase 6, v1.x — recorded 2026-05-24).

## Context

After five phases of feature work (Phase 0 latent-bug fixes through Phase 5
eval harness), we performed a full code index of the repository and
validated implementation choices against the published documentation of
each upstream component: Apache AGE, pgvector, NATS JetStream, Cerbos,
SpiceDB, the OASIS STIX 2.1 / TAXII 2.1 specifications, Sigstore (cosign +
Rekor), the MCP Python SDK, and OCSF 1.1.

The goal was not to drive new feature work but to (a) record where the
code is provably aligned with authoritative guidance, (b) capture
documentation drift between the prose and the code as it stands, and
(c) make architectural-intent gaps explicit so they cannot be mistaken
for implementation bugs by future contributors.

## Decision

This ADR is the single landing page for the 2026-05 validation pass.
Future code reviews can use it as a baseline for what was validated, by
whom, and against which upstream version. Subsequent revalidations append
new sections rather than overwriting old ones.

## Scope of the validation

The index covered seven areas, each surveyed by an independent pass:

1. Schema and migrations (`schema/migrations/`, `schema/seed/`)
2. Authorization stack (`policies/`, `api/authz/`, `tests/rls/`,
   `tests/auth/`)
3. Ingest pipeline (`ingest/connectors/`, `ingest/graph_writer.py`,
   `ingest/dlq/`, `ingest/ner/`, `ingest/resolver/`, `ingest/metrics.py`)
4. API layer (`api/mcp/`, `api/rest/`, `api/taxii/`, `api/config.py`,
   `api/db.py`)
5. Evidence integrity (`evidence/chain/`, `evidence/signing/`,
   `scripts/stamp_merkle_roots.py`)
6. Tests and CI (`tests/`, `.github/workflows/`)
7. Deployment artefacts (`deploy/docker/`, `deploy/k8s/`, `deploy/nats/`,
   `deploy/grafana/`, `zarf.yaml`)

## Validated alignments

For each item below, the code path on the left was checked against the
authoritative source on the right and found to agree.

| Area | Code | Authoritative source |
|---|---|---|
| AGE label/path-quantifier interpolation | `api/utils/age_template.py` allow-lists 38 vertex labels and 18 edge labels; `api/mcp/tools/cypher_query.py::_materialise_depth` substitutes a validated integer for `__DEPTH__`/`__MAX_HOPS__` markers before AGE sees the query | Apache AGE: labels and variable-length path quantifiers cannot be bound via `$name`; they must be interpolated as literals, with caller-side validation |
| AGE vlabel/elabel creation | `schema/migrations/002_graph_schema.sql` and `023_memory_layer.sql` use `create_vlabel`/`create_elabel` (issue #39) | Apache AGE Python driver and docs use these helpers to register labels with the correct sequences and parent tables |
| pgvector HNSW + halfvec + partial-per-model | `schema/migrations/021_embedding_models_and_hybrid.sql` adds a halfvec column populated by trigger, a tsvector + GIN index, and a helper (`cg_create_model_indexes`) that materialises both full and half HNSW indexes per `model_id`; `cg_validate_model_suffix` enforces `[a-zA-Z0-9_]` before DDL interpolation | pgvector README and ADR-0002 |
| pgvector `ef_search` per call | `api/mcp/tools/vector_search.py` exposes `ef_search` per query and constrains by `model_id` | pgvector `hnsw.ef_search` GUC, settable per session/transaction |
| NATS JetStream durable consumer | `ingest/graph_writer.py:440` subscribes to `enriched.>` with `durable="graph_writer"`, `ConsumerConfig(ack_wait=30)`, explicit `msg.ack()` after `conn.commit()` succeeds | NATS server: at-least-once requires durable name + AckExplicit + AckWait |
| NATS DLQ | `ingest/dlq/processor.py` runs a dedicated `DLQ` stream over `dlq.>` with exponential backoff (`BASE_BACKOFF_S=2`, `MAX_RETRIES=3`) and an `dlq_archive` SQL table for terminal failures | NATS docs: idiomatic DLQ uses a sibling stream + MaxDeliver + advisory subjects |
| Cerbos TLP gating | `policies/resource/threat_entity.yaml`, `evidence_record.yaml`, `incident.yaml` all use `request.resource.attr.tlp_level <= request.principal.attr.max_tlp` (integers, 0..4) | Cerbos docs: `condition.match.expr` with integer comparison is the canonical numeric-clearance pattern |
| Cerbos `cg_ciso`-only assert | `policies/resource/identity_attribution.yaml` allows only `cg_ciso`; `api/mcp/tools/identity_attribution.py:_check_cerbos_authorization` calls Cerbos before MERGE and fails closed | Cerbos: resource policy + explicit allow-list of roles is the canonical least-privilege pattern |
| RLS — IAM TLP:AMBER floor | `schema/migrations/010_iam_layer.sql` creates RESTRICTIVE `iam_tlp_floor` policy AND-ed with the permissive read policy; `tests/rls/test_iam_tlp_floor.sql` verifies | PostgreSQL RLS: RESTRICTIVE policies are AND-combined, ideal for unconditional floors |
| Merkle tree | `evidence/chain/merkle.py` prefixes leaf hashes with `0x00` and internal-node hashes with `0x01` (RFC 6962 domain separation); odd nodes promoted; `hmac.compare_digest` for inclusion verification | RFC 6962 + CVE-2012-2459 mitigation pattern |
| Audit-log append-only | `schema/migrations/008_audit_immutability.sql` installs `trg_audit_log_no_update` and `trg_audit_log_no_delete` triggers that `RAISE EXCEPTION` unconditionally | PostgreSQL — trigger-enforced append-only is the only way to bind the constraint at engine level (no user role suffices) |
| MinIO WORM | `evidence/signing/minio.py` sets bucket lock mode to `COMPLIANCE` (not `GOVERNANCE`) with 2555-day retention | MinIO docs: COMPLIANCE mode is the regulatory-grade lock; even root cannot remove until expiry |
| cosign keyless | `evidence/signing/sign.py` shells out to `cosign sign-blob --yes` and parses the Rekor `tlog entry created with index:` line | Sigstore docs: `--yes` for non-interactive CI; Rekor index extraction from stdout |
| TAXII 2.1 endpoints | `api/taxii/server.py` exposes discovery, api-roots, collections, manifest, objects, status; keyset pagination uses `X-TAXII-Date-Added-First/Last`; OIDC auth (no dev-header) | OASIS TAXII 2.1 OS — all MUST-level endpoints and pagination headers covered |
| STIX 2.1 bundle | `api/taxii/server.py::STIXBundle` carries `type:"bundle"`, `id`, `objects`; SDOs persist `spec_version`, `created`, `modified` | OASIS STIX 2.1 OS — required common properties |
| MCP server | `api/mcp/server.py` uses `from mcp.server.fastmcp import FastMCP`, registers tools via `@mcp.tool()`, skills via `registry.discover_skills()` | modelcontextprotocol/python-sdk canonical pattern |
| OIDC JWKS cache | `api/rest/middleware/oidc.py::_JWKSCache` wraps `jwt.PyJWKClient` with TTL from `CG_OIDC_JWKS_CACHE_TTL` (default 3600 s) | PyJWT docs — JWKS clients should cache keys with bounded TTL |
| Bitemporal invariants | `schema/migrations/020_temporal_invariants.sql` + `026_temporal_overlap_predicate_fix.sql` enforce `t_valid ≤ t_invalid`, `t_recorded ≤ t_superseded`, GIST exclusion for overlapping active facts, partial-unique for single-active-version | Snodgrass bitemporal semantics; ADR-0005 supersession contract |
| Statement-timeout uniformity | `api/db.py::get_connection` sets `statement_timeout` from `age_query_guard.query_timeout_ms` for every caller (REST / MCP / ingest / TAXII) | PostgreSQL — uniform per-role ceiling defeats per-call override drift |

## Documentation-vs-code drift

Surfaced during the index. These are corrected in the same change set as
this ADR.

| File | Drift | Resolution |
|---|---|---|
| `README.md` | Repository layout said `Numbered SQL files (001_ through 019_)`. Current head is 001..026. | Updated to `001_ through 026_` |
| `CLAUDE.md` | The "Configuration" section listed two known exceptions (NETBOX_*, OPENCTI_*) and one secondary read (`CG_CORS_ORIGINS`). The audit found three additional service-level direct reads not bound through `api/config.py`: `CG_RERANKER_URL` (`api/mcp/tools/hybrid_search.py:46`), `CG_DLQ_MAX_RETRIES` (`ingest/dlq/processor.py:29`), and `CG_PROMETHEUS_WEBHOOK_SECRET` (`ingest/connectors/prometheus/adapter.py:41`); plus connector-internal Pydantic configs in misp / keycloak / netbox / prometheus that re-read their own `CG_*` / unprefixed vars. | `CLAUDE.md` exceptions list extended; the connector-internal pattern is documented as a deliberate per-connector config-dataclass convention |
| `docs/architecture/authorization-model.md` | The Layer-3 RLS section shows a `compartment_read_policy ... USING (compartment_id = ANY(string_to_array(current_setting('app.allowed_compartments', true), ',')))`. No such policy exists in any migration; the only RLS predicate over compartments is in the application-layer Cypher templates. The session variable `app.allowed_compartments` is set in `api/db.py` but never read by any RLS policy. | Added a status note distinguishing the (implemented) TLP policy from the (target-state) compartment policy |
| `docs/architecture/authorization-model.md` | Layer 2 (SpiceDB) is described as evaluated on every request. The schema (`api/authz/schema.zed`) and client (`api/authz/spicedb.py`) are present, but no REST route or MCP tool calls `check_permission()` or `lookup_resources()`. Compartment scoping currently happens at the Cypher template layer via the `compartments` user attribute. | Added a status note: SpiceDB schema is defined and the client is wired; integration into the request path is pending (Phase 4 hardening) |
| `docs/skills/README.md` | The skill table listed 10 skills. The registry actually exposes 13 (the three graphrag skills added in Phase 4 were not listed). | Added `graphrag_anchored_retrieval`, `graphrag_path_ranking`, `graphrag_neighborhood` to the table |

## Architectural-intent gaps (not bugs, but worth recording)

These are deliberately documented as gaps so they don't masquerade as
implementation bugs in future reviews.

1. **Compartment enforcement is application-layer, not RLS.** RLS
   enforces TLP at the engine level, but compartment scoping is currently
   the responsibility of the Cypher templates that compose
   `WHERE n.compartment = ANY($compartments)` predicates. Threat model:
   any caller able to issue raw Cypher through `cypher_query` bypassing
   the templates can read across compartments. Mitigation today is
   template allow-listing + parameter-schema enforcement in
   `api/mcp/tools/cypher_query.py`. Future hardening (planned but not
   scheduled) is to add a `compartment_id` column to each label table
   with an RLS policy that reads `app.allowed_compartments`.

2. **SpiceDB schema is defined but not in the request path.**
   `api/authz/schema.zed` and `api/authz/spicedb.py` are production-ready;
   the schema covers `team`, `investigation`, and `entity` with
   compartment/ownership/sharing semantics. No request path calls them
   yet. The architecture diagram in
   `docs/architecture/authorization-model.md` shows SpiceDB as Layer 2,
   which represents the target shape, not current code. The same
   document now carries a "status: pending integration" note.

3. **Identity-attribution policy lacks a Cerbos test fixture.**
   `policies/resource/identity_attribution.yaml` gates the
   `Principal--same_as--ThreatActor` MERGE to `cg_ciso`. The MCP tool
   correctly fails closed (`api/mcp/tools/identity_attribution.py:131`),
   but `tests/auth/cerbos_policies_test.yaml` does not declare a
   principals/resources/tests block for this policy. The policy works
   in practice and the MCP path is integration-tested, but the unit
   coverage in Cerbos is missing. Tracked as follow-up.

4. **Connector configs duplicate config bindings.** The Pydantic
   dataclasses in `ingest/connectors/{netbox,keycloak,prometheus,misp}/`
   re-read environment variables that are also bound in
   `api/config.py`. This is a deliberate convention — connectors carry
   their own self-contained `Config` so they can run as standalone
   services — but it means changes to defaults must be made in two
   places. Considered a known artefact, not a bug.

## Tests covering these claims

- AGE label safety: `tests/test_label_safety_coverage.py`,
  `tests/test_cypher_safety.py`, `tests/test_cypher_template_safety.py`
- Bitemporal: `tests/test_migration_020_safety.py`,
  `tests/integration/test_graph_write.py::test_audit_log_hash_chain_intact`
- RLS TLP: `tests/rls/test_tlp_enforcement.sql`,
  `tests/rls/test_iam_tlp_floor.sql`, `tests/rls/test_edge_tlp.sql`,
  `tests/integration/test_rls_age.py`,
  `tests/eval/test_rls_retrieval_correctness.py`
- Merkle: `tests/test_merkle.py` (CVE-2012-2459 second-preimage),
  `tests/test_audit_chain_verify.py`
- TAXII: `tests/taxii/test_taxii_endpoints.py`
- Cerbos policy compile: `.github/workflows/test.yml` (`cerbos compile
  --tests=tests/auth policies/`)
- Statement timeout uniformity: `tests/test_statement_timeout_uniformity.py`
- TLP encoding: `tests/test_threat_entity_policy_tlp.py`

## Consequences

* This ADR is the canonical source for "what version of which upstream
  did we validate against, when, and with what outcome." Future
  validation passes append `ADR-0007`, `ADR-0008`, … rather than
  overwriting this file.
* The documentation drift items above are corrected in the same change
  set; future drift between prose and code should be caught by ADR
  revalidations on a schedule.
* The architectural gaps are explicitly named so they cannot be
  mistaken for bugs. Items 1 (compartment RLS) and 2 (SpiceDB
  integration) are candidate Phase 4 hardening work; item 3 (Cerbos
  identity-attribution test fixture) is a tracked follow-up; item 4
  (connector config duplication) is documented as a deliberate
  convention.
* No code changes are introduced by this ADR. The validation pass
  surfaced no security regressions and no new bugs.

## References

* RFC 6962 — Certificate Transparency Merkle tree construction (leaf
  / internal-node domain separation).
* CVE-2012-2459 — Bitcoin Merkle second-preimage attack; the rationale
  for the domain-separation prefixes implemented in
  `evidence/chain/merkle.py`.
* OASIS STIX 2.1 OS (June 2021) — required common properties on SDOs;
  Bundle structure.
* OASIS TAXII 2.1 OS (June 2021) — discovery / api-roots / collections
  / manifest / objects / status endpoint set; pagination headers;
  trailing-slash and Accept/Content-Type requirements.
* OCSF 1.1.0 — class taxonomy (Authentication = 3002, Process Activity
  = 1007, Detection Finding = 2004); base event attributes.
* Apache AGE — `create_vlabel`, `create_elabel`, parameter-binding
  semantics for `cypher()`; variable-length path quantifiers are not
  parameterisable.
* pgvector — HNSW + halfvec + per-model partial-index pattern;
  `hnsw.ef_search` GUC tuning.
* NATS JetStream — durable consumer + AckExplicit + AckWait for
  at-least-once; DLQ pattern via MaxDeliver + advisory subjects.
* Cerbos — `condition.match.expr` for numeric clearance comparisons;
  derived-roles composition; YAML test fixtures.
* SpiceDB / Authzed — Zanzibar-style relations with arrow
  (`->`) permissions for delegation chains.
* Sigstore — `cosign sign-blob --yes` keyless flow with bundle output
  and Rekor index extraction; verification via `--certificate-identity`
  + `--certificate-oidc-issuer`.
* modelcontextprotocol/python-sdk — `FastMCP` (now `MCPServer`)
  tool-registration via `@mcp.tool()`; recommended `streamable-http`
  transport for networked deployment.
* MinIO — object-lock COMPLIANCE vs GOVERNANCE modes; root cannot
  remove COMPLIANCE-locked objects before expiry.
* Snodgrass — *Developing Time-Oriented Database Applications in SQL*
  (1999) — bitemporal modelling with valid-time and transaction-time
  intervals; foundation for the four-timestamp model.
