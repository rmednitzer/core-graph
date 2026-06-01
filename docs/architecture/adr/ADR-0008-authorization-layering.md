# ADR-0008: Authorization layering (RLS-primary, Cerbos write-path, SpiceDB deferred)

## Status

Accepted (recorded 2026-06-01). Supersedes the "pending integration" notes in
ADR-0006 for the Cerbos path. Builds on ADR-0003 (edge TLP denormalisation) and
ADR-0006 (code-base validation).

## Context

`CLAUDE.md` records two authorization decisions that must not be contradicted:

- *"Row-Level Security enforces TLP markings at the engine level."*
- *"Cerbos (ABAC) + SpiceDB (ReBAC) for authorization decisions."*

ADR-0006 (2026-05) found a gap between that stated three-layer model and the
runtime:

- `api/authz/cerbos.py:check_resource` had **zero callers**.
- `api/authz/spicedb.py:check_permission` had **zero callers**.
- The *only* place Cerbos was actually invoked at runtime was the CISO-gated
  identity-attribution write path, through a **bespoke inline httpx client**
  in `api/mcp/tools/identity_attribution.py` rather than the canonical client.

SECURITY.md was subsequently aligned to the runtime (reads enforce RLS only).
The 2026-05-27 senior-assurance engagement then recommended a dedicated ADR to
**decide and record** whether the project commits to invoking Cerbos/SpiceDB on
read paths, or accepts an RLS-primary runtime model — folding in findings S-01
(Cerbos unused), S-02 (SpiceDB unused), and M-01 (two Cerbos client
implementations). That ADR was never written; ADR-0007 was used for the
modernization/engine-upgrade pass instead. The decision has therefore been
deferred twice.

This pass additionally found that **both** Cerbos clients were wire-incorrect,
in *different* ways, against the documented Cerbos `/api/check/resources` API
(verified against the Cerbos v0.53 API reference):

| Client | Request shape | Response parse |
|---|---|---|
| `api/authz/cerbos.py` (canonical, unused) | **wrong** — singular `resource` + top-level `actions` posted to the plural `resources` endpoint | correct — reads `actions[action]` as a string |
| `identity_attribution.py` (the only wired call) | correct — batch `resources: [{resource, actions}]` | **wrong** — read `actions[action].effect`; the effect is a string, so `.get("effect")` raised `AttributeError` and fail-closed |

Because the wired path fail-closed on every decision, **identity attribution
denied every request against a live Cerbos** — the feature was non-functional
and the breakage was invisible (no live-Cerbos test exercised the parse). See
`tests/test_cerbos_client.py` for the regression that pins the corrected shape.

## Decision

Adopt and record an **RLS-primary** authorization model with a single,
correct Cerbos client used only where ABAC adds value over RLS.

1. **PostgreSQL RLS is the primary, unforgeable authorization boundary.** TLP
   clearance (`app.max_tlp`) and compartment scoping (`app.allowed_compartments`)
   are enforced by the database engine on every read, via session GUCs set on
   each connection acquired from `api.db.get_connection`. This is the floor; no
   application bug can make the engine return rows the session is not cleared
   to see. (Unchanged; restated as the keystone.)

2. **Cerbos (ABAC) is the policy-decision point for high-assurance writes that
   RLS cannot express** — specifically the `ciso`-gated
   `Principal--same_as--ThreatActor` attribution (`assert` action). It is
   invoked *before* the DB operation and fails closed. Cerbos is **not** placed
   in the read path: RLS already enforces the TLP/compartment decision at the
   engine, so a per-read Cerbos round-trip would duplicate that decision at
   higher latency without strengthening the floor.

3. **There is exactly one Cerbos client: `api/authz/cerbos.py`.** It exposes a
   low-level `check_action(principal, resource_kind, resource_id, action)` and a
   `check_resource(CallerIdentity, ...)` convenience that builds the principal
   from OIDC attributes and delegates. The bespoke inline client in
   `identity_attribution.py` is removed; that path now delegates to
   `check_action`, giving the canonical client its first real caller (resolves
   S-01 and M-01). The wire format is corrected to the documented batch request
   and string-effect response (resolves the always-deny bug), pinned by
   `tests/test_cerbos_client.py`.

4. **SpiceDB (ReBAC) is retained as scaffolding, explicitly deferred, with a
   wiring tripwire.** The schema (`api/authz/schema.zed`) and client
   (`api/authz/spicedb.py`) stay in the tree but are documented as
   not-yet-in-the-request-path (resolves S-02 as a recorded decision rather than
   silent dead code). It is wired in **when, and only when, relationship-based
   resource sharing is required that RLS compartments cannot express** — e.g.
   per-investigation membership or cross-team case sharing where access derives
   from a graph of grants rather than a single TLP/compartment label. Until that
   need is concrete, no request path calls SpiceDB.

5. **The canonical role vocabulary is the IdP's bare names; Cerbos binds to them
   directly.** The principal `roles` that reach Cerbos must match the IdP-emitted
   strings *exactly* — Cerbos does no normalisation, and matching is
   case-sensitive (per the Cerbos derived-roles docs). The OIDC IdP emits the
   **bare** role names (`ciso`, `soc_analyst`, …), so `derived_roles.yaml`
   `parentRoles` and the `tests/auth` fixtures use those bare names — and with
   the wire-format fix above, a real `ciso` caller now activates the `ciso`
   derived role and is allowed. No code-level role normaliser is added: that
   would contradict Cerbos's exact-match model.

   **Two namespaces (reconciled, A-03).** The `cg_*` strings in the codebase are
   *not* all the same kind of role. There are two distinct namespaces:

   - **Application roles** — the bare names (`ciso`, …) the IdP emits in the JWT
     `roles` claim. Consumed by Cerbos (`derived_roles.yaml`) and the
     application-layer depth/timeout guards (`api/utils/age_query_guard.py`),
     both of which match the claim verbatim.
   - **PostgreSQL database roles** — `cg_`-prefixed (`cg_ciso`, …), created in the
     schema migrations and targeted by the RLS `GRANT`s and `to <role>` policies.
     The application path connects as the pool user and enforces TLP via the
     `app.max_tlp` session GUC (not `SET ROLE`), so these are a separate,
     coarse-grained layer.

   The original defect was that `api/utils/age_query_guard.py` keyed its
   depth/timeout tables on the **database-role** spelling (`cg_*`) while being fed
   the **application-role** claim, so every caller silently fell back to the
   default limits (a real but fail-safe, more-restrictive bug — and its unit test
   had locked in the wrong spelling). A-03 reconciles the application-role sites
   (`age_query_guard.py`, the dormant `schema/seed/roles.sql` clearances, and the
   application-role references in the docstrings, CLAUDE.md, and the architecture
   docs) onto the bare names, with a regression test asserting a `ciso` caller
   resolves its non-default depth/timeout. The `cg_`-prefixed **database roles**
   in the migrations are intentionally left unchanged — they are a different
   namespace, not a misspelling.

## Consequences

- Identity attribution **functions** against a live Cerbos for the first time;
  legitimate `ciso` callers are allowed, all other roles denied, fail-closed
  preserved on transport error / empty result / non-`EFFECT_ALLOW`.
- The "Cerbos defined but unused" and "two client implementations" findings are
  closed by consolidation, not by deletion: the canonical client now has a
  caller and a regression test.
- Reads remain RLS-gated. The documented model and the runtime now agree, so
  SECURITY.md no longer needs a divergence note for the Cerbos path (it is
  updated alongside this ADR).
- SpiceDB stays as honest scaffolding with a written activation criterion, so a
  future reader does not mistake it for an enforced layer (the ADR-0006 risk) or
  delete it as unused (it is on the roadmap).
- `check_resource` / `plan_resources` exist for a future read-path ABAC or
  query-plan-pushdown design; they are correct and tested, but not yet wired —
  the same honest-scaffolding posture as SpiceDB.

## Alternatives considered

- **Wire the Cerbos PDP into every read.** Rejected: RLS already enforces the
  TLP/compartment decision at the engine. A per-read Cerbos call adds a network
  round-trip and a second source of truth for the same decision without a
  stronger guarantee — the engine floor is what makes the system auditable and
  single-engineer-operable.
- **Remove Cerbos and SpiceDB; go RLS-only.** Rejected: the identity-attribution
  role gate is genuinely an ABAC decision (role + TLP precondition) that RLS does
  not express, and ReBAC is a real roadmap need for case sharing. Deleting them
  would discard working/needed structure.
- **Cerbos query-plan → SQL pushdown for reads (`plan_resources`).** Deferred,
  not rejected: translating a Cerbos query plan into a `WHERE` fragment that
  composes with RLS is a viable future enhancement for attribute filters RLS
  cannot encode. The client method is kept as scaffolding for that work.

## References

- `CLAUDE.md` — Architecture decisions (RLS, Cerbos, SpiceDB)
- ADR-0006 — code-base validation (records the original S-01/S-02/M-01 gaps)
- `SECURITY.md` — Authorization model (updated with this ADR)
- `docs/architecture/authorization-model.md` — layer-by-layer detail
- `api/authz/cerbos.py`, `api/mcp/tools/identity_attribution.py`
- `policies/resource/identity_attribution.yaml`, `policies/derived_roles.yaml`
- `tests/test_cerbos_client.py` — wire-format regression suite
- Cerbos API reference — `POST /api/check/resources` request/response schema
  (<https://docs.cerbos.dev/cerbos/latest/api/>)
