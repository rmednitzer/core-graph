# Repository Audit Engagement: 2026-06-01

Repository: `rmednitzer/core-graph`
Working branch: `claude/gifted-galileo-sIoRK`
Base: `main` @ `57fc38a` (HEAD before engagement)
Remit: full-repo audit — find gaps, add ADRs, work the backlog.

Evidence tags: `[V]` verified this session, `[I]` inference from premises,
`[?]` unknown / needs a live stack.

---

## 1. Inventory snapshot (read-only)

State at engagement start (HEAD `57fc38a`):

- 181 Python files; 32 SQL migrations (`001`–`032` + README); 7 ADRs
  (`0001`–`0007`); 5 GitHub workflows (lint, test, security, eval, release). [V]
- Backlog sources: **0 open issues, 0 open PRs.** The backlog is therefore the
  union of (a) ADR-0007's "Deferred — roadmap", and (b) the
  `audit/2026-05-27-engagement.md` "Outstanding risks & recommended next
  steps". [V]
- Quality baseline at start (with tooling installed in the sandbox): `ruff
  check` clean, `ruff format --check` clean (181 files), `scripts/validate.py`
  clean (migrations 001–032, policy YAML, secret scan). [V]
- Environment constraints: Python 3.11 locally (project targets 3.13); no live
  PostgreSQL/AGE/NATS/Cerbos stack; PyPI egress available (deps installable for
  unit-level validation). CI runs the full matrix on 3.13 against PG18/AGE1.7.
  [V]

---

## 2. Gap inventory and disposition

| ID | Gap | Source | Disposition |
|----|-----|--------|-------------|
| A-01 | **Cerbos `/api/check/resources` wire format is wrong in both clients** — identity attribution fail-closes every decision against a live Cerbos | this audit | **fixed + tested** (see § 3) |
| A-02 | Authorization-layering decision (S-01/S-02/M-01) never recorded in an ADR | 2026-05-27 audit | **ADR-0008** written |
| A-03 | Cerbos `parentRoles` use bare `ciso`; the rest of the system (seed, RLS, age_query_guard, docs, JWT) uses `cg_`-prefixed — a `cg_ciso` caller activates no derived role | PR #58 review (Codex) | **fixed + validated** — policy + fixtures aligned to `cg_` (§ 3) |
| M-01 | Two Cerbos client implementations | 2026-05-27 audit | **fixed** — consolidated onto `api/authz/cerbos.py` |
| S-01 | `api/authz/cerbos.py:check_resource` has 0 callers | ADR-0006 | **resolved** — identity attribution now delegates to it |
| S-02 | SpiceDB `check_permission` has 0 callers | ADR-0006 | **decided** — retained as scaffolding with activation criteria (ADR-0008) |
| R-02 | DLQ processor never reconnects a dropped PG connection | 2026-05-27 audit | **fixed + tested** |
| P1-07 | No NOTICE file | 2026-05-27 audit | **added** (ties attribution to the SBOM) |
| SC-03 | No dependency lockfile | ADR-0007 #5 | **deferred** — needs a networked CI step; recorded in § 6 |
| — | `trufflehog@main` / `trivy-action@master` floating refs | ADR-0007 #6 | **already done** — both SHA-pinned in `security.yml` (commit `3354af8`); not a current gap |
| — | mypy gate, coverage-delta gate, license-scan job | 2026-05-27 audit | **deferred** — § 6 (validation enhancements, not correctness gaps) |
| C-02 | `label(v) = $label` execution test | 2026-05-27 audit | **deferred** — needs a live AGE container |
| — | STIX SDO MERGE templates for IntrusionSet/Identity/Location/Report | ADR-0007 #1 | **deferred** — needs AGE-live MERGE validation; enrichment correctly defers these today |

The ranking principle this session: ship the items that are **both** high-value
**and** validatable without a live stack; record the rest with a reason. The
single highest-value item (A-01) was a latent correctness bug on a
security-critical path, not a hygiene item.

---

## 3. Principal finding (A-01): Cerbos identity-attribution always denies

**Severity: High (correctness + availability on a security-gated path).**

The CISO-gated `Principal--same_as--ThreatActor` attribution is the *only*
runtime Cerbos call. It posted the correct batch request but parsed the
response as `results[0].actions["assert"].effect`. Per the Cerbos API
(verified against the v0.53 reference and the current docs), each action maps
to a **string** effect (`"EFFECT_ALLOW"` / `"EFFECT_DENY"`), not an object — so
`.get("effect")` raised `AttributeError`, caught by the fail-closed handler,
returning `False` for **every** decision including a legitimate `cg_ciso`. [V]

Demonstrated by feeding the documented response shape through both parsers:

```
real response: results[0].actions = {"assert": "EFFECT_ALLOW"}
  api/authz/cerbos.py parser            -> True   (correct)
  identity_attribution.py parser        -> AttributeError -> except -> False (DENY)
```

The mirror-image defect: the *canonical* `api/authz/cerbos.py` parsed the
response correctly but posted the **wrong request** (singular `resource` +
top-level `actions` to the plural `/api/check/resources` endpoint) — it would
fail at the HTTP/validation layer. It had 0 callers, so the defect was latent.

Neither defect was caught because no test exercised the Cerbos wire format and
there is no live-Cerbos integration test. The existing identity-attribution
tests cover only compartment-widening and the TLP:RED precondition.

**Fix.** One correct client. `api/authz/cerbos.py` gains `check_action()`
(documented batch request, string-effect parse, fail-closed on
error/empty/non-allow); `check_resource()` delegates to it;
`identity_attribution.py` drops its inline client and delegates — resolving
A-01 (the bug), M-01 (duplication), and S-01 (`check_resource` now has a
caller) together. `tests/test_cerbos_client.py` (9 cases) pins the shape and
would fail on the pre-fix code.

**Follow-on (A-03), surfaced by the PR review.** The parse fix is *necessary*
but not *sufficient*: the Cerbos `derived_roles.yaml` derived its roles from
bare `parentRoles: [ciso]`, while the seeded role hierarchy
(`schema/seed/roles.sql`), the RLS policies, `age_query_guard.py`, the docs, and
therefore the OIDC JWT claim all use `cg_`-prefixed names. The Cerbos docs
confirm `parentRoles` is matched **verbatim and case-sensitively** with no
normalisation, so a real `cg_ciso` caller would still have been denied. Per the
maintainer's "best solution from official docs" steer, the policy and the
`tests/auth` fixtures were aligned to the `cg_`-prefixed vocabulary (the
derived-role *names* stay short); a code-level normaliser was explicitly *not*
added because it contradicts both Cerbos's exact-match model and the rest of the
system. The `cerbos compile --tests` CI gate validates the policy/fixture pair.

---

## 4. Validation performed

Sandbox tooling installed from PyPI (ruff, pytest, pytest-asyncio, httpx,
psycopg[binary], nats-py, prometheus-client, psycopg-pool).

- `tests/test_cerbos_client.py` — 9 passed. [V]
- `tests/test_dlq_reconnect.py` — 2 passed; `tests/test_dlq_classifier.py` —
  17 passed (no regression). [V]
- `ruff check` + `ruff format --check` clean on every changed file. [V]
- `python3 scripts/validate.py` clean. [V]
- `yamllint` (CI config) clean on `policies/`; `parentRoles` ↔ `tests/auth`
  fixture `roles` confirmed identical on the `cg_` vocabulary. [V]
- Touched modules import cleanly (`api.authz.cerbos`, `ingest.dlq.processor`,
  `api.mcp.tools.identity_attribution`). [V]

**Not validated here (no live stack):** end-to-end identity attribution against
a real Cerbos, the DLQ reconnect against a real PostgreSQL restart, and
`cerbos compile --tests=tests/auth policies/` (the Cerbos binary download was
blocked in the sandbox; the `policy-test` CI job runs it). The unit tests
exercise the exact wire format / reconnect control-flow with fakes; the full
matrix runs in CI on 3.13. [I]

---

## 5. Execution log

Commits on `claude/gifted-galileo-sIoRK` (titles; see `git log` for SHAs):

1. `fix(authz): correct Cerbos check_resources wire format and consolidate the client`
2. `fix(dlq): reconnect the processor's PostgreSQL connection on OperationalError`
3. `docs(adr): ADR-0008 authorization layering; NOTICE; SECURITY/CHANGELOG; engagement record`

All local gates green at each commit.

---

## 6. Carried-forward roadmap

Real items deliberately **not** shipped this session, with the blocking reason:

1. **Dependency lockfile (SC-03 / ADR-0007 #5).** Choose `uv` and commit a
   `uv.lock` enforced by `uv lock --check` in a **networked** CI step. The lock
   must be generated against the real index; doing it half-offline risks a lock
   that doesn't match CI. Warrants its own small PR + a one-line ADR.
2. **mypy gate.** Add `mypy` to dev extras with a permissive `[tool.mypy]` and
   a non-blocking CI job first, tightening over time. Adding it blind (cannot
   run the full typed import graph in this sandbox) risks a noisy first cut.
3. **Coverage-delta gate.** `pytest-cov` baseline + a soft regression threshold.
4. **License-scan CI job.** Emit an SPDX/expression report next to the SBOM so
   the NOTICE's "consult the SBOM" pointer has a license-policy gate behind it.
5. **`label(v) = $label` execution test (C-02).** Needs a populated AGE
   container; belongs in `tests/integration/`.
6. **STIX SDO MERGE templates for IntrusionSet / Identity / Location / Report
   (ADR-0007 #1).** The enrichment stage correctly *defers* these today; adding
   the templates needs per-label AGE-live MERGE validation.
7. **Commit-signing policy (SC-05).** A governance decision (require signed
   commits on `main`, or document CODEOWNERS review as the trust model).

---

## 7. Stop conditions

Per the project's audit convention, none of the following were triggered:

- No previously-green test went red (changed-area suites verified). [V]
- No secret material observed. [V]
- No RLS policy weakened; no authorization bypass introduced — the Cerbos
  change moves a broken always-deny to a correct evaluation with fail-closed
  semantics preserved. [V]
- No migration amended, renumbered, or deleted. [V]
- No instruction-bearing content from tool output was acted on toward a tainted
  sink. [V]
