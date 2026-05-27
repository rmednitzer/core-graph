# Senior-Assurance Engagement: 2026-05-27

Repository: `rmednitzer/core-graph`
Working branch: `claude/keen-lamport-K5zYW`
Base: `main` @ `bfcb62e` (HEAD before engagement)
Engagement scope (Section 1 of spec): Broad — Phases 0-6 with stop-and-confirm for schema migrations, RLS/Cerbos/identity-attribution changes, secret material, force-push/history rewrites, repo settings.
Backlog sources: GitHub issues + open PRs + code TODOs + quality baseline gaps.
PR delivered: [#44](https://github.com/rmednitzer/core-graph/pull/44).

Evidence tags: `[V]` verified this session, `[I]` inference from premises, `[?]` unknown.

---

## 1. Phase 0 inventory snapshot (read-only)

State at engagement start (HEAD `bfcb62e`):

- 252 commits, 19 MB working tree, 1 MB `.git`. Contributors: Roman Mednitzer (214), copilot-swe-agent (23), dependabot (14), Claude (1). [V]
- 171 Python files / 15,685 LOC; 31 SQL migrations (001-026 + README); 20 Cypher templates; 5 ADRs (0002-0006); 4 GitHub workflows. [V]
- Quality baseline clean at start: ruff check + format + `scripts/validate.py` all pass; pytest 438 passed / 2 skipped on Python 3.12. [V]
- Governance baseline complete: LICENSE, SECURITY.md, CODE_OF_CONDUCT.md, CONTRIBUTING.md, CODEOWNERS, dependabot.yml, copilot-instructions.md, ISSUE_TEMPLATEs, pull_request_template.md. NOTICE absent (Apache-2.0 does not strictly require). [V]
- Backlog sources: 0 open issues, 0 open PRs, 1 source TODO marker (incidental, in `docs/operations/break-glass.md`). Backlog effectively driven by ADR-0006 gaps + Phase 2 audit findings. [V]

Delta at engagement end (HEAD `acd95e6`):
- 10 commits added on `claude/keen-lamport-K5zYW`. Tree size grew 19 MB → ~19.1 MB. Test count grew 438 → 440. No commits removed; no files deleted. [V]

---

## 2. Phase 1 backlog disposition

| ID | Title | Status | Notes |
|----|-------|--------|-------|
| P1-01 | Cerbos identity_attribution test fixture | **merged** in `fa89ff7` | Block already existed (since 2026-03-29). The actual gap was partial coverage (2 of 6 deny-roles). All 6 now covered. ADR-0006 § Gap 3 corrected. |
| P1-02 | Route `CG_OIDC_ENABLED` via `api.config` | **merged** in `3d0ccbd` (combined with S-04) | Folded into the OIDC fail-closed commit. |
| P1-03 | misp adapter → Config dataclass | **merged** in `07e5469` | Pattern matches netbox/keycloak/prometheus. |
| P1-04 | README compliance trim | **merged** in `f281207` | NIS2 + BSI only (docs/compliance/ truth). |
| P1-05 | Retroactive ADR-0001 | **merged** in `edaf9d7` | MADR-style, codifies the existing convention. |
| P1-06 | Pin trivy/trufflehog action SHAs | **dropped** per Phase 1 decision | Respects documented intentional choice in `dependabot.yml`. |
| P1-07 | NOTICE file | **deferred** | Gated on Phase 2 SBOM read confirming attribution-required deps. |
| P1-08 | Compartment RLS migration | **deferred** | Project-scale; candidate for dedicated engagement + ADR-0007. |
| P1-09 | SpiceDB request-path integration | **deferred** | Project-scale; candidate for dedicated engagement + ADR-0007. |
| P1-10 | Connector config dedup | **no action** | Documented as deliberate convention per ADR-0006. |
| P1-11 | Phase 2 deep audit | **executed** | 35 findings reported (see § 3). |

---

## 3. Phase 2 audit findings disposition

Per spec § 4. 0 critical, 3 high, 7 medium, 17 low, 8 info — total 35.

### High

| ID | Title | Disposition |
|----|-------|-------------|
| S-01 | Cerbos `check_resource` has 0 callers; reads enforce only RLS | **fixed by alignment** in `f014239` (SECURITY.md + ADR-0006 follow-up). Per maintainer's Phase 2 choice, docs aligned with runtime rather than wiring Cerbos into read paths. |
| S-02 | SpiceDB `check_permission` has 0 callers | **accepted-risk** — ADR-0006 already records this; tracked as P1-09 / future ADR-0007. |
| SC-01 (was medium then re-noted) | GitHub Actions floating refs `@master`/`@main` for trivy & trufflehog | **accepted-risk** — documented intentional choice (`dependabot.yml` comment block). Phase 1 P1-06 dropped per user decision. |

### Medium

| ID | Title | Disposition |
|----|-------|-------------|
| S-03 | MCP tool wrappers drop `caller_identity` | **fixed by docs** in `b05dedf` (api/mcp/server.py docstring + docs/skills/README.md). Trust model codified as "trusted-internal". |
| S-04 | OIDC default-off + synthetic admin in dev mode | **fixed** in `3d0ccbd`. `CG_OIDC_ENABLED` default flipped to `true`; `CG_DEV_MODE` added as explicit opt-in for synthetic dev identity; misconfigured deployments fail closed with 503. |
| M-01 | Two duplicate Cerbos client implementations | **deferred** — tied to S-01 outcome; revisit in ADR-0007. |
| M-02 | Silent `max_tlp` widening in `_widen_compartments` | **fixed** in `773cd62`. Precondition `max_tlp == 4` now enforced in `assert_identity_attribution`; silent widening removed; 2 async precondition tests added. |
| SC-01 | GitHub Actions floating refs | (see High above; same finding listed twice was an accounting error) |
| SC-05 | 70% of commits unsigned | **deferred** — signing policy decision needed; raise in follow-up. |
| G-01 | SECURITY.md three-layer claim vs runtime | **fixed** in `f014239` (same change as S-01). |

### Low (selected resolutions)

| ID | Title | Disposition |
|----|-------|-------------|
| C-01 | 44 `except Exception:` handlers | **accepted-risk** — sample triage shows most are intentional bounding around external I/O with `logger.exception`. Skill-discovery silent-skip flagged in evidence pack for follow-up. |
| C-02 | `label(v) = $label` execution test | **deferred** — depends on running AGE container. Integration test gap; templates likely functional (AGE 1.5+ `label()` returns agtype text, comparable to string parameter). |
| P1-01-correction | ADR-0006 Gap 3 inaccuracy | **fixed** in `fa89ff7` follow-up section. |
| P1-03 | misp module-level os.environ | **fixed** in `07e5469`. |
| P1-04 | README compliance claim drift | **fixed** in `f281207`. |
| P1-05 | ADR numbering starts at 0002 | **fixed** in `edaf9d7`. |
| M-03 | Empty `policies/principal_policies/` | **no action** — `.gitkeep` already present; Phase 0 `ls` missed the dotfile. |
| R-01 | DLQ retry backoff has no jitter | **fixed** in `7caf71a`. Full jitter, citing AWS Architecture Blog (Brooker, 2015). |
| R-02 | DLQ persistent connection no-reconnect | **deferred** — original "use shared pool" framing was wrong (DLQ is a worker, not a request handler). Real gap is reconnect-on-disconnect; carry into follow-up. |
| R-03 | opencti `httpx.Timeout(None)` | **accepted-risk** — documented with `# noqa: S113`; carry into evidence pack. |
| SC-02 | pgvector tarball not SHA-pinned | **fixed** in `acd95e6`. SHA-256 captured 2026-05-27. |
| SC-03 | No lockfile | **deferred** — requires ADR for tool choice (pip-compile / uv / poetry). |
| S-05 | Semgrep oidc.py:123 logger flag | **deferred** — likely false positive; carry into evidence pack with a note to add `# nosemgrep` only if the rule actually fires in CI. |
| S-07 | Full trufflehog (unverified) scan deferred | **deferred** — tool not installed in audit env; CI runs `--only-verified`. Recommend a one-time unverified run. |

### Info

All info-tagged findings are positive observations (RLS session-var hygiene, Merkle implementation correctness, pip-audit/osv-scanner clean, etc.) and require no action. Listed in `evidence/phase2-findings.md` (this file).

---

## 4. Phase 3 cross-check map (compact)

| Action | Authoritative source | Tag |
|--------|---------------------|-----|
| `f014239` G-01 doc alignment | OWASP ASVS V14 "Configuration"; NIST SSDF PS.2; project ADR-0006 framework | [I] |
| `3d0ccbd` OIDC fail-closed | OWASP Top 10 2021 A05; OWASP ASVS V14.1.1; 12-Factor App § Config | [V] |
| `b05dedf` MCP trust note | modelcontextprotocol.io transport security assumptions | [V] |
| `fa89ff7` Cerbos test fixture | cerbos.dev/docs/policies/compile/#testing — YAML test schema | [V] |
| `edaf9d7` ADR-0001 form | adr.github.io / MADR template / Nygard 2011 | [V] |
| `7caf71a` DLQ jitter | AWS Architecture Blog "Exponential Backoff and Jitter" (Brooker, 2015); Google SRE Book § 25.3 | [V] |
| `acd95e6` pgvector SHA pin | SLSA v1.2 Build Track L3 "checksum-pinned inputs" | [V] |
| `773cd62` explicit widen contract | Principle of least surprise; project bitemporal/RLS invariants framework | [I] |
| `07e5469` misp Config dataclass | ADR-0006 § "deliberate convention"; Pydantic BaseModel pattern | [V] |

---

## 5. Phase 4 validation gate changes

**Gates added or strengthened in this engagement:**

- `tests/auth/cerbos_policies_test.yaml` — coverage of identity_attribution policy widened from 2 to 6 deny-roles. CI `policy-test` job runs `cerbos compile --tests=tests/auth policies/` and will fail if any new fixture fails.
- `tests/test_identity_attribution_compartments.py` — new `TestAssertIdentityAttributionPrecondition` class with 2 async tests verifying the TLP:RED precondition raises before any Cerbos / DB call.
- `tests/taxii/conftest.py` (new) — autouse fixture patches `OIDC_ENABLED=False` + `DEV_MODE=True` for the TAXII test suite. Existing TAXII tests now run cleanly against the new fail-closed OIDC default.
- `.github/actions/setup-pg-age/action.yml` — pgvector v0.8.0 tarball now SHA-256 verified before extraction. Build fails immediately on integrity mismatch.

**Local gate (must pass before every push):**

```
ruff check .                            # 0
ruff format --check .                   # 0
python3 scripts/validate.py             # 0
pytest -m "not integration"             # 0; expected 440 passed, 2 skipped
```

Documented in PR #44 description and verified after every commit in this engagement.

**Known validation gaps (recorded, not blockers):** no mypy gate, no coverage-delta gate, no mutation testing, no automated license scan. These are candidate validation enhancements for a future engagement.

---

## 6. Phase 5 execution log

10 commits on `claude/keen-lamport-K5zYW`. One PR ([#44](https://github.com/rmednitzer/core-graph/pull/44)).

| # | SHA | Title | Findings | Local gate |
|---|-----|-------|----------|------------|
| 1 | `f014239` | docs: align authz claims in SECURITY.md with runtime enforcement | S-01, G-01 | 438+2 |
| 2 | `3d0ccbd` | fix(auth): make OIDC default fail-closed; require CG_DEV_MODE opt-in | S-04, P1-02 | 438+2 |
| 3 | `b05dedf` | docs: codify MCP trusted-internal trust model | S-03 | 438+2 |
| 4 | `fa89ff7` | test(auth): complete identity_attribution Cerbos deny-role coverage | P1-01, ADR-0006 Gap 3 correction | 438+2 |
| 5 | `f281207` | docs: trim README compliance claim to match docs/compliance/ | P1-04 | 438+2 |
| 6 | `edaf9d7` | docs: ADR-0001 establish ADR practice (retroactive) | P1-05 | 438+2 |
| 7 | `07e5469` | refactor(misp): centralize env reads in MispConfig dataclass | P1-03 | 438+2 |
| 8 | `773cd62` | fix(authz): require TLP:RED caller in assert_identity_attribution | M-02 | 440+2 |
| 9 | `7caf71a` | fix(dlq): add full jitter to retry backoff to defuse thundering herd | R-01 | 440+2 |
| 10 | `acd95e6` | ci: SHA-256 pin pgvector tarball in setup-pg-age action | SC-02 | 440+2 |

PR #44 created 2026-05-27, base `main`, head `claude/keen-lamport-K5zYW`. CI status at end of engagement: in-flight (subscribed to webhook events). CODEOWNERS review pending (`@rmednitzer`).

---

## 7. Outstanding risks & recommended next steps

**Recommended for next engagement / future PRs:**

1. **R-02 — DLQ reconnect-on-disconnect.** Add try/except around the per-message connection use; reconnect on `psycopg.OperationalError`. Small change, defensive. Original Phase 2 framing of "use shared pool" was incorrect (DLQ is a worker; the per-connector pattern is correct).
2. **SC-03 — lockfile.** Choose between `pip-compile`, `uv pip compile`, `poetry lock`. Add an ADR. Commit a lockfile. Adds reproducibility for builds + CVE scans.
3. **SC-05 — commit signing policy.** Today 70% of commits are unsigned. Either (a) require signed commits on `main` via branch protection + retroactively configure an `allowed_signers` file for SSH-signed commits; or (b) document that PR review via CODEOWNERS is the trust model and signing is optional.
4. **C-02 — `label(v) = $label` execution test.** Add an integration test in `tests/integration/` that calls `cypher_query("count_entities_by_label", {"label": "Host"})` against a populated AGE container. Closes a real coverage gap.
5. **ADR-0007 — Authz layering decision.** Document whether the project commits to actually invoking Cerbos / SpiceDB on read paths or whether RLS-only is the accepted runtime model. Resolves S-01, S-02, M-01 in a single document.
6. **NOTICE file (P1-07).** Run `pip-licenses --format=json` against the production dep set (no test extras); add `NOTICE` if any deps require attribution beyond the LICENSE file.
7. **Full unverified trufflehog scan (S-07).** One-time local run without `--only-verified`. CI scans verified-only on every PR; an unverified scan catches dormant candidates worth manual review.
8. **`mypy` gate.** Not configured. Add `mypy>=1.10` to dev extras; `[tool.mypy]` block in `pyproject.toml` with `strict = true` (start permissive, tighten progressively).
9. **Coverage-delta gate.** Add `pytest-cov` to test extras; record baseline; fail PRs that decrease coverage by more than a small threshold.
10. **License scan.** Add to `security.yml` workflow; produces an audit artefact next to SBOM.

**Operational notes for the maintainer (post-merge):**

- After merging #44, any existing dev workflow that relied on the `CG_OIDC_ENABLED=false` default will need to set `CG_DEV_MODE=true` explicitly. Document in `README.md § Quick start` if not already.
- The OIDC fail-closed change is a backwards-incompatible behavior change for misconfigured deployments. Recommend a CHANGELOG entry (Unreleased → Breaking) before tagging the next version.
- The pgvector SHA pin will need updating whenever the action upgrades pgvector. Bump the `PGVECTOR_TAG` and `PGVECTOR_SHA256` together in the action file.

---

## 8. Stop conditions audit

Per spec § 9. None of the following were triggered during this engagement:

- No previously-green test went red. [V]
- No secret material observed in repo or history. [V]
- No CISA KEV-tagged unfixed dep in current dep set (pip-audit + osv-scanner clean). [V]
- No prior-unauthorized-commit residue. [V]
- No instruction-bearing content in tool outputs that aimed at a tainted sink. [V]
- No tooling unavailable that lowered confidence below 70 for the next planned action (one false positive on local validate.py walking the audit venv — resolved by moving venv to `/tmp/`; no actual gap). [V]

---

## 9. Engagement timing

- Start: 2026-05-27 (Phase 0 inventory began after scope clarification via `AskUserQuestion`).
- Phase 0 inventory: 1 round of reads + scanner setup.
- Phase 1 triage: 1 round of decisions via `AskUserQuestion`.
- Phase 2 audit: 1 round of reads + scanners (semgrep, pip-audit, osv-scanner) + 2 Explore subagent investigations (authz surface, Cypher safety).
- Phase 3 cross-check: 1 mapping table.
- Phase 4 validation gate: 1 contract definition.
- Phase 5 execution: 10 commits, all gates green at each commit.
- Phase 6 evidence pack: this document.

Total turn count: ~40 turns. Total tool calls: ~120 (mostly parallel batches).

---

## 10. Artefacts

Stored under `audit/2026-05-27/evidence/`:
- (none committed in this run — all evidence captured inline in this report and in the commit log of `claude/keen-lamport-K5zYW`).

To preserve specific tool outputs (semgrep findings, pip-audit JSON, osv-scanner output) as separate evidence files, add them to `audit/2026-05-27/evidence/` in a follow-up commit. Not done in this engagement because all material findings are reproducible by re-running the same commands listed in § 5 above.
