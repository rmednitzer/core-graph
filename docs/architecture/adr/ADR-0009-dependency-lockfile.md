# ADR-0009: Dependency lockfile with uv

## Status

Accepted (recorded 2026-06-09). Closes ADR-0007 deferred item #5 / audit
SC-03, carried forward by the 2026-06-01 engagement (§ 6.2).

## Context

`pyproject.toml` deliberately declares loose version floors (`>=`) so Renovate
can propose upgrades, but nothing recorded which concrete versions a given
commit was tested against. A CI run and a production image built a week apart
could resolve different dependency trees from the same commit — unacceptable
for a platform whose evidence chain depends on reproducible builds, and the
gap was twice deferred because the lock "must be generated against the real
index" and earlier engagement sandboxes had no PyPI egress.

## Decision

- **`uv` is the lockfile tool.** A committed `uv.lock` (sha256-pinned,
  universal resolution for `requires-python >= 3.13`, so it also covers the
  3.14 CI runtime) records the resolved tree for every dependency group.
- **CI enforces sync, networked.** The `lockfile-check` job in `lint.yml`
  runs `uv lock --check` (uv pinned by version) against the real index on
  every PR; a `pyproject.toml` change without a matching lock update fails.
- **Renovate maintains it.** `lockFileMaintenance` was already enabled in
  `renovate.json5`; the pep621 manager updates `uv.lock` alongside its
  dependency PRs, so the lock stays current without manual churn.
- Version *floors* in `pyproject.toml` remain the human-reviewed contract;
  the lock is the reproducibility record, not a second place to manage
  constraints.

## Consequences

- Builds and CI runs of the same commit resolve identical dependency trees,
  and the SBOM/license tooling has a deterministic input.
- CI installs (`pip install '.[test]'`) still resolve from the floors; moving
  them to `uv sync --locked` is a possible follow-up once the lock has soaked,
  at which point the lock becomes enforcing for test environments too.
- Contributors changing dependencies must run `uv lock` (any platform — the
  resolution is universal) and commit the result.

## References

- ADR-0007 § Deferred roadmap #5; `audit/2026-06-01-engagement.md` § 6.2
- `renovate.json5` (`lockFileMaintenance`)
- uv lockfile docs: <https://docs.astral.sh/uv/concepts/projects/sync/>
