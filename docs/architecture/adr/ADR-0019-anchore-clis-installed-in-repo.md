# ADR-0019: The Anchore CLIs are installed by this repository, not by their actions

## Status

Accepted (recorded 2026-08-12).

## Context

`anchore/sbom-action` and `anchore/scan-action` each bundle an installer that
downloads a release asset from github.com at job start. That installer has no
retry and no pinned digest, and the action exposes no input to change either
(its inputs are `path`, `file`, `image`, `registry-username`,
`registry-password`, `format`, `github-token`, `artifact-name`, `output-file`,
`syft-version`, `dependency-snapshot`, `upload-artifact`,
`upload-artifact-retention`, `upload-release-assets`, `config` — none of them
about caching, retry, or reusing an installed binary).

On 2026-08-12 a github.com degradation produced 503s across roughly two hours.
Three of this repository's jobs failed on that installer alone:

```
[command]/usr/bin/sh ... syft v1.42.3
[error] received HTTP status=503 for url='https://github.com/anchore/syft/releases/v1.42.3'
[error] do not specify a version or select a valid version
```

`sbom` failed twice on PR #115 and `docker-scan` failed on the merge commit
itself. The direct downloads in `lint.yml` and `test.yml` (kubeconform,
actionlint, cerbos) survived the same window, because #111 had already given
them `--retry 8 --retry-all-errors --retry-max-time 180`. The retry hardening
could not reach inside a vendor action.

The contrast within a single job is the clearest evidence. `docker-scan` runs
`aquasecurity/trivy-action` immediately before the Anchore step. Trivy passed:
it ships a `setup-trivy` step with an `actions/cache` layer and a pinned
install. Anchore's has neither, and failed six lines later.

## Decision

**Install syft and grype from this repository, via
`.github/actions/setup-anchore-cli`, and call the CLIs directly.**

The composite action does three things the vendor installer does not:

1. **Retries**, with the flag shape #111 established: no `--retry-delay`
   (which would disable exponential backoff), bounded so a real outage fails
   rather than hangs.
2. **Verifies a digest pinned in this repository** before extracting, rather
   than trusting whatever the release URL returns. This follows
   `.github/actions/setup-pg-age`, which pins `PGVECTOR_SHA256`, and the
   `actionlint` job, which pins `ACTIONLINT_SHA256` under the same rationale:
   build steps consume only checksum-pinned inputs. Verifying against a
   `checksums.txt` fetched from the same origin was considered and rejected --
   it catches truncation but not a compromised release, and we can do better
   by pinning.
3. **Caches the binary** by version, so a repeat run needs no network at all.

**The vulnerability database is deliberately not cached.** The binary is
version-pinned and therefore safe to cache; the CVE data is the one input that
must be current. `trivy-action` caches its database under a date-keyed key,
which is reasonable for its own tradeoff, but for a gate whose entire purpose
is detecting known vulnerabilities, a cached database buys seconds and risks a
false negative. grype re-fetches on every run.

**One syft invocation now renders both SBOM formats.** The previous form
invoked the action twice, scanning the tree twice; the two documents were
independent catalogues that could in principle disagree. `-o
cyclonedx-json=... -o spdx-json=...` renders one catalogue two ways.

## Consequences

Positive. The three jobs no longer fail on a transient github.com 5xx, and on
a cache hit they do not contact github.com at all. The installed bytes are now
checksum-verified, which they were not: the vendor installer accepted whatever
the release URL served.

**Negative, and the real cost: this repository now owns the syft and grype
version bumps.** The vendor action advanced its pinned default whenever it
released; we do not get that for free any more. Those two pins join
kubeconform, actionlint and cerbos as manually bumped tool versions.

That cost is bounded by what actually goes stale. grype's *vulnerability data*
is fetched fresh on every run, so a stale grype binary means stale matching
logic, not stale CVEs. A stale syft means slightly weaker package detection.
Neither is silent-failure-shaped, and neither is what the vendor action was
protecting us from.

Neutral. `permissions` are unchanged. The artifact names (`sbom.cyclonedx.json`,
`sbom.spdx.json`, `sbom-container.cyclonedx.json`) are unchanged, so
`cve-scan`'s `download-artifact` contract still holds. `--fail-on high` is the
CLI spelling of `severity-cutoff: high` plus `fail-build: true`.

## Alternatives considered and rejected

**Re-run the job and move on.** What was done twice on 2026-08-12, and correct
while an incident is in progress. Rejected as the standing answer: three
failures in one day on a step with no retry is a defect in the step, and each
re-run needs a human to notice.

**Seed the runner tool cache so the vendor action's `tc.find` skips the
download.** Keeps the action, adds resilience. Rejected: it depends on the
action's internal tool-cache layout, which is not part of its interface. If
Anchore changes it, the seeding silently stops working — a hardening measure
whose failure mode is invisible is worse than none.

**Add a third-party retry action around the step.** Rejected: it adds a
supply-chain dependency to remove a supply-chain fragility.

**Pin the version but verify against the published `checksums.txt`.** What
Anchore's own installer does. Rejected in favour of an in-repo digest, per the
existing convention above.

**Track the pins with a Renovate custom manager.** Would remove this ADR's main
negative. Deliberately not done here: the three tool pins that already exist in
this repository are manual, so automating one tool while leaving three behind
is the wrong shape. Worth doing once, for all five, as its own change.

## Revisit triggers

- Anchore adding a retry, cache, or skip-download input to their actions, which
  would make the vendor action the smaller thing to maintain again.
- Any of syft or grype falling far enough behind that detection quality
  measurably suffers -- the signal that the manual-bump cost has come due.
- A second repository needing the same composite action, which would argue for
  hoisting it somewhere shared rather than copying it. `ai-stack` and
  `aiops-mcp` carry the same exposure today.
- A runner that is not `Linux-x86_64`. The action refuses rather than
  installing a binary its pinned digest was never computed against.

## References

- #111 (the retry hardening this extends), `.github/actions/setup-pg-age`
  (the checksum-pinning convention it follows).
- `.github/actions/setup-anchore-cli`, `.github/workflows/security.yml`.
- Failing runs: 31630938666 (`sbom`, PR #115) and 31632531923 (`docker-scan`,
  merge commit 3e126ba).
