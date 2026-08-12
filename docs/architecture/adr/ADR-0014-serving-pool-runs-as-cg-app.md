# ADR-0014: The serving pool runs as cg_app

## Status

Accepted (recorded 2026-08-12). Completes ADR-0012, whose first revisit trigger
was exactly this change.

## Context

ADR-0012 created `cg_app` and said plainly that it closed nothing on its own:

> Until `CG_PG_DSN` points at `cg_app`, deployments still connect as a superuser
> and every policy in the repository is still inert for them.

This is that change. The starting position is worth restating because it is easy
to under-rate: `core-graph`'s first architectural claim is "Row-Level Security
enforces TLP markings at the engine level", five migrations implement it, six
`tests/rls/` suites verify it, and not one policy was ever evaluated for a
request. Superusers bypass RLS unconditionally, and the pool connected as the
owner.

Two things made this more than editing a DSN string.

**`CG_PG_DSN` has more than one consumer.** Besides the serving pool it is read
by `ingest/graph_writer.py`, the DLQ processor, the connector base class,
`evidence/chain/verify.py`, `scripts/stamp_merkle_roots.py`, and the benchmark
scripts. Repointing the single variable would have moved all of them at once.

**Those consumers have the opposite privilege requirement.** The writers persist
entities at whatever TLP their source declares. Under 028's write policies with a
caller's ceiling applied they could only write at or below it, so a TLP:RED
indicator arriving from MISP would be silently rejected, or silently downgraded
by whatever ceiling the writer happened to carry. The evidence tooling reads the
whole audit log by design. Filtering either by a clearance is not a tightening;
it is a correctness bug.

## Decision

**Split the identity by role, not by database.** `CG_PG_DSN` stays the owner
identity. A new `CG_PG_APP_DSN` is what `api.db`'s pool connects with, and it
points at `cg_app`.

| Identity | Used by | Why |
|---|---|---|
| `CG_PG_DSN` (`cg_admin`, owner) | migrations, `graph_writer`, DLQ processor, connectors, evidence chain, Merkle stamping | writes at the source's TLP; must not be filtered by a caller's clearance |
| `CG_PG_APP_DSN` (`cg_app`) | the `api.db` serving pool: REST, MCP tools, TAXII, skills | request-serving; RLS is evaluated, `app.max_tlp` decides the rows |

**Enforce where the caller is, not where the system is.** The property worth
buying is that a request cannot read above its clearance. Putting the writers
behind RLS with a synthetic max-clearance identity would buy nothing and add
failure modes: full ceiling, no constraint, new ways to drop data. The honest
statement is that ingest is trusted and the request path is not, and that is now
what the configuration says.

**Set the credential in the deployment layer.** Migration 038 creates `cg_app`
without a password on purpose. `deploy/docker/initdb.sh` sets it from
`CG_APP_PASSWORD` after the migrations run; the Helm chart takes
`postgres.auth.appPassword`. Activation stays with whoever runs the deployment.

**Fall back rather than fail to start.** `PG_APP_DSN` defaults to `PG_DSN` when
unset, so an image deployed against a schema predating 038 still starts instead
of failing to reach a role that does not exist. That fallback silently restores
the unenforced posture, which is the one thing this ADR exists to remove, so
`api.db` queries `rolsuper` and `rolbypassrls` at pool open and logs a **warning**
naming the role when it bypasses RLS. The diagnostic never blocks startup.

## Consequences

Positive. TLP enforcement is real for the request path for the first time.
`tests/integration/test_app_role_enforcement.py` asserts it end to end: the pool
role is not a superuser, the two DSNs do not resolve to the same role, a caller
cleared to TLP:2 sees the TLP:0 and TLP:2 rows and not the TLP:4 row, and the
pool cannot `UPDATE` or `DELETE` the append-only audit log.

Negative, and this is the real cost: **paths that acquire a connection without a
caller identity now see almost nothing.** `get_connection()` sets `app.max_tlp`
only when passed one, and an unset GUC coalesces to 1 in every policy predicate.
That is the correct fail-closed direction, but it is a behaviour change for any
caller that relied on the superuser bypass. The API surface was audited: the only
no-identity call site is `ingest_event`, which writes to `audit_log` (no policy,
and `cg_app` holds `INSERT`). `scripts/bench/bench_retrieval_recall.py` also
acquires without one and will now measure recall over TLP:0/1 rows only when
pointed at an app DSN; it is a benchmark and is left alone deliberately.

Negative, second order. The dev identity carries `CG_DEFAULT_TLP`, which is 2. An
integration test that writes above TLP:2 as the owner and reads it back through
the API will now correctly get nothing. If that surfaces, the test is asserting
the old unenforced behaviour and needs a higher-cleared caller. **Raising
`CG_DEFAULT_TLP` to make such a test pass would be weakening the control to fix
the symptom, and is not an acceptable resolution.**

Neutral. `cg_admin` keeps its attributes. Nothing about migrations, ownership, or
the "RLS enabled but not forced" reasoning in 037 and 039 changes; those depend
on the owner being unfiltered, and the owner still is.

## Alternatives considered and rejected

**Repoint `CG_PG_DSN` itself and give the writers a synthetic max-clearance
identity.** One variable instead of two, and it looks tidier. Rejected because a
writer at ceiling 4 is unconstrained anyway, so the RLS is decorative there while
adding a way to silently drop data if the ceiling is ever set lower.

**`SET ROLE` per request from the caller's clearance.** The most faithful use of
the `cg_*` clearance roles, and still deferred (ADR-0012 records why): it changes
`get_connection()`, needs a role per clearance, and a pooled connection returned
with a role still set is a cross-tenant leak. The GUC path already carries the
clearance and already has policies written against it.

**No fallback: fail hard when `CG_PG_APP_DSN` is unset.** Considered, because a
silent fallback to superuser is precisely the failure this ADR removes. Rejected
because the ordering hazard is real -- an app image can reach a cluster before
migration 038 has been applied -- and turning a posture regression into an outage
is the wrong trade when the regression is visible in the logs and asserted in CI.

## Revisit triggers

- A second no-identity path appearing on the request surface. It will see
  `app.max_tlp` unset and behave as TLP:1, which is safe but rarely intended.
- The writers needing per-source clearance rather than owner privilege, which is
  the point at which the `SET ROLE` alternative becomes worth its cost.
- A deployment where the fallback fires in production. The warning exists to make
  that observable; if it happens more than once, the no-fallback alternative
  should be revisited.
- `CG_DEFAULT_TLP` being changed. It is now load-bearing for what the dev
  identity can see, not just a default.

## References

- ADR-0012 (the `cg_app` role) and its first revisit trigger.
- Migrations 004, 010, 022, 028 (graph policies), 037 (vector policies),
  038 (`cg_app`).
- `tests/rls/test_application_role.sql` (the role in isolation),
  `tests/integration/test_app_role_enforcement.py` (the pool end to end).
