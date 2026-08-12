# ADR-0012: Non-superuser application role

## Status

Accepted (recorded 2026-08-12). Closes the first half of the gap recorded in
ADR-0011 and in the header of migration 037.

## Context

"Row-Level Security enforces TLP markings at the engine level" is the first
security claim in this repository's conventions, and four migrations implement
it: 004, 010, 022 and 028 create policies over `core_graph.*`, and 037 extended
them to the vector tier.

None of those policies is evaluated for the application's connection.

Three facts compose into that. The `cg_*` roles created by 004, 005 and 010 are
`NOLOGIN`, so they are grant targets rather than connection identities. Nothing
outside `tests/rls/` ever issues `SET ROLE`; `get_connection()` sets
`app.max_tlp` and `app.allowed_compartments` as GUCs and leaves the session role
alone. And `deploy/docker/docker-compose.yml` connects as `cg_admin`, which is
`POSTGRES_USER` in the official postgres image and therefore a superuser.
Superusers bypass row-level security unconditionally, `ENABLE` and `FORCE`
alike.

The `tests/rls/*.sql` suites pass, and they are not wrong. Each creates its own
non-superuser role and `SET ROLE`s to it, which establishes that the policies
are correct. It does not establish that the application ever reaches them, and
nothing in the repository did.

The remedy is smaller than the defect suggests. The policies key off the
`app.max_tlp` GUC rather than off the role, so no per-request `SET ROLE` is
needed and `get_connection()` does not change. The application needs one thing:
to stop being a superuser.

## Decision

**Create `cg_app`** (migration 038), a `LOGIN NOSUPERUSER NOBYPASSRLS` role with
`USAGE` on `public`, `ag_catalog` and `core_graph`, and table, sequence and
function grants across all three plus matching default privileges.

**Do not switch anything over in the same change.** The migration is purely
additive: nothing uses `cg_app` until a deployment points `CG_PG_DSN` at it.
Switching over is a change to the compose file and the CI environment, and it is
where grant-completeness gets proven, because the integration suite exercises
the real read and write paths. Separating the two means a missing grant surfaces
as a failing integration run against a role nothing depends on yet, rather than
as a broken deployment.

**No password in the migration.** A migration is the wrong place for a
credential, and a role created with a default one is worse than a role that
cannot yet connect. Setting the password is what activates the role, which
keeps activation and deployment in the same hands.

**Broad table grants, narrow row access.** `cg_app` gets
`SELECT, INSERT, UPDATE, DELETE` on every table in the three schemas, and RLS is
what constrains it. This is the model 004 already established: it grants `SELECT`
on every `core_graph` table to all seven clearance roles and lets the TLP policy
decide which rows each sees. Narrowing table grants instead would restate the
policy in a second place that can drift from it.

**Three carve-outs from that breadth.** `UPDATE` and `DELETE` on `audit_log`,
because the log is append-only (024) and the evidence chain rests on it; and
`INSERT`, `UPDATE`, `DELETE` on `ag_catalog.ag_graph` and `ag_catalog.ag_label`,
because writing AGE's registries is DDL by another name.

**No `CREATE` on any schema.** AGE creates a label's backing table on the first
`CREATE (n:Label)`, which a non-owner cannot do, and a `CREATE` grant would have
let it: the resulting table would be owned by `cg_app` with no policy attached,
which is exactly the hole migration 028 had to close by hand for the 009/023
labels. It does not arise. `ingest/graph_writer.py` resolves every label through
`MERGE_TEMPLATES` and returns `None` when there is no template, so an unknown
label from a message payload is logged and dropped before it reaches Cypher.
The templates cover only labels the migrations already create.

## Consequences

Positive. There is now a role the application can connect as under which its
policies bind. `tests/rls/test_application_role.sql` asserts that directly, and
it is the first suite here that grants itself nothing: everything it exercises
has to come from the migration. Its row-count assertion was checked against a
`BYPASSRLS` control and moves from 2 to 3, so it fails on the regression it
exists to catch rather than passing vacuously.

Negative. The gap is not closed yet, only made closable. Until `CG_PG_DSN`
points at `cg_app`, deployments still connect as a superuser and every policy in
the repository is still inert for them. Anyone reading 037 or this ADR as "TLP is
enforced" would be wrong. The migration header says so; this is the second place
it is said.

Neutral. The `cg_*` clearance roles are unchanged and remain `NOLOGIN`. `cg_app`
is not a member of any of them, so it holds no clearance-derived grant and is
subject to `tlp_read_policy` rather than to `ciso_full_access`.

## Alternatives considered and rejected

**`SET ROLE` per request from the caller identity.** Would map a caller's
clearance onto a `cg_*` role and let `ciso_full_access` and friends apply as
designed. Rejected for now on blast radius: it changes `get_connection()`, needs
a role for every clearance a caller can hold, and interacts with pooling, since a
connection returned to the pool with a role still set is a cross-tenant leak. The
GUC path already carries the clearance and already has policies written against
it. This stays available as a later refinement.

**Switching the compose file over in the same migration.** Rejected because a
missing grant would then surface as a broken dev stack, and because the
integration suite is the thing that proves the grant surface complete. Better to
land the role, then let CI fail against it.

**Revoking the superuser attribute from `cg_admin`.** Would fix the deployment
without a new role, and is wrong: `cg_admin` runs the migrations and owns the
schema. Migration 036's backfill reads `embeddings` and writes
`retrieval_embeddings`, which under a policied non-superuser owner would
silently copy only rows at or below TLP:1. This is the same reasoning that led
037 to enable RLS without forcing it.

## Revisit triggers

- The switch-over itself: `CG_PG_DSN` pointing at `cg_app` in
  `deploy/docker/docker-compose.yml` and in CI. Until then the gap stands.
- A producer being added for `embeddings`, which converts the TLP gap from
  latent to live (ADR-0011).
- A new migration creating tables outside `public`, `ag_catalog` and
  `core_graph`, which the schema loop in 038 would not cover.
- Any requirement that needs clearance-derived grants rather than GUC-derived
  row filtering, which is the `SET ROLE` alternative above.

## References

- ADR-0011, "Discovered while implementing: the vector path does not enforce
  TLP".
- Migration 037 header (the superuser finding), migration 038.
- `tests/rls/test_application_role.sql`.
