# ADR-0015: Clearance-role assumption per request

## Status

Accepted (recorded 2026-08-12). Implements the alternative ADR-0012 and ADR-0014
both deferred, and closes ADR-0014's second revisit trigger.

## Context

ADR-0014 pointed the serving pool at `cg_app`, which made the TLP policies real
for the first time. It left enforcement resting on a single mechanism: every
policy in the repository reads `app.max_tlp`, a GUC the application sets from the
caller's clearance. One missed `set_config` and a request is unfiltered in the
only direction that matters — though fail-closed, since an unset GUC coalesces
to 1.

Meanwhile the seven clearance roles created by migrations 004, 010 and 033 were
inert in a different way from the policies. They existed, they held `SELECT` on
`core_graph.*`, and nothing ever connected or switched to them. Two consequences:

- the role-targeted policies (`ciso_full_access`, `ciso_full_write`) could never
  match, because the connecting role was never `cg_ciso`;
- the roles' own table grants sat between nothing and nothing, so the only thing
  standing between a request and a write was a policy predicate.

ADR-0014 named the blockers: it changes `get_connection()`, needs a role per
clearance, and "a pooled connection returned with a role still set is a
cross-tenant leak."

Implementing it surfaced a fourth, larger than the other three. **`cg_app` is
`NOINHERIT`**, so assuming a clearance role drops everything `cg_app` holds:
`INSERT` on `audit_log`, `USAGE` on `ag_catalog`, the sequences, the functions.
And migration 028 added write *policies* but no write *grants* — its own comment
says they "bite only if a non-superuser role is granted" write. A request that
wrote anything would have failed on privilege long before reaching a policy.

## Decision

**Assume, do not inherit.** Migration 040 grants each clearance role to `cg_app`
`with inherit false, set true`. `cg_app` may `SET ROLE` to a clearance but holds
none of its privileges passively; a query issued as `cg_app` is checked against
`cg_app`'s own grants, never the union of seven roles.

Stated explicitly rather than relying on `cg_app`'s `NOINHERIT` default, so a
later `ALTER ROLE cg_app INHERIT` cannot silently widen every membership at once.
Verified: with the membership in place, `cg_app` selecting a table granted only
to `cg_ciso` gets `permission denied`, and the same select after `SET ROLE
cg_ciso` succeeds as `cg_ciso`.

**`SET LOCAL ROLE`, not `SET ROLE`.** The role reverts when the transaction ends,
which the pool's context manager does on the way out. This is the primary defence
against the leak ADR-0014 called out, not an afterthought. Two more sit behind
it: `get_connection` issues `RESET ROLE` in its `finally`, and the pool now has a
`reset` hook running `RESET ROLE; RESET ALL` before a connection re-enters the
pool. psycopg_pool discards a connection whose reset raises, which is the right
outcome — losing a connection is cheaper than reusing a dirty one.

**An allowlist, not a prefix.** `api/utils/clearance_roles.py` maps the bare
application roles the IdP emits to the `cg_`-prefixed database roles. The mapping
is exactly the prefix but is written out, because the input is attacker-influenced
— it arrives in a token — and a computed prefix would turn any string in the
`roles` claim into a role name. The role is interpolated into `SET LOCAL ROLE`
(a role name cannot be a bind parameter), guarded by a membership check against
the same table.

**Most-privileged role wins**, by a fixed order matching the clearances seeded in
`schema/seed/roles.sql`. Consistent with how `query_timeout_ms` already resolves
a multi-role caller, and order-independent, so the same caller gets the same role
on every request.

**Unmapped callers fall through to `cg_app`,** logged, rather than being refused.
The synthetic dev identity emits `admin`, which is deliberately not a clearance.
The fall-through is the pre-040 posture: still non-superuser, still policy-bound,
still filtered by `app.max_tlp`. It loses defence in depth, not enforcement.

**All seven roles get the same grants, for now.** Migration 040 mirrors `cg_app`'s
surface onto each, including the two carve-outs (no `UPDATE`/`DELETE` on
`audit_log`, no writes to AGE's registries) — otherwise those carve-outs would be
sidestepped by assuming any clearance, which every request can do.

Behaviour-preserving on purpose. Which clearances *should* be read-only is a real
decision — an external auditor arguably should never write, whatever the policies
say — and it belongs in its own change, as a narrowing, once someone has made it.
Nothing widens: every one of these roles is reachable only by a caller that could
already reach `cg_app`, and `cg_app` already holds this exact surface.

## Consequences

Positive. Enforcement no longer rests on one GUC. A request now runs as an
identity whose table grants are checked before any policy is consulted, which is
what makes a future read-only clearance meaningful rather than advisory.
`current_user` in the database reflects the caller's clearance, so audit and
`pg_stat_activity` say who a query was for.

Negative. `ciso_full_access` starts matching, so a CISO's reads OR past
`tlp_read_policy` instead of being filtered by `app.max_tlp`. The seeded CISO
clearance is 4, which already saw everything, so the effect today is nil — but it
is a genuine widening of the *mechanism*, and `tests/rls/test_clearance_roles.sql`
asserts it deliberately so that removing the policy is a visible change rather
than a silent one. The IAM floor from 010 is unaffected: it is `RESTRICTIVE` and
keyed on the GUC, so it still `AND`s for `cg_ciso`.

Negative, second. `cg_app` can now assume `cg_ciso`, so anyone who can influence
the `roles` claim can reach full clearance. That was already true of `max_tlp`,
which the same claim set drives, so this widens an existing trust in the token
rather than creating a new one — but it does widen it, and it is the reason the
mapping is an allowlist rather than a prefix.

Neutral. Nothing changes for the owner identity. Migrations, `graph_writer`, the
DLQ processor, the connectors and the evidence tooling still connect as
`cg_admin` and are unaffected by any of this (ADR-0014).

## Alternatives considered and rejected

**Keep the GUC as the only mechanism.** The status quo, and defensible: it
already enforces TLP. Rejected because a single mechanism with no grant-level
backstop makes every future "this role is read-only" claim unenforceable, and
because the clearance roles were otherwise dead weight in five migrations.

**`SET ROLE` with `RESET ROLE` in a `finally`.** Simpler to read and one fault
away from a cross-caller leak: an exception between `SET` and the reset, or a
connection returned by a path that does not run the `finally`, hands the next
borrower a clearance. `SET LOCAL` makes the database enforce the scope.

**Refuse requests whose role maps to nothing.** The strictest reading, and it
would make the mapping load-bearing. Rejected because it breaks `CG_DEV_MODE`
and the entire integration suite until the dev identity changes, and because the
fall-through is not an escalation — it is the posture ADR-0014 shipped.

**Split read-only and read-write clearances in this migration.** The substantive
prize, and deliberately not taken here. See the decision above.

## Revisit triggers

- A decision on which clearances are read-only. That is the narrowing migration
  this one is shaped to make possible.
- The dev identity's `admin` role being reconciled with the seven-role hierarchy,
  which is tracked separately (ADR-0008 decision 5, audit A-03). At that point
  the fall-through stops being exercised in CI and refusing unmapped callers
  becomes affordable.
- A caller path that acquires a connection and commits mid-request. `SET LOCAL`
  reverts at that commit, so the remainder runs as `cg_app` — fail-closed, but
  surprising. No such path exists today on the request surface.
- `cg_app` ever being made `INHERIT`, which the explicit `inherit false` on each
  membership is there to survive.

## References

- ADR-0012 (the `cg_app` role), ADR-0014 (the serving pool), ADR-0008 decision 5
  (the two role namespaces).
- Migrations 004, 010, 028, 033 (the clearance roles and their policies),
  038, 040.
- `api/utils/clearance_roles.py`, `tests/test_clearance_roles.py`,
  `tests/rls/test_clearance_roles.sql`,
  `tests/integration/test_app_role_enforcement.py`.
