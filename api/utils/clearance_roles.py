"""Mapping from a caller's application roles to a PostgreSQL clearance role.

Two role namespaces exist in this repository and they are deliberately distinct
(ADR-0008 decision 5):

* the **application** roles the OIDC IdP emits in the JWT `roles` claim, bare:
  `ciso`, `soc_analyst`, ... These are what Cerbos matches on and what
  `age_query_guard` keys its depth and timeout tables by.
* the **database** roles the RLS GRANTs target, `cg_`-prefixed: `cg_ciso`,
  `cg_soc_analyst`, ... These are the roles `api.db` can `SET ROLE` to.

The mapping between them is exactly the `cg_` prefix, but it is written out
below rather than computed. A computed prefix would turn any string in the
`roles` claim into a database role name, and that string is attacker-influenced:
it arrives in a token. An explicit dict is the allowlist.

Nothing here touches the database. It is pure so the selection rule can be
tested without a stack.
"""

from __future__ import annotations

from typing import Any

# Ordered most- to least-privileged. The order is the selection rule, not
# decoration: a caller presenting several roles gets the most privileged one,
# matching how `age_query_guard.query_timeout_ms` already resolves multi-role
# callers ("most permissive role wins").
#
# The ranking follows the clearances seeded in schema/seed/roles.sql --
# ciso 4, soc_analyst 3, then the three at 2, external_auditor 1, dpo 0. The
# three-way tie at TLP:2 is broken here by an arbitrary but fixed order, so the
# resolution is at least deterministic; a caller holding two of them gets the
# same role on every request.
CLEARANCE_ROLES: tuple[tuple[str, str], ...] = (
    ("ciso", "cg_ciso"),
    ("soc_analyst", "cg_soc_analyst"),
    ("compliance_officer", "cg_compliance_officer"),
    ("it_operations", "cg_it_operations"),
    ("ai_agent", "cg_ai_agent"),
    ("external_auditor", "cg_external_auditor"),
    ("dpo", "cg_dpo"),
)

# Membership test for values that reach SQL. `api.db` interpolates the result of
# `database_role_for` into a `SET LOCAL ROLE` statement, because a role name
# cannot be a bind parameter. This set is what makes that safe: only a value
# that came out of the table above is ever interpolated.
DATABASE_ROLES: frozenset[str] = frozenset(db for _, db in CLEARANCE_ROLES)


def database_role_for(caller_identity: dict[str, Any] | None) -> str | None:
    """Return the database role for a caller, or None when nothing matches.

    None is the normal answer for two cases that are not errors:

    * no caller identity at all (a background or system path), and
    * a caller whose roles are outside the seven-role hierarchy -- the synthetic
      dev identity emits `admin`, which is deliberately not a clearance.

    Both fall through to the pool's own role, which is `cg_app`: still
    non-superuser, still subject to every policy, still constrained by
    `app.max_tlp`. That is the status quo before this mapping existed, so the
    fall-through loses defence in depth rather than enforcement.
    """
    if not caller_identity:
        return None

    roles = caller_identity.get("roles") or []
    if isinstance(roles, str):
        # A single role sent unwrapped. Tolerated rather than iterated as
        # characters, which would match nothing and silently fall through.
        roles = [roles]

    present = {r for r in roles if isinstance(r, str)}
    for app_role, db_role in CLEARANCE_ROLES:
        if app_role in present:
            return db_role
    return None
