# ADR-0016: Read-only clearances

## Status

Accepted (recorded 2026-08-12). Closes ADR-0015's first revisit trigger, and is
the narrowing that ADR-0014 and ADR-0015 were each shaped to make possible.

## Context

ADR-0015 put the caller's clearance role in the request path, and deliberately
gave all seven clearances the same grants so that assumption could ship without
carrying a governance decision. That left the mechanism in place and the decision
open: which clearances may write?

Answering it is the point of the whole sequence. Migration 028 wrote TLP
INSERT/UPDATE/DELETE policies, and a policy is a predicate. A predicate that is
wrong is a hole; a missing `GRANT` is not. Until some clearance actually lacks
write, "this role is read-only" is a claim the engine cannot enforce.

## Decision

**Derive the split; do not invent it.** Two independent sources in this
repository already say who may mutate, and they agree exactly.

Cerbos (`policies/resource/*.yaml`), parsed for actions in
`{*, create, update, delete, assert}`:

| Role | Mutating actions allowed |
|---|---|
| `ciso` | `evidence_record:*`, `incident:*`, `threat_entity:*`, `identity_attribution:assert` |
| `soc_analyst` | `incident:update` |
| `compliance_officer` | none |
| `it_operations` | none |
| `dpo` | none |
| `external_auditor` | none |
| `ai_agent` | none |

`docs/architecture/authorization-model.md`, "Seven-role hierarchy", on purpose:

| Role | Purpose |
|---|---|
| `ciso` | "Full operational oversight" |
| `soc_analyst` | "Threat investigation and response" |
| `compliance_officer` | "Audit, compliance mapping, evidence review" |
| `it_operations` | "Infrastructure monitoring and alerting" |
| `dpo` | "Data protection duties, pseudonymisation oversight" |
| `external_auditor` | "Third-party audit with read-only, scoped access" |
| `ai_agent` | "Automated analysis via MCP, bounded scope" |

Every role Cerbos grants no mutating action is described in prose as review,
oversight, monitoring, audit or analysis. `external_auditor` is documented as
"read-only" in as many words. So migration 041 revokes `INSERT`, `UPDATE` and
`DELETE` from `cg_compliance_officer`, `cg_it_operations`, `cg_dpo`,
`cg_external_auditor` and `cg_ai_agent`, and leaves `cg_ciso` and
`cg_soc_analyst` alone.

**Revoke the default privileges too.** This is the half that would otherwise rot
quietly: migration 040 set default privileges granting write on tables created
*later*, so revoking only the current table grants would leave every read-only
clearance re-widened by the next migration that adds a table, with nothing to
notice it.

**Keep `INSERT` on `audit_log`.** Every audited tool writes an entry, so
revoking it would fail *every call* by a read-only caller rather than only its
writes. `UPDATE` and `DELETE` stay revoked (038, 040), so the log remains
append-only for them. The re-grant is a separate statement after the blanket
revoke, so the exception reads as an exception.

**Keep `SELECT`, sequence `USAGE` and function `EXECUTE`.** Functions here are
`SECURITY INVOKER`, so one that writes still fails on the table grant; revoking
`EXECUTE` would break reads for no gain.

**Add `cg_clearance_write_surface`**, a view reporting per clearance how many
tables it may insert, update or delete. Whether a clearance can write is now a
property of the database, and an auditor should be able to read it off without
reconstructing a migration.

## Consequences

Positive. Five clearances cannot write, whatever the RLS policies say and
whatever a future policy bug allows. That is a different kind of guarantee from
the one 028 provides, and it is the one that survives a mistake in a predicate.

Negative, and this is the one that will surprise. **The AI memory layer becomes
unwritable by `ai_agent`.** Layer 5 (migration 023) is the only graph-write path
reachable through the request pool, and an agent writing memory as `ai_agent`
will now get `permission denied`.

That is deliberate, on three grounds: Cerbos grants `ai_agent` no mutating action
on any resource; the memory tools do not consult Cerbos at all, so the absence of
a memory policy is not an implicit allow; and 023 attributes memory writes to
"application writers" rather than to a role. If a deployment does want agents
writing Layer 5, the fix is a Cerbos policy for the memory resource that says so,
making the decision explicit and reviewable, plus a grant. Not a silent exception
in the migration, which would put the engine and the authorization model back out
of step — the exact condition this ADR exists to end.

Neutral. `cg_app` is untouched; a caller whose role maps to no clearance still
falls through to it (ADR-0015) and still has the full surface. That is not a
bypass of this decision so much as its boundary: the fall-through is for callers
outside the hierarchy, and the hierarchy is what this ADR splits.

## Alternatives considered and rejected

**Leave `ai_agent` writable.** Tempting, because it is the role most likely to
have a live write path, and breaking a working feature is a real cost. Rejected
because the entire value of this migration is that the split is *derived*.
Carving out one role on my reading of what agents probably do would make the
result an opinion wearing the costume of a derivation, and would leave the engine
disagreeing with Cerbos in exactly the way ADR-0015 set out to fix.

**Revoke `EXECUTE` on functions from read-only roles.** Superficially tighter and
actually harmful: the functions are `SECURITY INVOKER`, so table grants already
constrain them, and revoking `EXECUTE` breaks read paths that call helpers.

**Revoke `INSERT` on `audit_log` as well, for a pure read-only role.** Rejected:
it fails every call rather than every write, and an unaudited read is worse than
an audited one.

**Encode the split in a policy instead of a grant.** That is what 028 already
does, and the reason this migration exists. A predicate can be wrong.

## Revisit triggers

- A Cerbos policy for the memory resource. That is the mechanism by which
  `ai_agent` (or any other clearance) should regain write, and the grant here
  should follow it rather than lead it.
- Any new clearance role. It lands with 040's default privileges, so it is
  read-write until 041's list is extended — the safe direction is to add it to
  the read-only list and grant back deliberately.
- A migration adding a table to a schema outside `public`, `ag_catalog` and
  `core_graph`, which neither 040 nor 041 covers.
- Cerbos gaining a mutating action for a role listed as read-only here. The two
  would then disagree, which is the condition this ADR removes; the grant should
  follow Cerbos.

## References

- ADR-0014 (the serving pool), ADR-0015 (clearance assumption) and its first
  revisit trigger.
- `policies/resource/*.yaml`, `docs/architecture/authorization-model.md`
  ("Seven-role hierarchy"), `schema/seed/roles.sql`.
- Migrations 028 (write policies), 038, 040, 041.
- `tests/rls/test_readonly_clearances.sql`.
