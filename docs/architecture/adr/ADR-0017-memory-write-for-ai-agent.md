# ADR-0017: Memory write for the AI agent

## Status

Accepted (recorded 2026-08-12). Closes ADR-0016's first revisit trigger by the
route that ADR named, and does not amend it.

## Context

Migration 041 made five clearances read-only, derived from the mutating actions
Cerbos grants. `ai_agent` fell into that set because Cerbos had no `memory`
resource at all — and absence is not denial when the tools in question never ask
Cerbos. The consequence, recorded in ADR-0016 rather than discovered later:
Layer 5 (migration 023) became unwritable by the role it exists for.

ADR-0016 refused to fix that inline:

> If a deployment does want agents writing Layer 5, the fix is a Cerbos policy
> for the memory resource that says so — making the decision explicit and
> reviewable — plus a grant. Not a silent exception in the migration, which
> would put the engine and the authorization model back out of step.

This is that route, taken in that order. The policy states the decision; the
grant derives from it. Written the other way round — grant first, policy
backfilled to match — it would have been the silent exception with extra steps.

## Decision

**`policies/resource/memory.yaml`** grants `ai_agent` `read`, `create` and
`update` on the `memory` resource; `ciso` keeps `*`; `soc_analyst` and
`compliance_officer` may `read`; everyone else is explicitly denied the mutating
actions.

The action names are `create` and `update` rather than something
memory-flavoured like `remember`, deliberately. ADR-0016 derives the database
write split by reading these files for actions in
`{*, create, update, delete, assert}`. An action outside that set would leave a
future re-derivation concluding that `ai_agent` still mutates nothing, and the
grant would look unjustified to the process that is supposed to justify it.

**Migration 042 grants `INSERT` and `UPDATE`** on exactly the objects 023
created — the eight AGE memory labels in `core_graph` and the three relational
shadow tables — and nothing else. Not "write": Cerbos grants `ai_agent` mutating
actions on `memory` and on no other resource, so the grant stops where the
policy does.

**No `DELETE`, for anyone but the CISO.** Memory is bitemporal: a superseded
fact keeps its row and gains a `t_superseded` stamp. Migration 020 enforces that
with a delete-block trigger and the project conventions state facts are
"invalidated, never deleted", so a `DELETE` grant would describe an operation
the model does not have. The Cerbos policy says the same.

**Two grants that do not follow from reading the tool code**, both from
`SECURITY INVOKER` functions in 023 that run with the caller's privileges:

- `memory_session_counters` needs `UPDATE` as well as `INSERT`, because
  `memory_next_sequence()` is an `insert … on conflict do update` and
  `memory_remember` calls it for every episode.
- `memory_extracted_fact_index` needs `UPDATE` as well as `INSERT`, because
  `trg_memory_supersession` is an `AFTER INSERT` trigger that updates the same
  table. An insert-only grant would let the insert begin and the trigger fail
  it.

## Consequences

Positive. Layer 5 works for the role it was built for, and the engine and the
authorization model agree about why. `ai_agent` is now the most precisely scoped
clearance in the system: it can write eleven memory objects and the audit log,
and nothing else — a tighter surface than `cg_app` itself.

Negative, and it is the honest cost of the scoping. **The grant is a list, and
lists go stale.** A future migration adding a memory label or shadow table will
not be covered, and the failure appears at runtime as `permission denied` rather
than in CI. That is a deliberate trade against the alternative — default
privileges, or a blanket schema grant — either of which would have re-widened
`ai_agent` beyond `memory` and undone 041. `tests/rls/test_readonly_clearances.sql`
asserts the boundary in both directions, so a *widening* is caught; a *narrowing*
gap is not, and cannot be without a list of what memory contains, which is the
same list.

Negative, second. **CI cannot catch an under-grant here.** The integration suite
runs with the dev identity (`roles: ["admin"]`), which falls through to `cg_app`
and never assumes a clearance, so no test exercises `cg_ai_agent`'s grants
end to end. The RLS suite checks the catalogue and the local verification
exercised the behaviour, but a memory write path that needs a privilege nobody
enumerated will surface in a deployment, not in a pull request.

Neutral. The other four read-only clearances from 041 are untouched, and the
Cerbos policy is not enforced at the application layer, because the memory tools
do not call Cerbos. Its role here is to state the decision and to be the thing
the grant derives from — the same role the other resource policies play for
migration 041.

## Alternatives considered and rejected

**Grant `cg_ai_agent` write broadly and rely on RLS.** Simple, and it discards
the property 041 bought: a policy is a predicate, and a predicate that is wrong
is a hole. The point of the scoping is that a bug in a memory policy cannot let
an agent write threat intelligence.

**Use `ALTER DEFAULT PRIVILEGES` so future memory tables are covered.** It
would fix the staleness above, and it cannot be scoped to a subset of a schema —
`core_graph` holds every AGE label, not just the memory ones — so it would grant
`ai_agent` write on every future graph label. Rejected as strictly worse than a
stale list.

**Wire the memory tools to Cerbos in the same change.** The policy is
declarative-only until something calls it, which is a real gap. Rejected as a
separate concern with a much larger blast radius: it changes three tool entry
points and their failure modes. Recorded as a revisit trigger.

**Leave Layer 5 unwritable and treat 041 as final.** Defensible if no deployment
runs agents that write memory. Rejected because the maintainer asked for the
opposite, and because ADR-0016 had already laid out this exact route.

## Revisit triggers

- A new memory label or shadow table. It will not be in 042's list, and the
  symptom is a runtime `permission denied` rather than a CI failure.
- The memory tools gaining a Cerbos check, which would make
  `policies/resource/memory.yaml` enforced rather than declarative and close the
  gap noted above.
- The dev identity being reconciled with the seven-role hierarchy (ADR-0015),
  after which the integration suite could exercise a real clearance and this
  ADR's second negative consequence would lift.
- Cerbos granting `ai_agent` a mutating action on another resource. The grant
  should follow, in that order.

## References

- ADR-0015 (clearance assumption), ADR-0016 (read-only clearances) and its
  first revisit trigger.
- `policies/resource/memory.yaml`, `tests/auth/cerbos_policies_test.yaml`.
- Migrations 020 (temporal invariants), 023 (the memory layer), 041, 042.
- `tests/rls/test_readonly_clearances.sql` section 4.
