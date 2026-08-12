# ADR-0018: The memory tools consult Cerbos

## Status

Accepted (recorded 2026-08-12). Closes the gap ADR-0017 recorded as its own
second revisit trigger.

## Context

ADR-0017 added `policies/resource/memory.yaml` and derived migration 042's grant
from it, and was explicit that the policy was declarative only:

> the Cerbos policy is not enforced at the application layer, because the memory
> tools do not call Cerbos. Its role here is to state the decision and to be the
> thing the grant derives from.

That left the authorization model split across two layers that could not
disagree visibly. The database enforced *which tables* a clearance may write;
nothing enforced *which actions* a caller may take. A caller with a clearance
that permits memory writes could call any memory tool, and a caller with no
role at all could call every one of them — `tool_remember` accepted
`caller_identity={"max_tlp": 4}` and wrote an episode.

Migration 041 and 042 constrained that at the grant level, which is a real
backstop but the wrong shape for the question: "may this caller record a fact?"
is not answered by "which tables can this role write?".

## Decision

**All four memory entry points call Cerbos before doing anything else.**
`tool_remember` and `tool_record_extracted_fact` check `create`; `tool_recall`
and `tool_session_start` check `read`. `tool_session_start` is a read despite
its name — it only selects; it is named for the caller's workflow, not because
it writes a session.

**`create` for `tool_record_extracted_fact`, not `update`**, even though the
supersession trigger updates the previous fact's row. What the caller is
authorized to do is record a fact; the update is the model's bookkeeping, not a
second operation the caller chose.

**Before the connection, not after.** The check runs ahead of `get_connection`
and, in `tool_recall`, ahead of `hybrid_search`. A denial should cost a policy
round-trip rather than a pooled connection and a half-built episode. The tests
enforce this rather than trusting it: the denial-path tests replace
`get_connection` and `hybrid_search` with functions that raise a distinctive
`AssertionError`, so a tool that authorized too late fails loudly instead of
passing.

**A raising helper, not a boolean.** `api.authz.cerbos.require_caller_action`
raises `PermissionError` rather than returning a bool, because the alternative
is one forgotten `if` away from a tool that checks authorization and proceeds
regardless. Four call sites made that risk worth removing.

**`principal_from_caller` is shared.** MCP tools receive a plain dict rather
than the REST layer's typed `CallerIdentity`, and each was assembling the Cerbos
principal by hand. `identity_attribution` now uses it too, keeping its own
message and its own bool-returning wrapper — refactoring its call shape as well
would have widened this change across a working, security-critical path for
cosmetic gain.

## Consequences

Positive. `policies/resource/memory.yaml` is now load-bearing rather than
documentation. The two layers can no longer silently disagree: an authorization
change lands in the policy and both the grant (via ADR-0016's derivation) and
the runtime check follow from it.

**Breaking, and worth stating first: a caller that presents no roles is now
denied.** `principal_from_caller` builds a principal with an empty role list,
which every resource policy denies. That is the intended reading — authorization
is decided by role, so a caller that presents none has not established one — but
until now the memory tools accepted exactly that shape, and
`tests/integration/test_memory_edge_tlp.py` was written that way. Any caller
passing only `max_tlp` will start receiving `PermissionError`.

Positive, and a genuine surprise from the change. Giving that integration test a
real role (`ai_agent`) makes it **the first integration test to exercise a
clearance end to end**: `get_connection` now assumes `cg_ai_agent`, so its writes
run against migration 042's grants rather than `cg_app`'s. ADR-0017 recorded as a
limitation that "CI cannot catch an under-grant here, because the integration
suite runs as the dev identity". For the memory path, that is no longer true.

Negative. **Memory stops working when Cerbos is unreachable.** `check_action`
fails closed on any transport error, so an outage denies rather than admits.
That matches `identity_attribution` and is the right direction, but it moves
Cerbos onto the critical path for Layer 5, which it was not on before.

Neutral. The policy's `read` rules for `soc_analyst` and `compliance_officer`
become enforced, which they were not; nothing else about the policy changes.

## Discovered by wiring it: every Cerbos check was already failing closed

Not caused by this change, and found the moment it landed. The integration test
denied a caller that should have been allowed:

```
PermissionError: Denied by Cerbos policy: create on memory. Caller roles: ['ai_agent'].
ERROR api.authz.cerbos: Cerbos check failed for memory/create, denying by default
httpx.RemoteProtocolError: illegal request line
```

The role was right and the policy was right. Cerbos never returned a verdict:
`CG_CERBOS_ENDPOINT` defaulted to `http://localhost:3593`, which is Cerbos's
**gRPC** listener. Its HTTP listener is 3592, and the Cerbos SDK vendored in this
repository states both (`cerbos.sdk.container.HTTP_PORT` / `GRPC_PORT`). Posting
HTTP at a gRPC port produces exactly that `illegal request line`, and
`check_action` fails closed on any transport error, so it became a denial.

**That has been true since `api/authz/cerbos.py` was written.** Every Cerbos
decision in this repository was a silent denial. `identity_attribution` -- the
only other caller, and the tool that gates `Principal--same_as--ThreatActor`
edges behind the CISO role -- would have denied a legitimate CISO.

It stayed invisible for the same reason ADR-0016's `ai_agent` problem did:
nothing on a CI-exercised path called Cerbos. `identity_attribution` requires the
`ciso` role and has no integration test, so the failure had nowhere to surface.
Putting a Cerbos call on a path the integration suite runs surfaced it in the
first run.

Fixed here: the default becomes `http://localhost:3592`, the compose stack
publishes 3592 alongside 3593, and `tests/test_cerbos_client.py` asserts the
configured endpoint is not the gRPC port. The real regression test is the
integration test itself, which now exercises a Cerbos decision end to end.

Worth noting what this says about fail-closed defaults. `check_action` denying
on transport error is correct, and it is also what hid a total misconfiguration
for the lifetime of the client: a control that denies everything looks identical
to a control that is working, from the outside. The lesson is not to fail open;
it is that a fail-closed control needs a positive test -- one that asserts an
*allowed* action is allowed -- and this repository had none.

## Alternatives considered and rejected

**Skip the check when OIDC is disabled.** It would have kept the integration
test working untouched. Rejected outright: a security control that turns itself
off in the configuration used for development and CI is a control that has never
been tested in the state it ships in.

**Map the dev identity's `admin` role to a clearance.** Would fix the same
problem more broadly and belongs to the tracked reconciliation of the two role
namespaces (ADR-0008 decision 5), not to this change. Wiring `admin` to a
clearance here would prejudge that.

**Check inside `get_connection` for every tool.** Tempting — one place, no
forgotten call sites — and wrong: the resource kind and action are properties of
the tool, not of the connection, and a generic check would have to invent them.

**Refactor `identity_attribution` fully onto `require_caller_action`.** Its
message is more specific than the generic one and its wrapper is well covered.
Reduced to sharing `principal_from_caller`, which removes the duplication that
mattered.

## Revisit triggers

- Any new memory tool. It needs its own check; nothing enforces that structurally
  and the failure mode is a tool that is unauthorized by omission.
- The dev identity being reconciled with the seven-role hierarchy, after which
  the fall-through path in ADR-0015 stops being exercised in CI at all.
- Cerbos becoming a hard dependency people notice — if Layer 5 outages trace to
  Cerbos reachability, the answer is caching a decision, not removing the check.
- Conditions being added to `memory.yaml`. The call sites already pass
  `session_id` and `tlp_level` as resource attributes, so a condition can use
  them without touching the tools.

## References

- ADR-0016 (read-only clearances), ADR-0017 (memory write for the AI agent) and
  its second revisit trigger.
- `policies/resource/memory.yaml`, `api/authz/cerbos.py`.
- `tests/test_memory_authz.py`, `tests/integration/test_memory_edge_tlp.py`.
