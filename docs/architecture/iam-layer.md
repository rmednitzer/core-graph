# IAM layer architecture

## Keycloak as authoritative identity source

Keycloak is the single authoritative source for identity data in core-graph.
The Keycloak adapter (`ingest/connectors/keycloak/adapter.py`) polls the Admin
REST API for users, groups, realm roles, client roles, and role mappings. Delta
sync via Valkey ensures only modified entities are re-published each cycle.

## Sync architecture

```
Keycloak Admin API
    │
    ▼
KeycloakAdapter.fetch()
    │  users, groups, roles, role mappings
    ▼
KeycloakAdapter.map()
    │  User → Principal, Group → Group, Role → Role
    │  TLP floor enforced: tlp = max(2, tlp)
    ▼
NATS JetStream
    │  enriched.entity.iam.keycloak (vertices)
    │  enriched.relationship.iam.keycloak (edges)
    ▼
graph_writer
    │  MERGE_TEMPLATES + RELATIONSHIP_TEMPLATES
    ▼
PostgreSQL / Apache AGE
    │  core_graph namespace
    ▼
RLS: iam_tlp_floor policy
```

## TLP floor rationale

IAM data is inherently sensitive. Knowing who has what roles, which groups
exist, and who has administrative access is valuable to an adversary for
privilege escalation and lateral movement planning. Therefore:

1. The Keycloak adapter mapper enforces `tlp >= 2` on every entity.
2. Migration `010_iam_layer.sql` creates an `iam_tlp_floor` RLS policy that
   blocks visibility when `app.max_tlp < 2`, regardless of the vertex's own
   `tlp_level` property.
3. This is a defence-in-depth measure: even if the adapter were bypassed,
   the database itself would prevent exposure.

## Principal--same_as--ThreatActor authorization

This edge type asserts that an internal principal (employee, service account)
is the same entity as a known threat actor. This is an extremely sensitive
attribution that can have legal, HR, and investigative consequences.

### Authorization procedure

1. Only a principal with the `cg_ciso` Cerbos role can call
   `tool_assert_identity_attribution`.
2. Cerbos is checked **before** any database operation. If Cerbos is
   unreachable, the action is denied (fail closed).
3. The `cg_ai_agent` role is explicitly denied by the Cerbos policy
   `policies/resource/identity_attribution.yaml`.
4. The edge is created with `tlp_level = 4` (RED) and a `compartment`
   property set to the `investigation_id`.
5. A mandatory audit log entry records the justification, the actor,
   and the correlation ID.

### Break-glass

In emergency scenarios where Cerbos is unavailable and attribution is
operationally critical, the CISO can connect directly to PostgreSQL with
the `cg_ciso` database role and execute the Cypher MERGE manually. This
bypasses the application layer but is still subject to the append-only
audit log trigger. The break-glass action must be documented in the
incident record.
