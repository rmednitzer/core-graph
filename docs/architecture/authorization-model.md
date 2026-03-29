# Authorization model

core-graph enforces access control through three complementary layers working
in concert. No single layer can be bypassed; every query passes through all
three before returning data. This defence-in-depth approach ensures that a bug
in any single layer cannot result in unauthorised data exposure.

## Three-layer overview

```text
  +----------------------------------------------------------+
  |  Layer 1: Cerbos (ABAC)                                  |
  |  Attribute-based access control                          |
  |  "Does this role have clearance for TLP:AMBER?"          |
  +---------------------------+------------------------------+
                              | ALLOW / DENY
                              v
  +----------------------------------------------------------+
  |  Layer 2: SpiceDB (ReBAC)                                |
  |  Relationship-based access control                       |
  |  "Is this user a member of investigation-42?"            |
  +---------------------------+------------------------------+
                              | ALLOW / DENY
                              v
  +----------------------------------------------------------+
  |  Layer 3: PostgreSQL RLS                                 |
  |  Row-level security at the database engine               |
  |  "Filter every row by session TLP + compartment vars"    |
  +----------------------------------------------------------+
```

| Layer | Engine | Model | Scope |
|-------|--------|-------|-------|
| 1 | Cerbos | ABAC | TLP markings, role attributes, contextual constraints |
| 2 | SpiceDB | ReBAC | Investigation compartments, team relationships, delegation |
| 3 | PostgreSQL RLS | Mandatory | Engine-level row filtering, unforgeable by application code |

**Layers 1 and 2** are evaluated at the application level before any database
query is constructed. **Layer 3** is enforced by the database engine itself and
cannot be bypassed by application code, SQL injection, or direct database
connections (all application roles have RLS enabled; only the migration role
bypasses RLS).

## Layer 1: Cerbos (ABAC)

Cerbos evaluates attribute-based access control policies written in YAML.
Policies are stored in `policies/` and version-controlled as first-class
artefacts alongside the application code.

### What Cerbos decides

- **TLP clearance**: Each role has a maximum TLP level. A `cg_soc_analyst`
  might be cleared to TLP:AMBER+STRICT, while `cg_external_auditor` is limited
  to TLP:GREEN.
- **Resource-action permissions**: Which resource types (indicators, events,
  investigations, compliance records) each role can read, create, update, or
  export.
- **Contextual constraints**: Time-of-day restrictions (e.g., bulk exports
  only during business hours), source-IP allowlisting, and rate limiting
  thresholds.
- **Derived roles**: Cerbos computes derived roles from token claims. For
  example, a user with `department: SOC` and `seniority: lead` derives
  `role:soc-lead` with elevated TLP clearance.
- **PII gating**: Resources flagged with `pii_flag: true` require explicit
  PII access permission, held only by the DPO and CISO roles.

### Key attributes evaluated

- `principal.tlp_clearance` -- maximum TLP level the user may access
- `principal.role` -- one of the seven platform roles
- `principal.department` -- organisational unit for derived role computation
- `resource.tlp_level` -- TLP marking on the target entity
- `resource.pii_flag` -- whether the entity contains personal data

### TLP level encoding

TLP markings are encoded as integers for comparison in both Cerbos policies and
PostgreSQL RLS:

| TLP marking | Integer value |
|---|---|
| TLP:CLEAR | 0 |
| TLP:GREEN | 1 |
| TLP:AMBER | 2 |
| TLP:AMBER+STRICT | 3 |
| TLP:RED | 4 |

A user with `max_tlp = 2` can see rows marked 0, 1, or 2 but not 3 or 4.

### Policy structure

```yaml
# policies/resource_indicator.yaml (illustrative)
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  resource: "indicator"
  version: "default"
  rules:
    - actions: ["read"]
      effect: EFFECT_ALLOW
      roles: ["cg_soc_analyst", "cg_ciso"]
      condition:
        match:
          expr: >
            request.resource.attr.tlp_level <=
            request.principal.attr.max_tlp

    - actions: ["export"]
      effect: EFFECT_ALLOW
      roles: ["cg_ciso"]
      condition:
        match:
          all:
            of:
              - expr: >
                  request.resource.attr.tlp_level <=
                  request.principal.attr.max_tlp
              - expr: >
                  now().getHours() >= 8 && now().getHours() <= 18
```

## Layer 2: SpiceDB (ReBAC)

SpiceDB manages relationship-based access using a Zanzibar-style permissions
model. Where Cerbos answers "does this role have permission?", SpiceDB answers
"does this specific user have a relationship that grants access?"

### What SpiceDB decides

- **Investigation compartments**: Users are added to specific investigations.
  Only members of an investigation can see its associated entities. This
  enforces need-to-know beyond role-based TLP access.
- **Team ownership**: Teams own sets of entities. Team members inherit read
  access; team leads inherit write access.
- **Delegation**: A user can delegate their access to another user for a
  bounded time period. SpiceDB tracks the delegation relationship and its
  expiry.
- **Cross-team sharing**: An investigation lead can grant read access to a
  specific entity to members of another team, without granting access to the
  entire investigation.

### Schema definition

```text
definition user {}

definition team {
  relation member: user
  relation lead: user
  permission view = member + lead
  permission manage = lead
}

definition investigation {
  relation owner: team
  relation member: user
  relation lead: user
  permission view = member + lead + owner->view
  permission contribute = member + lead + owner->manage
  permission manage = lead
}

definition entity {
  relation investigation: investigation
  relation shared_with: user | team#member
  permission view = investigation->view + shared_with
  permission edit = investigation->contribute
}
```

### Relationship examples

```text
investigation:INV-2024-001#member@user:analyst-1
investigation:INV-2024-001#lead@user:senior-analyst-2
entity:vertex-12345#belongs_to@investigation:INV-2024-001
team:soc-alpha#member@user:analyst-1
investigation:INV-2024-001#owner@team:soc-alpha
```

### Relationship lifecycle

Relationships are created and revoked through the API layer, never by direct
SpiceDB manipulation. Every relationship change is recorded in the audit log
with the operator's identity and a justification field.

## Layer 3: PostgreSQL RLS (mandatory enforcement)

Row-level security is the final, unforgeable enforcement layer. RLS policies
are defined in the schema migrations (`schema/migrations/`) and enforced by the
database engine for every query, regardless of how it was issued.

### Session variables

After Cerbos and SpiceDB checks pass, the application sets two PostgreSQL
session variables before executing any query:

```sql
-- Using set_config with true for transaction-local scope
SELECT set_config('app.max_tlp', '3', true);
SELECT set_config('app.allowed_compartments', 'INV-2024-001,INV-2024-003', true);
```

The third argument (`true`) scopes the variables to the current transaction.
When the transaction ends, the variables are automatically cleared and cannot
leak to subsequent queries on the same connection.

### RLS policy pattern

```sql
-- Every table with TLP-marked data uses this policy pattern
ALTER TABLE core.indicator ENABLE ROW LEVEL SECURITY;

CREATE POLICY tlp_read_policy ON core.indicator
  FOR SELECT
  USING (
    coalesce(tlp_level, 1)
    <= coalesce(current_setting('app.max_tlp', true)::int, 1)
  );

CREATE POLICY compartment_read_policy ON core.indicator
  FOR SELECT
  USING (
    compartment_id = ANY(
      string_to_array(
        current_setting('app.allowed_compartments', true), ','
      )
    )
    OR compartment_id IS NULL  -- unclassified entities visible to all
  );
```

The `current_setting(..., true)` form returns NULL instead of raising an error
when the variable is not set, defaulting to the most restrictive posture.

### Why RLS is essential

Application-layer authorisation is necessary but not sufficient. RLS prevents
these failure modes:

- **SQL injection through AGE**: A malformed Cypher query template could bypass
  application checks. RLS still filters results.
- **Application bug**: A code path might forget to call Cerbos/SpiceDB. RLS
  still filters results.
- **Direct database access**: An operator with psql access uses an application
  role (not the migration role). RLS still filters results.
- **Future code changes**: If a developer introduces a new query path, RLS
  applies automatically without requiring explicit authorisation calls.

## OIDC-to-RLS pipeline

The full authorisation flow spans six stages, from token issuance to row
filtering. Every API request traverses this entire pipeline.

```text
  Stage 1          Stage 2           Stage 3          Stage 4
  --------         --------          --------         --------
  IdP issues  -->  API gateway  -->  Cerbos eval  --> SpiceDB check
  OIDC token       validates JWT,    ABAC policy:     ReBAC relations:
  with claims      extracts claims   TLP clearance,   compartment
  (sub, roles,     (sub, roles,      role perms,      membership,
   groups,          groups,           contextual       delegation,
   department)      department)       constraints      team ownership

  Stage 5                    Stage 6
  --------                   --------
  Application sets      -->  PostgreSQL RLS
  session variables          filters every
  in transaction:            query result
  app.max_tlp,               based on session
  app.allowed_compartments   variables
```

### Stage 1: Token issuance

The identity provider (IdP) authenticates the user and issues a signed JWT
containing claims:

- `sub` -- user identifier
- `roles` -- platform role(s)
- `tlp_clearance` -- maximum TLP level
- `department` -- organisational unit
- `groups` -- group memberships for derived role computation

The IdP is the single source of identity truth. core-graph does not maintain
its own user database.

### Stage 2: API gateway validation

The API gateway (or FastAPI middleware, or MCP server) validates the JWT
signature against the IdP's published JWKS, checks expiry and audience claims,
and extracts the claims into a structured principal object. Invalid or expired
tokens are rejected with a 401 response before reaching any application code.

### Stage 3: Cerbos ABAC evaluation

The application sends a `CheckResources` request to Cerbos with the principal
(from the JWT claims) and the requested resource/action pair. Cerbos evaluates
the YAML policy files in `policies/` and returns ALLOW or DENY.

If denied, the request is rejected with a 403 response. The denial reason is
logged but not exposed to the client (to prevent policy enumeration).

### Stage 4: SpiceDB ReBAC check

For compartmented resources, the application calls SpiceDB
`CheckPermission` to verify that the user has a relationship with the relevant
investigation or team. This enforces need-to-know beyond role-based TLP access.

For list operations (e.g., "show me all indicators"), SpiceDB is queried via
`LookupResources` to determine which compartments the user can access. The
resulting set of compartment IDs is passed to Stage 5.

If denied, the request is rejected with a 403 response.

### Stage 5: Session variable injection

The application opens a database transaction and sets session variables using
the results from Stages 3 and 4:

```sql
BEGIN;
SELECT set_config('app.max_tlp', '3', true);       -- from Cerbos result
SELECT set_config('app.allowed_compartments',
  'INV-2024-001,INV-2024-003', true);               -- from SpiceDB result
-- query executes here, RLS is active on every table access
COMMIT;
```

These variables are scoped to the transaction and cannot leak to other
connections or subsequent transactions on the same connection.

### Stage 6: RLS enforcement

The database engine evaluates RLS policies on every table access within the
transaction. Rows that do not satisfy the policy predicates are silently
excluded from results. The application receives only the rows the user is
authorised to see. No error is raised for filtered rows -- they simply do not
appear in the result set.

## AGE RLS integration

Apache AGE stores graph data in PostgreSQL tables (one table per vertex label,
one table per edge label) within the graph schema. RLS policies apply to these
tables exactly as they apply to any other PostgreSQL table.

### The edge-denormalisation problem

Graph edges in AGE store references to source and target vertex IDs but do not
inherently carry the TLP level of the vertices they connect. This creates two
problems:

1. **Visibility leakage**: An edge between two TLP:RED vertices would be
   visible to a user cleared only for TLP:GREEN, because the edge table row
   itself has no TLP column.
2. **Inference attack**: Even if the edge is filtered, a user could infer the
   existence of hidden high-TLP vertices by observing that visible vertices
   have edges pointing to non-visible vertex IDs.

### Mitigation: denormalise TLP onto edges

The graph writer denormalises the maximum TLP level of an edge's source and
target vertices onto the edge row itself:

```sql
-- Edge table includes a denormalised TLP column
-- Set to MAX(source.tlp_level, target.tlp_level) at write time
ALTER TABLE ag_catalog."core_graph"."edge_label"
  ADD COLUMN tlp_level integer NOT NULL DEFAULT 0;

CREATE POLICY edge_tlp_policy ON ag_catalog."core_graph"."edge_label"
  FOR SELECT
  USING (
    tlp_level <= current_setting('app.max_tlp', true)::int
  );
```

When a vertex's TLP level changes, a trigger updates all connected edges.
This denormalisation is a controlled trade-off: write amplification (updating
edges when vertices change) in exchange for correct RLS enforcement on graph
traversals.

### Compartment denormalisation on edges

The same pattern applies to compartment IDs. Edges carry the compartment of
their source vertex, and the RLS policy on edges filters by
`app.allowed_compartments`. This ensures that a graph traversal cannot cross
compartment boundaries via edges.

## Graph traversal depth limits

To prevent both performance abuse and information leakage through transitive
graph traversal, core-graph enforces depth limits per role:

| Role | Max depth | Rationale |
|------|-----------|-----------|
| `cg_ciso` | unlimited | Full operational picture |
| `cg_soc_analyst` | 5 | Investigation scope |
| `cg_compliance_officer` | 3 | Control-evidence chains |
| `cg_it_operations` | 3 | Infrastructure scope |
| `cg_dpo` | 2 | Minimal graph access, privacy-focused |
| `cg_external_auditor` | 3 | Audit trail following |
| `cg_ai_agent` | 4 | Reasoning chain depth |

Depth limits are enforced at the application layer by parameterising the Cypher
query template's path length constraint. They are not enforced by RLS (RLS
operates on individual rows, not traversal depth).

```sql
-- Cypher query template with parameterised depth limit
SELECT * FROM cypher('core_graph', $$
  MATCH path = (start)-[*1..%s]->(end)
  WHERE id(start) = $1
  RETURN path
$$, $2) AS (path agtype);
```

The `%s` depth placeholder is set by the application from a fixed lookup table
keyed on the authenticated user's role. It is never derived from user input.

## Seven-role hierarchy

| Role | max_tlp | PII access | Purpose |
|------|---------|------------|---------|
| `cg_ciso` | 4 (RED) | Yes | Full operational oversight |
| `cg_soc_analyst` | 3 (AMBER+STRICT) | No | Threat investigation and response |
| `cg_compliance_officer` | 2 (AMBER) | No | Audit, compliance mapping, evidence review |
| `cg_it_operations` | 2 (AMBER) | No | Infrastructure monitoring and alerting |
| `cg_dpo` | 0 (CLEAR) | Yes | Data protection duties, pseudonymisation oversight |
| `cg_external_auditor` | 1 (GREEN) | No | Third-party audit with read-only, scoped access |
| `cg_ai_agent` | 2 (AMBER) | No | Automated analysis via MCP, bounded scope |

The DPO role has TLP clearance 0 but PII access. This reflects the data
protection officer's need to audit personal data handling without accessing
threat intelligence classified above CLEAR.

## Break-glass procedures

In exceptional circumstances (active incident, investigation lead unavailable,
time-critical response), authorised operators may need to temporarily elevate
their access beyond normal policy. Break-glass is not a bypass of
authorisation; it is a pre-authorised, heavily audited escalation path.

Key properties of the break-glass mechanism:

- **Two-person authorisation**: Requires both the operator requesting elevation
  and an independent approver (CISO or delegate)
- **Time-limited**: Creates a temporary SpiceDB relationship with automatic
  expiry (default: 4 hours, maximum: 24 hours)
- **Audit trail**: Generates an audit log entry with mandatory justification
  text, approver identity, and expiry timestamp
- **Immediate alerting**: Triggers an alert to the security operations channel
  at activation time
- **Automatic revocation**: SpiceDB relationship is automatically revoked at
  expiry; no manual cleanup required
- **Post-incident review**: All break-glass activations are reviewed in the
  next operational review meeting

See [break-glass.md](../operations/break-glass.md) for the full procedure,
including activation steps and the review checklist.
