# Authorization model

core-graph enforces access control through three complementary layers working
in concert. No single layer can be bypassed; every query passes through all
three before returning data.

## Three-layer architecture

| Layer | Engine | Model | Scope |
|-------|--------|-------|-------|
| 1 | Cerbos | ABAC | TLP markings, role attributes |
| 2 | SpiceDB | ReBAC | Investigation compartments, team relationships |
| 3 | PostgreSQL RLS | Mandatory | Engine-level row filtering, unforgeable |

### Layer 1: Cerbos (ABAC)

Cerbos evaluates attribute-based access control policies written in YAML.
Each request includes the principal (role, TLP clearance, department) and the
resource (entity type, TLP marking, classification). Policies are stored in
`policies/` and version-controlled as first-class artifacts.

Key attributes evaluated:

- `principal.tlp_clearance` — maximum TLP level the user may access
- `principal.role` — one of the seven platform roles
- `resource.tlp_level` — TLP marking on the target entity
- `resource.pii_flag` — whether the entity contains personal data

### Layer 2: SpiceDB (ReBAC)

SpiceDB manages relationship-based access for investigation compartments.
A user can only access entities within investigations they are assigned to.
Relationships are modeled as:

```
investigation:INV-2024-001#member@user:analyst-1
investigation:INV-2024-001#lead@user:senior-analyst-2
entity:vertex-12345#belongs_to@investigation:INV-2024-001
```

SpiceDB checks are performed after Cerbos ABAC passes. If a user has
sufficient TLP clearance but is not a member of the relevant investigation
compartment, access is denied.

### Layer 3: PostgreSQL RLS (mandatory enforcement)

Row-Level Security is the final, unforgeable enforcement layer. Even if
application code has a bug, RLS policies at the database engine level
prevent unauthorized data access. RLS cannot be bypassed by SQL injection
or application-layer vulnerabilities.

Policies use session variables set by the application:

- `app.max_tlp` — maximum TLP level (integer 0-4)
- `app.allowed_compartments` — comma-separated investigation IDs

## OIDC-to-RLS pipeline

The six-stage pipeline transforms an OIDC token into enforceable database
session variables:

### Stage 1: Token issuance

The Identity Provider (IdP) issues an OIDC token containing claims:

- `sub` — user identifier
- `roles` — platform role(s)
- `tlp_clearance` — maximum TLP level
- `department` — organizational unit

### Stage 2: API gateway validation

The API gateway (or MCP server) validates the JWT signature, checks
expiration, and extracts claims. Invalid tokens are rejected before
reaching the application.

### Stage 3: Cerbos ABAC evaluation

The application sends a CheckResources request to Cerbos with the
principal attributes and requested resource. Cerbos returns allow/deny
based on YAML policies in `policies/`.

### Stage 4: SpiceDB ReBAC check

For compartmented resources, the application calls SpiceDB to verify
the user has a relationship with the relevant investigation. This
enforces need-to-know beyond role-based TLP access.

### Stage 5: Session variable injection

The application sets PostgreSQL session variables before executing queries:

```sql
select set_config('app.max_tlp', '3', true);       -- from Cerbos result
select set_config('app.allowed_compartments', 'INV-2024-001,INV-2024-003', true);
```

These variables are scoped to the current transaction.

### Stage 6: RLS enforcement

PostgreSQL RLS policies reference the session variables to filter rows:

```sql
create policy tlp_read_policy on core_graph.vertex_table
    for select using (
        coalesce((properties::jsonb->>'tlp_level')::int, 1)
        <= coalesce(current_setting('app.max_tlp', true)::int, 1)
    );
```

## AGE RLS integration

Apache AGE stores graph data in PostgreSQL tables within the `core_graph`
schema. Each vertex label and edge label has a corresponding table with a
`properties` column of type `agtype`.

### Edge denormalization mitigation

A critical design decision: TLP level is denormalized onto edge properties
in addition to vertex properties. Without this, an attacker could infer the
existence of hidden high-TLP vertices by observing edges that reference them.

When creating an edge, the application copies the higher TLP level of the
two endpoint vertices onto the edge's `tlp_level` property. RLS policies on
edge tables then filter edges the same way vertex tables are filtered.

### Graph traversal depth limits

To prevent information leakage through multi-hop traversals, each role has
a maximum traversal depth:

| Role | Max depth | Rationale |
|------|-----------|-----------|
| cg_ciso | unlimited | Full operational picture |
| cg_soc_analyst | 5 | Investigation scope |
| cg_compliance_officer | 3 | Control-evidence chains |
| cg_it_operations | 3 | Infrastructure scope |
| cg_dpo | 2 | Minimal graph access |
| cg_external_auditor | 3 | Audit trail following |
| cg_ai_agent | 4 | Reasoning chain depth |

Depth limits are enforced at the application layer via Cypher query
template validation.

## Seven-role hierarchy

| Role | max_tlp | PII access | Purpose |
|------|---------|------------|---------|
| cg_ciso | 4 (RED) | Yes | Full operational oversight |
| cg_soc_analyst | 3 (AMBER) | No | Threat investigation |
| cg_compliance_officer | 2 (GREEN) | No | Audit and compliance |
| cg_it_operations | 2 (GREEN) | No | Infrastructure monitoring |
| cg_dpo | 0 (none) | Yes | Data protection duties |
| cg_external_auditor | 2 (GREEN) | No | Third-party audit |
| cg_ai_agent | 2 (GREEN) | No | Automated analysis |

## Break-glass procedures

Emergency access bypasses the normal authorization pipeline via a
time-limited `breakglass_admin` role. See
[break-glass.md](../operations/break-glass.md) for the full procedure
including Shamir secret sharing activation and automatic role expiry.
