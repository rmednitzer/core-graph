# NIS2 Article 21 -- Control Mapping

> Directive (EU) 2022/2555, Article 21: Cybersecurity risk-management measures
>
> This document maps each Article 21 measure to concrete core-graph platform
> capabilities, configuration, and operational practices. Evidence references
> point to audit_log entries, graph queries, or CI artefacts that an auditor
> can verify independently.

---

## 1. Risk analysis and information system security policies

**Article 21(2)(a)**

| Requirement | Platform implementation |
|---|---|
| Maintain risk analysis process | Bitemporal fact model provides full audit trail of risk assessments. Every risk entity carries `t_valid`, `t_invalid`, `t_recorded`, `t_superseded` timestamps -- no assessment is ever deleted, only superseded. |
| Assess impact of incidents on systems | Graph queries (openCypher via Apache AGE) enable impact analysis across connected entities. Traversals from any asset vertex yield the full blast radius. |
| Policy integrity and non-repudiation | Evidence integrity via SHA-256 hash chain + MinIO WORM storage. Each policy revision is signed with cosign and recorded in the Rekor transparency log. |

**Evidence artefacts:**

- `audit_log` entries with `action = 'risk_assessment_updated'`
- Graph query: `MATCH (r:RiskAssessment)-[:AFFECTS]->(a:Asset) RETURN r, a`
- MinIO WORM bucket `evidence/risk-assessments/`

---

## 2. Incident handling

**Article 21(2)(b)**

| Requirement | Platform implementation |
|---|---|
| Detection and logging | Layer 2 (security events) normalised to OCSF + Layer 6 (forensic timeline) provide complete incident record from first alert to resolution. |
| No event loss | NATS JetStream with at-least-once delivery ensures no event loss during ingest. Consumer acknowledgement is required before dequeue. |
| Root cause analysis | Causal chain vertices (`caused_by`, `preceded_by` edges) link root cause to impact across ontology layers. |
| Incident timeline | Forensic timeline (Layer 6) maintains strict temporal ordering with nanosecond-precision timestamps (ISO 8601, UTC). |

**Evidence artefacts:**

- NATS stream `INGEST.*` consumer lag metrics
- Graph query: `MATCH path = (root)-[:CAUSED_BY*]->(effect) RETURN path`
- `audit_log` entries with `action = 'incident_created'`

---

## 3. Business continuity and crisis management

**Article 21(2)(c)**

| Requirement | Platform implementation |
|---|---|
| Backup and recovery | pgBackRest for point-in-time recovery with RPO <=1h / RTO <=4h. Weekly full + hourly incremental backups. |
| Evidence chain continuity | Evidence chain RPO 0 via synchronous WAL archiving. The hash chain is never broken even during failover. |
| Dependency awareness | Graph-based dependency mapping for impact assessment. `DEPENDS_ON` edges between services, data stores, and network segments enable automated crisis scoping. |
| Recovery testing | Monthly restore tests executed and documented as compliance evidence in Layer 4 (audit/compliance). |

**Evidence artefacts:**

- pgBackRest backup manifests in MinIO `backups/`
- WAL archive lag monitoring (must be 0 for evidence chain)
- Graph query: `MATCH (s:Service)-[:DEPENDS_ON*]->(d) RETURN s, d`

---

## 4. Supply chain security

**Article 21(2)(d)**

| Requirement | Platform implementation |
|---|---|
| Container provenance | Harbor self-hosted container registry with integrated Trivy vulnerability scanning. No Docker Hub pulls in production. |
| Software bill of materials | Software BOM tracked as graph entities. Each component vertex links to its upstream source, licence, and known vulnerabilities via `HAS_COMPONENT` and `AFFECTED_BY` edges. |
| Dependency monitoring | Dependency alerts via Dependabot integration. Alerts are ingested into the graph as `VulnerabilityAlert` vertices linked to affected components. |
| Image signing | cosign enforces image signature verification before deployment. Unsigned images are rejected by admission policy. |

**Evidence artefacts:**

- Harbor scan reports per image tag
- Graph query: `MATCH (c:Component)-[:AFFECTED_BY]->(v:Vulnerability) RETURN c, v`
- Dependabot alert ingest log in NATS stream `INGEST.dependabot`

---

## 5. Security in network and information systems acquisition, development, and maintenance

**Article 21(2)(e)**

| Requirement | Platform implementation |
|---|---|
| Secure development lifecycle | CI/CD pipeline with ruff linting, schema validation, and RLS testing. Every merge request must pass all gates before deployment. |
| Injection prevention | Parameterised queries exclusively (CVE-2022-45786 mitigation). Cypher queries through AGE use query templates, never string concatenation. |
| Database audit | pgAudit for database operation logging. All DDL and DML operations are captured with session context. |
| Schema management | Numbered SQL migrations (`001_`, `002_`, ...) with idempotent application. No ORM. Schema changes are reviewed and tested in CI. |

**Evidence artefacts:**

- CI pipeline logs (ruff, schema validation, RLS test results)
- pgAudit log entries in PostgreSQL log stream
- Migration files in `schema/migrations/`

---

## 6. Policies and procedures to assess the effectiveness of cybersecurity risk-management measures

**Article 21(2)(f)**

| Requirement | Platform implementation |
|---|---|
| Control-to-evidence mapping | Layer 4 (audit/compliance) with `satisfies` and `evidenced_by` edges linking controls to evidence artefacts. |
| Framework mapping | Compliance frameworks (NIS2, BSI IT-Grundschutz) mapped to controls in the graph. Each framework requirement is a vertex with edges to implementing controls. |
| Automated evidence production | Scheduled queries via pg_cron produce compliance evidence automatically. Results are hashed, signed, and stored in MinIO WORM. |
| Effectiveness measurement | Graph queries aggregate control coverage, evidence freshness, and finding resolution rates for management reporting. |

**Evidence artefacts:**

- Graph query: `MATCH (f:Framework)-[:REQUIRES]->(c:Control)-[:EVIDENCED_BY]->(e:Evidence) RETURN f, c, e`
- pg_cron job definitions for scheduled evidence production
- MinIO WORM bucket `evidence/compliance/`

---

## 7. Basic cyber hygiene practices and cybersecurity training

**Article 21(2)(g)**

| Requirement | Platform implementation |
|---|---|
| Role-based access | Seven-role hierarchy (CISO, threat_analyst, incident_responder, soc_operator, compliance_officer, read_only, ai_agent) with principle of least privilege. |
| Disclosure prevention | TLP (Traffic Light Protocol) enforcement at database level via PostgreSQL RLS prevents accidental disclosure. Users cannot query data above their TLP clearance. |
| Awareness | Role definitions and access policies are documented as Cerbos YAML policies in `policies/`, serving as executable security documentation. |

**Evidence artefacts:**

- Cerbos policy files in `policies/`
- RLS policy definitions in `schema/migrations/`
- Role assignment audit trail in `audit_log`

---

## 8. Policies and procedures regarding the use of cryptography

**Article 21(2)(h)**

| Requirement | Platform implementation |
|---|---|
| Integrity protection | SHA-256 hash chain for audit log integrity. Each entry references the hash of the previous entry, forming a tamper-evident chain. |
| Artifact signing | cosign for container and artifact signing. Signatures are stored alongside artefacts and verified at deployment. |
| Transparency and non-repudiation | Rekor transparency log provides public, append-only record of all signing events. |
| Time authentication | NTS (Network Time Security) for authenticated time synchronisation. Prevents timestamp manipulation attacks. |
| Certificate management | step-ca for internal PKI. Certificates are short-lived and automatically rotated. |

**Evidence artefacts:**

- Hash chain verification query: `SELECT verify_hash_chain() FROM audit_log`
- Rekor log entries for all signed artefacts
- NTS configuration in `deploy/` overlay

---

## 9. Human resources security, access control policies, and asset management

**Article 21(2)(i)**

| Requirement | Platform implementation |
|---|---|
| Attribute-based access | Cerbos ABAC evaluates TLP clearance, role, time-of-day, and request context per API call. |
| Relationship-based compartments | SpiceDB ReBAC enforces compartment membership. Users see only entities in their authorised compartments. |
| Unforgeable enforcement | PostgreSQL RLS as the final enforcement layer. Even direct SQL connections cannot bypass access controls. |
| TLP clearance levels | Seven database roles with TLP clearance levels. Each role maps to a maximum TLP marking (WHITE through RED). |
| Break-glass access | Shamir secret sharing for emergency access. Break-glass sessions are time-limited with automatic expiry and full audit logging. |

**Evidence artefacts:**

- Cerbos policy evaluation logs
- SpiceDB relationship tuples
- RLS policy definitions with TLP predicates
- `audit_log` entries with `action = 'break_glass_activated'`

---

## 10. Multi-factor authentication and secured communication

**Article 21(2)(j)**

| Requirement | Platform implementation |
|---|---|
| Multi-factor authentication | OIDC integration with MFA requirement enforced at IdP level. The platform rejects tokens from sessions without MFA claims. |
| Service-to-service encryption | TLS for all service-to-service communication. Mutual TLS where supported. |
| Message bus encryption | NATS TLS enabled in production overlay. Unencrypted NATS connections are rejected in production configuration. |
| API security | All API endpoints require valid OIDC tokens. Cerbos policy evaluation occurs before any data access. |

**Evidence artefacts:**

- OIDC provider MFA policy configuration
- TLS certificate inventory managed by step-ca
- NATS TLS configuration in `deploy/production/`
- API gateway access logs with authentication status

---

## Revision history

| Date | Author | Change |
|---|---|---|
| 2026-03-29 | AI assistant | Initial mapping created |
