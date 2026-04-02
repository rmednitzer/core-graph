# BSI IT-Grundschutz -- Module Mapping

> BSI IT-Grundschutz Compendium, Edition 2023
>
> This document maps relevant IT-Grundschutz modules to concrete core-graph
> platform capabilities, configuration, and operational practices. Evidence
> references point to audit_log entries, graph queries, or CI artefacts that
> an auditor can verify independently.

---

## 1. CON.1 Cryptography

**Objective:** Ensure confidentiality, integrity, and authenticity through
appropriate use of cryptographic mechanisms.

| Requirement | Platform implementation |
|---|---|
| Integrity protection | SHA-256 hash chain for audit log tamper evidence. Each `audit_log` entry includes the hash of the previous entry, forming a cryptographically verifiable chain. Any modification breaks the chain and is immediately detectable. |
| Artifact signing | cosign for container and artifact signing. All deployment artefacts are signed before release. Unsigned artefacts are rejected by admission policy. |
| Transparency and non-repudiation | Rekor transparency log for non-repudiation. Every signing event is recorded in an append-only, publicly verifiable log. |
| Certificate management | step-ca for internal PKI certificate management. Short-lived certificates are issued automatically and rotated before expiry. Root CA keys are stored in hardware-backed storage. |
| Time authentication | NTS (Network Time Security) for authenticated timestamps. Prevents time-based attacks on bitemporal fact validity windows and audit log ordering. |

**Evidence artefacts:**

- Hash chain verification: `SELECT verify_hash_chain() FROM audit_log`
- Rekor log entries for all cosign signatures
- step-ca certificate inventory and rotation logs
- NTS configuration in `deploy/` overlay

---

## 2. APP.4.3 Database systems

**Objective:** Secure operation of database systems with appropriate access
control, auditing, and hardening.

| Requirement | Platform implementation |
|---|---|
| Hardened configuration | PostgreSQL 16+ with hardened configuration. Unnecessary extensions disabled, `listen_addresses` restricted, connection limits enforced, SSL required for all connections. |
| Mandatory access control | RLS (Row-Level Security) for mandatory access control at engine level. TLP markings are enforced by the database itself -- application code cannot bypass these policies. |
| Operation-level auditing | pgAudit for operation-level audit logging. All DDL and DML operations are captured with session context, user identity, and timestamp. |
| Injection prevention | Parameterised queries exclusively (no string concatenation). Cypher queries through Apache AGE use query templates. This mitigates CVE-2022-45786 and equivalent injection vectors. |
| Backup encryption | Encrypted backups via pgBackRest + AES-256. Backup encryption keys are managed separately from database credentials. Backups are stored in EU-sovereign object storage (Hetzner). |

**Evidence artefacts:**

- PostgreSQL configuration diff against CIS benchmark
- RLS policy definitions in `schema/migrations/`
- pgAudit log entries in PostgreSQL log stream
- pgBackRest backup manifests with encryption metadata

---

## 3. ORP.4 Identity and access management

**Objective:** Ensure that only authorised persons and systems have access to
information and IT systems, with appropriate granularity.

| Requirement | Platform implementation |
|---|---|
| Role hierarchy | Seven-role hierarchy: CISO, threat_analyst, incident_responder, soc_operator, compliance_officer, read_only, ai_agent. Each role follows the principle of least privilege. |
| Attribute-based access control | Cerbos ABAC evaluates TLP clearance, role, time-of-day, and request context per API call. Policies are defined as YAML files in `policies/` and version-controlled. |
| Relationship-based access control | SpiceDB ReBAC enforces compartment membership. Access decisions consider organisational relationships, team membership, and case assignment. |
| Session-scoped enforcement | OIDC-to-RLS pipeline for session-scoped enforcement. The authenticated user's TLP clearance and role are set as PostgreSQL session variables, enforced by RLS for every query. |
| Emergency access | Break-glass with Shamir secret shares and automatic expiry. Emergency access requires multiple key holders, is time-limited, and generates prominent audit entries for mandatory review. |

**Evidence artefacts:**

- Cerbos policy files in `policies/`
- SpiceDB relationship tuples and namespace definitions
- `audit_log` entries with `action = 'role_assigned'` or `action = 'break_glass_activated'`
- OIDC token claims mapped to RLS session variables

---

## 4. OPS.1.1.5 Logging

**Objective:** Collect, store, and evaluate log data to detect security-relevant
events and support forensic analysis.

| Requirement | Platform implementation |
|---|---|
| Tamper-evident storage | Append-only `audit_log` table with SHA-256 hash chain. Rows cannot be updated or deleted. The hash chain provides cryptographic proof of log integrity. |
| Database operation logging | pgAudit captures DDL and DML operations with full session context. Logs include the executing role, client address, and query text. |
| Message bus logging | NATS JetStream provides durable message log. All ingested events are retained in streams with configurable retention policies. Consumer acknowledgement ensures no silent message loss. |
| Immutable evidence retention | MinIO WORM (Write Once Read Many) storage for immutable evidence retention. Once written, evidence objects cannot be modified or deleted until the retention period expires. |
| Automated maintenance | pg_cron for automated log rotation and Merkle root computation. Periodic jobs compute Merkle tree roots over audit_log batches, providing efficient integrity verification for large log volumes. |

**Evidence artefacts:**

- `audit_log` hash chain verification query
- pgAudit configuration in `postgresql.conf`
- NATS JetStream stream configuration and consumer lag metrics
- MinIO WORM bucket policies and retention settings
- pg_cron job definitions for Merkle root computation

---

## 5. SYS.1.6 Containers

**Objective:** Secure use of container technology including image management,
runtime isolation, and network segmentation.

| Requirement | Platform implementation |
|---|---|
| Private registry | Harbor self-hosted registry with integrated Trivy vulnerability scanning. Images are scanned on push and periodically rescanned for newly disclosed CVEs. |
| Image signature verification | cosign verifies image signatures before deployment. The admission controller rejects any image without a valid signature from a trusted key. |
| Supply chain control | No Docker Hub pulls in production. All base images are mirrored into Harbor, scanned, and signed before use. This eliminates dependency on external registries at deploy time. |
| Network isolation | Kubernetes with NetworkPolicy isolation (Phase 3). Pod-to-pod communication is denied by default; explicit policies whitelist only required traffic flows. |

**Evidence artefacts:**

- Harbor scan reports per image tag and digest
- cosign signature verification logs
- NetworkPolicy definitions in `deploy/kustomize/`
- Container runtime configuration (seccomp profiles, read-only root filesystem)

---

## 6. DER.2.1 Incident detection and response

**Objective:** Detect security incidents promptly and respond to them in a
structured, documented manner.

| Requirement | Platform implementation |
|---|---|
| Alert normalisation | Wazuh alerts normalised to OCSF (Open Cybersecurity Schema Framework) via ingest adapter pattern. Raw alerts are transformed into a common schema before graph ingestion. |
| IOC extraction | Tier 1 regex-based extraction for IP addresses, hashes, domains, and email addresses. Tier 2 CyNER (planned) for contextual named entity recognition of threat intelligence indicators. |
| Cross-layer correlation | Graph-based correlation across eight ontology layers. Analysts can traverse from a security event (Layer 2) to threat intelligence (Layer 1) to affected assets (Layer 7) and back to forensic timeline (Layer 6). |
| Forensic timeline | Forensic timeline (Layer 6) with `caused_by` and `preceded_by` edges. Events are ordered with nanosecond precision (ISO 8601, UTC) and linked causally. |
| Deduplication | Bloom filter dedup prevents duplicate alert processing. Duplicate events are detected at ingest time, preventing alert fatigue and reducing graph noise. |

**Evidence artefacts:**

- NATS stream `INGEST.wazuh` consumer metrics
- Graph query: `MATCH (a:Alert)-[:CAUSED_BY]->(root) RETURN a, root`
- Bloom filter false positive rate monitoring
- Ingest adapter transformation logs

---

## 7. CON.3 Backup

**Objective:** Ensure availability and recoverability of data through regular,
tested, and secure backup procedures.

| Requirement | Platform implementation |
|---|---|
| Backup schedule | pgBackRest: weekly full + hourly incremental backups. The schedule ensures that recovery requires at most one full backup plus incremental chain replay. |
| Point-in-time recovery | WAL (Write-Ahead Log) archiving for point-in-time recovery. Any moment between the oldest retained WAL segment and the present can be restored to. |
| EU-sovereign storage | Encrypted backups to Hetzner Object Storage (EU). All backup data remains within EU jurisdiction. AES-256 encryption at rest with separately managed keys. |
| Restore testing | Monthly restore tests documented as compliance evidence. Each test verifies full recovery including RLS policies, graph data, and audit log hash chain integrity. Results are stored in Layer 4 (audit/compliance). |
| RPO targets | RPO <=1h standard for operational data via hourly incremental backups. RPO 0 for evidence chain via synchronous WAL archiving -- the hash chain is never broken, even during failover. |

**Evidence artefacts:**

- pgBackRest backup manifests and verification reports
- WAL archive lag monitoring (must be 0 for evidence chain)
- Monthly restore test reports in MinIO `evidence/compliance/`
- Hetzner Object Storage bucket configuration with encryption settings

---

## Revision history

| Date | Author | Change |
|---|---|---|
| 2026-03-29 | AI assistant | Initial mapping created |
