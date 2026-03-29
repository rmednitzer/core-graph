# Data residency and EU sovereignty controls

core-graph is designed for EU-sovereign operation. All data processing,
storage, and external service dependencies are constrained to EU
jurisdiction. No data leaves the EU without explicit configuration.

## DNS: Unbound + Quad9

All DNS resolution goes through a self-hosted Unbound recursive resolver.
Upstream forwarders are limited to Quad9 (9.9.9.9), operated by the
Quad9 Foundation in Switzerland under Swiss privacy law.

- No US-based resolvers (no Google 8.8.8.8, no Cloudflare 1.1.1.1)
- DNSSEC validation enabled
- Query logging disabled in production (privacy by design)
- Local zone overrides for internal services

## NTP: PTB + NTS

Time synchronisation uses the Physikalisch-Technische Bundesanstalt (PTB)
NTP servers with Network Time Security (NTS) for authenticated time.

- Primary: `ptbtime1.ptb.de` (NTS-enabled)
- Secondary: `ptbtime2.ptb.de` (NTS-enabled)
- NTS provides cryptographic authentication of time responses
- Critical for bitemporal model integrity and audit log timestamps

## Container images: Harbor self-hosted

Production environments pull container images exclusively from a
self-hosted Harbor registry. No direct Docker Hub pulls in production.

- Harbor instance runs on EU infrastructure (Hetzner)
- Automatic vulnerability scanning via Trivy integration
- Image signature verification via cosign
- Replication from upstream registries happens on a controlled schedule
- Air-gapped operation possible for classified environments

## Package repositories: self-hosted proxies

All language-specific package managers use self-hosted proxy repositories:

| Ecosystem | Proxy | Purpose |
|-----------|-------|---------|
| Debian/Ubuntu | aptly | System packages |
| Python | devpi | pip dependencies |
| Node.js | Verdaccio | npm packages |
| Go | Athens | Go modules |

Proxies cache upstream packages and can operate in air-gapped mode.
New packages are admitted after automated security scanning.

## OSINT feed proxying

External OSINT feeds (threat intelligence, vulnerability databases, news)
are fetched through an EU-located proxy server. This prevents direct
connections from the core platform to external services and enables:

- Content inspection and filtering before ingest
- Rate limiting and retry logic
- Caching to reduce external dependencies
- Audit trail of all external data fetches
- Ability to operate with degraded external connectivity

## Certificate authorities

| Use case | CA | Jurisdiction |
|----------|-----|-------------|
| External TLS | Actalis | Italy (EU-qualified TSP) |
| Internal PKI | step-ca (Smallstep) | Self-hosted |

Actalis is an EU-qualified Trust Service Provider under eIDAS regulation.
step-ca manages short-lived certificates for service-to-service mTLS with
automatic rotation.

## Object storage

| Use case | Service | Location |
|----------|---------|----------|
| Backups | Hetzner Object Storage | Falkenstein/Nuremberg, Germany |
| Evidence WORM | MinIO | Self-hosted, EU |
| WAL archive | Hetzner Object Storage | Falkenstein/Nuremberg, Germany |

All storage is S3-compatible with server-side encryption enabled.
MinIO operates in WORM (Write Once Read Many) mode for evidence
integrity.

## Summary: component jurisdiction

| Component | Provider | Location | Jurisdiction |
|-----------|----------|----------|-------------|
| Compute | Hetzner | Germany | EU/GDPR |
| DNS upstream | Quad9 | Switzerland | Swiss FADP |
| NTP | PTB | Germany | EU |
| Container registry | Harbor (self-hosted) | Germany | EU/GDPR |
| Package proxies | Self-hosted | Germany | EU/GDPR |
| Object storage | Hetzner | Germany | EU/GDPR |
| Evidence storage | MinIO (self-hosted) | Germany | EU/GDPR |
| TLS certificates | Actalis | Italy | EU/eIDAS |
| Internal PKI | step-ca (self-hosted) | Germany | EU/GDPR |
