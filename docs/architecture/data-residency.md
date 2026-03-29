# Data residency and EU sovereignty controls

core-graph is designed for EU-sovereign operation. All data processing,
storage, and external service dependencies are constrained to EU (or
EU-adequate) jurisdictions. No data leaves the EU without explicit
configuration and documented justification. This document catalogues every
external dependency and the controls ensuring jurisdictional compliance.

## Guiding principles

1. **Default deny**: No outbound connection to a non-EU service is permitted
   unless explicitly allowlisted and documented here.
2. **Self-hosted first**: Where a self-hosted alternative exists and is
   operationally viable, it is preferred over any hosted service.
3. **Jurisdiction over convenience**: A slightly less convenient EU-based
   service is always preferred over a more convenient US-based service.
4. **Auditability**: Every external dependency is catalogued with its operator,
   location, and governing privacy law.

## DNS: Unbound + Quad9

All DNS resolution goes through a self-hosted Unbound recursive resolver.
Unbound performs full recursive resolution from the root servers when possible,
falling back to upstream forwarders only when necessary.

**Upstream forwarder**: Quad9 (9.9.9.9 / 149.112.112.112), operated by the
Quad9 Foundation, headquartered in Zurich, Switzerland. Quad9 is governed by
Swiss privacy law (Federal Act on Data Protection, FADP) and has publicly
committed to not logging individual query data.

**Explicitly excluded**: No US-based DNS resolvers are used. This means no
Google Public DNS (8.8.8.8), no Cloudflare (1.1.1.1), and no Amazon Route 53
resolvers. While these services may offer superior performance or availability,
they operate under US jurisdiction and are subject to US legal processes that
could compel disclosure.

Configuration details:

- DNSSEC validation enabled and enforced
- DNS-over-TLS (DoT) to Quad9 on port 853 for transport encryption
- Query logging disabled in production (privacy by design)
- Local zone overrides for internal services (no external leakage of internal
  hostnames)
- Response Policy Zones (RPZ) for threat intelligence-based DNS blocking

## NTP: PTB + NTS

Time synchronisation uses the Physikalisch-Technische Bundesanstalt (PTB)
NTP servers. PTB is Germany's national metrology institute, responsible for
maintaining the official time standard (UTC(PTB)).

- Primary: `ptbtime1.ptb.de`
- Secondary: `ptbtime2.ptb.de`
- Tertiary: `ptbtime3.ptb.de`

All three servers support Network Time Security (NTS), as defined in RFC 8915.
NTS provides cryptographic authentication of time responses, preventing
man-in-the-middle attacks that could manipulate timestamps. This is critical
for:

- **Bitemporal model integrity**: Manipulated timestamps would corrupt the
  t_valid / t_recorded / t_superseded fields that underpin all historical
  queries.
- **Audit log reliability**: Regulators (NIS2, DORA) require demonstrably
  accurate timestamps on audit records.
- **Evidence chain validity**: cosign signatures include timestamps; if the
  system clock is manipulated, signatures could be backdated.

**Explicitly excluded**: No US-operated NTP pools (e.g., pool.ntp.org with
US-based servers, NIST time servers). While NTP itself does not transmit
sensitive data, authenticated time from a national metrology institute
provides a stronger evidentiary basis than anonymous pool servers.

## Container images: Harbor self-hosted

Production environments pull container images exclusively from a self-hosted
Harbor registry. No direct Docker Hub, GitHub Container Registry (ghcr.io),
or Quay.io pulls in production.

- Harbor instance runs on EU infrastructure (Hetzner Cloud, Germany)
- Trivy vulnerability scanning runs automatically on image push
- Image signatures verified via cosign before deployment
- Notary v2 content trust for supply chain verification
- Replication from upstream registries occurs on a controlled schedule through
  an EU-located pull-through proxy
- Air-gapped operation is supported for environments with no internet access

### Image provenance workflow

```text
1. Developer pushes image to Harbor (EU)
2. Trivy scans for CVEs; blocks deployment if critical/high found
3. cosign signs the image with developer's OIDC identity
4. Kubernetes admission controller (Kyverno) verifies signature before pull
5. Image is pulled from Harbor, never from an external registry
```

## Package repositories: self-hosted proxies

All language-specific package managers use self-hosted proxy repositories that
cache upstream packages within the EU. Direct pulls from upstream repositories
(pypi.org, npmjs.com, proxy.golang.org) are blocked in production.

| Ecosystem | Proxy | Upstream cached | Purpose |
|-----------|-------|-----------------|---------|
| Debian/Ubuntu | aptly | deb.debian.org, security.debian.org | System packages, security updates |
| Python | devpi | pypi.org | pip / poetry dependencies |
| Node.js | Verdaccio | registry.npmjs.org | npm / yarn packages |
| Go | Athens | proxy.golang.org, sum.golang.org | Go modules and checksum verification |

All proxies:

- Cache packages locally after first fetch, reducing external dependency
- Can operate in air-gapped mode using pre-populated caches
- Run automated security scanning on newly cached packages
- Maintain an allowlist of approved packages for production use
- Log all upstream fetches for audit purposes

## OSINT feed proxying

External OSINT feeds (threat intelligence, vulnerability databases, news
sources, dark web monitors) are fetched through an EU-located proxy server.
The core-graph platform never makes direct outbound connections to feed
sources.

This architecture provides:

- **Jurisdictional isolation**: The proxy runs on EU infrastructure; feed
  providers see only the proxy's IP, not the core-graph instance
- **Content inspection**: Feed data is validated and sanitised before ingest
  into the NATS pipeline
- **Rate limiting**: Upstream rate limits are respected centrally, preventing
  accidental abuse
- **Caching**: Frequently accessed feeds are cached, reducing external
  dependency and improving resilience
- **Audit trail**: Every external fetch is logged with timestamp, source URL,
  response size, and HTTP status
- **Degraded operation**: If external connectivity is lost, cached feeds
  continue to be available for a configurable period

### Feed proxy configuration

```text
Feed source --> EU proxy (Hetzner) --> NATS JetStream --> Ingest pipeline
                     |
                     +-- Content validation
                     +-- Rate limiting
                     +-- Cache (configurable TTL)
                     +-- Fetch audit log
```

## Certificate authorities

### External TLS: Actalis

External-facing TLS certificates (API endpoints, TAXII server, web interfaces)
are issued by Actalis S.p.A., an Italian certificate authority. Actalis is a
qualified Trust Service Provider (QTSP) under the EU eIDAS Regulation
(910/2014). This means:

- Actalis is supervised by AgID (Agenzia per l'Italia Digitale)
- Certificate issuance follows EU-regulated procedures
- Actalis is not subject to US legal processes that could compel issuance of
  fraudulent certificates

### Internal PKI: step-ca (Smallstep)

Service-to-service mutual TLS (mTLS) uses short-lived certificates issued by
a self-hosted step-ca instance:

- Certificates have a 24-hour lifetime with automatic renewal
- No long-lived service certificates to manage or risk compromising
- ACME protocol for automated certificate issuance
- Root CA private key stored in a hardware security module (HSM) or sealed
  with Shamir secret sharing
- Certificate transparency logs maintained internally

## Object storage

| Use case | Service | Location | Jurisdiction | Encryption |
|----------|---------|----------|-------------|------------|
| Database backups | Hetzner Object Storage | Falkenstein/Nuremberg, Germany | EU/GDPR | AES-256 server-side + client-side |
| WAL archive | Hetzner Object Storage | Falkenstein/Nuremberg, Germany | EU/GDPR | AES-256 server-side |
| Evidence WORM | MinIO (self-hosted) | Hetzner Cloud, Germany | EU/GDPR | AES-256 server-side |

- Hetzner Object Storage is S3-compatible and operated by Hetzner Online GmbH,
  a German company subject to GDPR. Data centres are located in Germany.
- MinIO operates in WORM (Write Once Read Many) mode with object-lock
  (compliance mode) for evidence integrity. Compliance mode prevents deletion
  even by the MinIO root user until the retention period expires.
- All storage uses server-side encryption. Database backups additionally use
  client-side encryption (age/gpg) so that Hetzner cannot read backup contents.

## Summary: component jurisdiction

| Component | Provider | Location | Jurisdiction | Data sensitivity |
|-----------|----------|----------|-------------|-----------------|
| Compute (production) | Hetzner Cloud | Germany (Falkenstein/Nuremberg) | EU/GDPR | All data |
| Compute (lab) | Hetzner Cloud | Germany (Falkenstein) | EU/GDPR | Test data |
| DNS upstream | Quad9 Foundation | Switzerland (Zurich) | Swiss FADP | DNS queries only |
| NTP | PTB | Germany (Braunschweig) | German federal | No data (time sync) |
| Container registry | Harbor (self-hosted) | Germany (Hetzner) | EU/GDPR | Container images |
| Debian packages | aptly (self-hosted) | Germany (Hetzner) | EU/GDPR | Package cache |
| Python packages | devpi (self-hosted) | Germany (Hetzner) | EU/GDPR | Package cache |
| Node.js packages | Verdaccio (self-hosted) | Germany (Hetzner) | EU/GDPR | Package cache |
| Go modules | Athens (self-hosted) | Germany (Hetzner) | EU/GDPR | Package cache |
| Object storage (backups) | Hetzner Object Storage | Germany (Falkenstein/Nuremberg) | EU/GDPR | Encrypted backups |
| Evidence storage | MinIO (self-hosted) | Germany (Hetzner) | EU/GDPR | WORM evidence |
| TLS certificates (external) | Actalis S.p.A. | Italy (Milan) | EU/eIDAS | Public certificates |
| Internal PKI | step-ca (self-hosted) | Germany (Hetzner) | EU/GDPR | Internal certificates |
| OSINT feed proxy | Self-hosted | Germany (Hetzner) | EU/GDPR | Feed content (cached) |

### Jurisdictional boundaries

```text
  +---------------------------------------------------------------+
  |  EU / GDPR Jurisdiction                                       |
  |                                                               |
  |  +---------------------------+  +-------------------------+  |
  |  | Germany (Hetzner)         |  | Italy (Actalis)         |  |
  |  | - Compute                 |  | - External TLS certs    |  |
  |  | - Harbor registry         |  +-------------------------+  |
  |  | - Package proxies         |                               |
  |  | - MinIO WORM              |  +-------------------------+  |
  |  | - OSINT proxy             |  | Switzerland (Quad9)     |  |
  |  | - step-ca PKI             |  | - DNS upstream          |  |
  |  | - Hetzner Object Storage  |  | (EU-adequate per FDPIC) |  |
  |  +---------------------------+  +-------------------------+  |
  |                                                               |
  +---------------------------------------------------------------+
  |  Explicitly excluded                                          |
  |  - No US-based DNS (Google, Cloudflare)                       |
  |  - No US-based NTP pools                                      |
  |  - No Docker Hub / ghcr.io / Quay.io in production            |
  |  - No US-based cloud providers (AWS, GCP, Azure)              |
  |  - No US-based CA for external TLS                            |
  +---------------------------------------------------------------+
```

Switzerland is recognised as providing an adequate level of data protection by
the European Commission (adequacy decision), making Quad9's Swiss jurisdiction
compatible with GDPR requirements for DNS query data.
