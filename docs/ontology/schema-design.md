# Schema design: six-layer unified ontology

> TODO: Migrate full ontology specification from initial research.

## Layers

1. **Threat intelligence** (STIX 2.1 core) - 5 year retention
2. **Security events** (OCSF-normalised) - 1 year retention
3. **OSINT entities** - 5 year retention
4. **Audit and compliance** - 10 year retention
5. **AI conversation memory** (Graphiti-inspired bitemporal) - indefinite
6. **Forensic timeline** - 10 year minimum

## Bitemporal modeling

Every fact carries four timestamps:

- `t_valid`: when the fact became true in the real world
- `t_invalid`: when the fact ceased to be true
- `t_recorded`: when the fact was ingested into the system
- `t_superseded`: when a newer fact replaced this one

Facts are invalidated, never deleted.

## Cross-layer entity resolution

Canonical entity nodes (CanonicalIP, CanonicalDomain, CanonicalPerson,
CanonicalOrganization) with `OBSERVED_AS` edges to source-specific observations
preserving provenance metadata.
