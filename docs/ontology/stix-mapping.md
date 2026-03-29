# STIX 2.1 mapping to core-graph

This document describes how STIX 2.1 objects are mapped to Apache AGE graph
elements in the core-graph threat intelligence layer (Layer 1). For the overall
ontology design and layer definitions, see [schema-design.md](schema-design.md).

---

## 1. STIX Domain Objects (SDOs) to graph vertices

Each SDO type maps to a dedicated vertex label. Properties are carried as
vertex attributes. All STIX properties use snake_case naming in the graph.

### threat-actor to ThreatActor

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Required |
| `description` | `description` | text | Free-text description |
| `aliases` | `aliases` | text[] | Alternative names |
| `roles` | `roles` | text[] | STIX threat-actor-role-ov |
| `goals` | `goals` | text[] | High-level objectives |
| `sophistication` | `sophistication` | text | STIX threat-actor-sophistication-ov |
| `resource_level` | `resource_level` | text | STIX attack-resource-level-ov |
| `primary_motivation` | `primary_motivation` | text | STIX attack-motivation-ov |

### campaign to Campaign

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Required |
| `description` | `description` | text | |
| `aliases` | `aliases` | text[] | |
| `first_seen` | `first_seen` | timestamptz | ISO 8601, UTC |
| `last_seen` | `last_seen` | timestamptz | ISO 8601, UTC |
| `objective` | `objective` | text | Campaign goal |

### attack-pattern to AttackPattern

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Required |
| `description` | `description` | text | |
| `kill_chain_phases` | `kill_chain_phases` | jsonb | Array of {kill_chain_name, phase_name} |
| `external_references` | `external_references` | jsonb | MITRE ATT&CK IDs, URLs |

### indicator to Indicator

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Human-readable label |
| `description` | `description` | text | |
| `pattern` | `pattern` | text | STIX pattern or other syntax |
| `pattern_type` | `pattern_type` | text | `stix`, `sigma`, `snort`, `yara` |
| `valid_from` | `valid_from` | timestamptz | Start of indicator validity |
| `valid_until` | `valid_until` | timestamptz | End of indicator validity (NULL = indefinite) |

### malware to Malware

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Required |
| `description` | `description` | text | |
| `malware_types` | `malware_types` | text[] | STIX malware-type-ov |
| `is_family` | `is_family` | boolean | True if this represents a family, not a specific sample |
| `kill_chain_phases` | `kill_chain_phases` | jsonb | Array of {kill_chain_name, phase_name} |

### vulnerability to Vulnerability

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Required (typically the CVE ID) |
| `description` | `description` | text | |
| `external_references` | `external_references` | jsonb | CVE ID, NVD URL, advisory links |

The `external_references` array is the primary carrier for CVE identifiers.
Ingest pipelines extract the CVE ID into an indexed `cve_id` property for
direct lookup.

### tool to Tool

| STIX property | Graph property | Type | Notes |
|---|---|---|---|
| `name` | `name` | text | Required |
| `description` | `description` | text | |
| `tool_types` | `tool_types` | text[] | STIX tool-type-ov |
| `kill_chain_phases` | `kill_chain_phases` | jsonb | Array of {kill_chain_name, phase_name} |

---

## 2. STIX Relationship Objects (SROs) to graph edges

STIX relationships map directly to labelled edges in the graph. The
`relationship_type` field in the SRO determines the edge label.

### relationship to edge label

| STIX relationship_type | Graph edge label | Typical source vertex | Typical target vertex |
|---|---|---|---|
| `uses` | `uses` | ThreatActor, Campaign | AttackPattern, Malware, Tool |
| `targets` | `targets` | ThreatActor, Campaign | Vulnerability, CanonicalOrganization |
| `attributed-to` | `attributed_to` | Campaign, Malware | ThreatActor |
| `indicates` | `indicates` | Indicator | ThreatActor, Campaign, Malware |
| `mitigates` | `mitigates` | Tool, AttackPattern | Vulnerability |

### Properties preserved on edges

| STIX property | Graph edge property | Type | Notes |
|---|---|---|---|
| `source_ref` | `source_ref` | text | STIX ID of the source SDO |
| `target_ref` | `target_ref` | text | STIX ID of the target SDO |
| `relationship_type` | `relationship_type` | text | Original STIX relationship type string |
| `start_time` | `start_time` | timestamptz | When the relationship began |
| `stop_time` | `stop_time` | timestamptz | When the relationship ended (NULL = ongoing) |

Edge `source_ref` and `target_ref` are retained for traceability back to the
original STIX bundle even though the graph structure already encodes the
direction.

### sighting to Finding vertex + detected_by edge

STIX sighting objects do not map to simple edges. Instead, each sighting
creates a `Finding` vertex with a `detected_by` edge pointing to the observing
system and a `triggered_by` edge pointing to the sighted SDO.

| STIX sighting property | Graph element | Mapping |
|---|---|---|
| `sighting_of_ref` | `triggered_by` edge | Finding --triggered_by--> referenced SDO |
| `observed_data_refs` | `observed_on` edges | Finding --observed_on--> referenced SCOs |
| `where_sighted_refs` | `detected_by` edge | Finding --detected_by--> observing Source |
| `first_seen` | `first_seen` property | On the Finding vertex |
| `last_seen` | `last_seen` property | On the Finding vertex |
| `count` | `count` property | Number of times sighted |

---

## 3. STIX Cyber-observable Objects (SCOs) to leaf nodes and canonical entities

SCOs represent concrete observables. In core-graph, SCOs are resolved to
canonical entities wherever possible, linking layer-specific vertices to shared
anchor points through `observed_as` edges.

### ipv4-addr to CanonicalIP

The `value` property (e.g., `198.51.100.23`) is normalised and hashed to
produce a `canonical_key`. The ingest pipeline executes a MERGE on
`CanonicalIP` and creates an `observed_as` edge from the referencing Indicator
or Finding.

### ipv6-addr to CanonicalIP

Identical to ipv4-addr handling. The IPv6 address is expanded to full long form
before hashing to ensure consistent canonical keys regardless of abbreviation.

### domain-name to CanonicalDomain

The `value` property is lowercased, the trailing dot is stripped, and IDNA
encoding is applied. The resulting string is hashed to produce the
`canonical_key`. The MERGE and `observed_as` edge creation follow the same
pattern as IP addresses.

### file to hash-based indicators

STIX file objects carry hash properties (`hashes.MD5`, `hashes.SHA-256`,
`hashes.SHA-1`). These are ingested as Indicator vertices with `pattern_type`
set to `stix` and the hash value embedded in the STIX pattern. The file is not
represented as a separate vertex; the hash indicator serves as the graph
representation and links to canonical entities through `observed_as` edges
where the hash was observed.

### email-addr to CanonicalPerson

The `value` property (email address) is normalised to lowercase and resolved
to a `CanonicalPerson` through the entity resolution pipeline. The mapping
is indirect: the email address is treated as an alias, and the `observed_as`
edge preserves the original address as provenance. Pseudonymisation rules from
the configured policy are applied before the canonical key is computed.

---

## 4. Common properties on all STIX vertices

Every vertex derived from a STIX object carries the following standard
properties in addition to the type-specific properties listed above:

| Property | Type | Source | Notes |
|---|---|---|---|
| `stix_id` | text | `id` field | Full STIX identifier (e.g., `threat-actor--uuid`) |
| `stix_type` | text | `type` field | STIX object type string |
| `created` | timestamptz | `created` field | When the STIX object was first created |
| `modified` | timestamptz | `modified` field | When the STIX object was last modified |
| `tlp_level` | text | `object_marking_refs` | Extracted TLP marking (white, green, amber, amber+strict, red) |
| `confidence` | integer | `confidence` field | 0-100 confidence score |
| `created_by_ref` | text | `created_by_ref` field | STIX ID of the identity that created this object |

The `tlp_level` property is extracted from `object_marking_refs` during
ingestion and stored as a first-class property to support PostgreSQL Row-Level
Security policies. RLS filters on `tlp_level` ensure that queries only return
objects the requesting user is cleared to see.

The bitemporal columns (`t_valid`, `t_invalid`, `t_recorded`, `t_superseded`)
are set during ingestion according to the rules described in
[schema-design.md](schema-design.md). The STIX `created` and `modified`
timestamps inform `t_valid`; the ingest timestamp becomes `t_recorded`.
