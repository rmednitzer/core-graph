# OCSF normalisation for core-graph

This document describes how Open Cybersecurity Schema Framework (OCSF) events
are normalised and mapped to Apache AGE graph elements in the core-graph
security events layer (Layer 2). For the overall ontology design and layer
definitions, see [schema-design.md](schema-design.md).

---

## 1. Overview

OCSF provides a vendor-neutral, extensible schema for security telemetry.
Satellite systems (Wazuh, OpenSearch, EDR agents) emit events in their native
formats; the ingest adapters normalise these into OCSF-compliant JSON before
graph ingestion. This normalisation step ensures that events from different
sources share a common vocabulary, enabling cross-source correlation within the
graph.

The OCSF specification organises events into categories, each containing one
or more event classes. core-graph maps each OCSF category to a specific vertex
label in Layer 2. Events that do not fit a recognised category fall through to
the generic `SecurityEvent` vertex.

---

## 2. OCSF categories mapped to graph entities

| OCSF category | OCSF category_uid | Graph vertex label | Notes |
|---|---|---|---|
| System Activity | 1 | `ProcessEvent` | Process creation, termination, module load, injection |
| Findings | 2 | `Finding` | Alerts, detections, policy violations, analytic matches |
| Identity & Access Management | 3 | `AuthEvent` | Authentication, authorisation, account changes, group management |
| Network Activity | 4 | `NetworkActivity` | Connections, flows, DNS queries, HTTP transactions |
| Discovery | 5 | `SecurityEvent` | Device inventory, service enumeration, configuration assessment |
| Application Activity | 6 | `SecurityEvent` | Web activity, API calls, SaaS audit events |
| File System | 7 | `SecurityEvent` | File create, modify, delete, rename events; file observables attached |
| Uncategorized | 0 | `SecurityEvent` | Catch-all for events that do not match a recognised category |

### Vertex properties common to all event types

Every event vertex carries the following baseline properties extracted from
the OCSF envelope:

| Property | Type | OCSF field | Notes |
|---|---|---|---|
| `ocsf_class_uid` | integer | `class_uid` | Numeric event class identifier |
| `ocsf_category_uid` | integer | `category_uid` | Numeric category identifier |
| `ocsf_activity_id` | integer | `activity_id` | What happened within the class |
| `ocsf_severity_id` | integer | `severity_id` | 0-6 severity scale |
| `ocsf_status_id` | integer | `status_id` | Success, failure, or unknown |
| `event_time` | timestamptz | `time` | Event timestamp (ISO 8601, UTC) |
| `message` | text | `message` | Human-readable event description |
| `source_system` | text | `metadata.product.name` | Originating security product |
| `tlp_level` | text | (derived) | Assigned during ingest based on severity mapping |

---

## 3. Structured field mapping

OCSF events contain structured sub-objects that map to canonical entities and
edges in the graph. The ingest pipeline extracts these fields and creates the
corresponding graph elements.

### src_endpoint to CanonicalIP

The `src_endpoint` object contains the source network address. The `ip` field
is normalised and resolved to a `CanonicalIP` vertex using the standard entity
resolution pattern (SHA-256 canonical key, MERGE, `observed_as` edge).

```
OCSF: src_endpoint.ip  -->  CanonicalIP vertex
Edge: EventVertex --observed_as--> CanonicalIP (source_role: 'src')
```

Additional properties from `src_endpoint` (hostname, port, mac) are carried on
the `observed_as` edge as context attributes.

### dst_endpoint to CanonicalIP

Identical handling to `src_endpoint`. The `dst_endpoint.ip` field resolves to a
`CanonicalIP` vertex with `source_role: 'dst'` on the `observed_as` edge.

```
OCSF: dst_endpoint.ip  -->  CanonicalIP vertex
Edge: EventVertex --observed_as--> CanonicalIP (source_role: 'dst')
```

### actor.user to CanonicalPerson

The `actor.user` object identifies the human or service account that initiated
the event. The `name` or `email_addr` field is normalised, pseudonymised
according to the configured policy, and resolved to a `CanonicalPerson` vertex.

```
OCSF: actor.user.name | actor.user.email_addr  -->  CanonicalPerson vertex
Edge: EventVertex --observed_as--> CanonicalPerson (source_role: 'actor')
```

### finding_info to Finding vertex

When an event carries a `finding_info` sub-object (common in Findings-category
events), the ingest pipeline creates a `Finding` vertex with properties
extracted from the finding metadata:

| OCSF field | Graph property | Notes |
|---|---|---|
| `finding_info.title` | `title` | Short description of the finding |
| `finding_info.uid` | `finding_uid` | Unique identifier from the source |
| `finding_info.types` | `finding_types` | Classification tags |
| `finding_info.analytic.name` | `analytic_name` | Detection rule or analytic that fired |
| `finding_info.analytic.uid` | `analytic_uid` | Rule identifier |

A `detected_by` edge connects the Finding to the originating `Source` vertex
(identified by `metadata.product.name`).

### observables[] to individual IOC extraction

The OCSF `observables` array provides pre-extracted indicators of compromise.
Each entry has a `type_id`, `name`, and `value`. The ingest pipeline iterates
over this array and for each entry:

1. Resolves the observable to the appropriate canonical entity type based on
   `type_id`:
   - `type_id: 1` (IP) maps to `CanonicalIP`
   - `type_id: 2` (Domain) maps to `CanonicalDomain`
   - `type_id: 3` (Hostname) maps to `CanonicalDomain`
   - `type_id: 20` (Email) maps to `CanonicalPerson`
   - Other types create an `ExtractedEntity` in the OSINT layer for future
     resolution

2. Creates an `observed_as` edge from the event vertex to the canonical entity
   with the observable `name` as context.

---

## 4. Severity mapping: OCSF severity_id to TLP level

OCSF defines a numeric severity scale (0-6). The ingest pipeline assigns a TLP
marking to each event based on its severity, controlling visibility through
PostgreSQL Row-Level Security.

| OCSF severity_id | Severity label | Assigned TLP level | Rationale |
|---|---|---|---|
| 0 | Unknown | `TLP:WHITE` | No assessed risk; broadly shareable |
| 1 | Informational | `TLP:WHITE` | Routine telemetry |
| 2 | Low | `TLP:GREEN` | Minor anomaly; shareable within community |
| 3 | Medium | `TLP:GREEN` | Notable event; shareable within community |
| 4 | High | `TLP:AMBER` | Significant threat; restricted to organisation |
| 5 | Critical | `TLP:AMBER+STRICT` | Active exploitation; restricted to need-to-know |
| 6 | Fatal | `TLP:RED` | Ongoing breach; named recipients only |

These defaults can be overridden per source system through the ingest adapter
configuration. A Wazuh alert with `severity_id: 4` might be assigned
`TLP:AMBER+STRICT` if the organisational policy treats Wazuh high-severity
alerts as need-to-know.

---

## 5. Edge creation rules

Each event vertex creates edges to connect it to related graph elements. The
specific edges depend on the event category and the structured fields present.

### triggered_by

Created when a `Finding` vertex is linked to the underlying event(s) that
caused it. The Finding references one or more source events through the
`evidences` array or through temporal correlation (events within a configured
time window that share common observables).

```cypher
MATCH (f:Finding {finding_uid: $finding_uid})
MATCH (e:SecurityEvent {ocsf_class_uid: $class_uid, event_time: $event_time})
CREATE (f)-[:triggered_by {
    correlation_method: $method,
    t_recorded: $now
}]->(e)
```

### observed_on

Created for every event that references a network entity (IP address or domain
name). The edge connects the event vertex to the canonical entity and carries
the observation role (source, destination, or other).

```cypher
MATCH (e:NetworkActivity {ocsf_class_uid: $class_uid})
MATCH (c:CanonicalIP {canonical_key: $key})
CREATE (e)-[:observed_on {
    source_role: $role,
    port: $port,
    t_recorded: $now
}]->(c)
```

### detected_by

Created for every `Finding` vertex. The edge points to the `Source` vertex
representing the security product that generated the detection.

```cypher
MATCH (f:Finding {finding_uid: $finding_uid})
MERGE (s:Source {name: $product_name})
CREATE (f)-[:detected_by {
    product_version: $version,
    t_recorded: $now
}]->(s)
```

### correlated_with

Created when two events share common observables or fall within a configured
temporal correlation window. The correlation engine runs as a post-ingest step,
linking events that are likely related but arrived from different source systems.

```cypher
MATCH (e1:SecurityEvent {ocsf_class_uid: $class_uid_1})
MATCH (e2:SecurityEvent {ocsf_class_uid: $class_uid_2})
WHERE e1 <> e2
CREATE (e1)-[:correlated_with {
    shared_observable: $observable_key,
    time_delta_ms: $delta,
    t_recorded: $now
}]->(e2)
```

The `correlated_with` edge is bidirectional in intent but stored as a single
directed edge to avoid duplication. Query patterns should match in both
directions.
