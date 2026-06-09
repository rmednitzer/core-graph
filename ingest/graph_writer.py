"""ingest.graph_writer — Graph upsert worker.

Consumes enriched entities from NATS JetStream and merges them into the
AGE graph using parameterised prepared statements.

Security: All Cypher queries use ag_catalog.cypher() with parameter binding.
Never constructs Cypher strings via concatenation (CVE-2022-45786 mitigation).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import nats
import psycopg
from nats.js.api import ConsumerConfig
from psycopg.rows import dict_row

from api.config import NATS_URL, PG_DSN
from api.utils.edge_tlp import resync_vertex_edges, sync_edges_tlp
from ingest.streams import content_msg_id, ensure_dlq_stream, ensure_enriched_stream

logger = logging.getLogger(__name__)

# Readiness marker. The graph writer is a headless NATS consumer with no HTTP
# port, so the Kubernetes readinessProbe checks for this file. It is created
# only after the JetStream subscription is live (see run()) and removed on
# shutdown, so a pod is reported Ready only while it is actually consuming.
# Resolves to /tmp/graph-writer.ready in-container.
_READY_MARKER = Path(tempfile.gettempdir()) / "graph-writer.ready"

# -- Cypher merge templates (parameterised, never concatenated) ----------------

MERGE_TEMPLATES: dict[str, str] = {
    "CanonicalIP": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:CanonicalIP {value: $value})
            set v.first_seen = coalesce(v.first_seen, $now),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "CanonicalDomain": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:CanonicalDomain {value: $value})
            set v.first_seen = coalesce(v.first_seen, $now),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Indicator": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Indicator {value: $value, indicator_type: $indicator_type})
            set v.first_seen = coalesce(v.first_seen, $now),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "SecurityEvent": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:SecurityEvent {event_id: $event_id})
            set v.time = coalesce(v.time, $now),
                v.category = coalesce(v.category, $category),
                v.severity = coalesce(v.severity, $severity),
                v.tlp_level = coalesce(v.tlp_level, $tlp)
            return id(v)
        $$, %s) as (id agtype)
    """,
    # -- Layer 1: Threat Intelligence (STIX 2.1 SDOs) ------------------------
    # Keyed on the globally-unique STIX id so redeliveries and cross-feed
    # duplicates (OpenCTI + MISP reporting the same actor) merge to one vertex.
    # Property mapping per docs/ontology/stix-mapping.md. first_seen/last_seen
    # are ingest bookkeeping; a campaign's own STIX activity window is carried
    # separately as stix_first_seen/stix_last_seen to avoid clobbering it.
    # On a match, t_recorded (the TAXII date_added cursor) advances only when
    # the STIX `modified` timestamp moves forward — a genuinely new object
    # version — so TAXII keyset clients that already paged past the original
    # still receive the update, while no-op redeliveries (same modified) don't
    # churn the cursor. AGE has no ON CREATE/ON MATCH sub-clauses, so a single
    # SET emulates both: every right-hand side reads the pre-SET property
    # snapshot, so the t_recorded CASE compares against the *prior* `modified`
    # even though `v.modified` is reassigned in the same SET. `v.t_recorded is
    # null` distinguishes the create path (first sight → $now). coalesce() on
    # the other fields preserves existing intelligence when an update omits a
    # field (the enrichment normaliser nulls empty optionals so the preserve
    # actually triggers); tlp_level only ever ratchets up (GREATEST), never
    # exposing a higher-marked object at a lower TLP.
    "ThreatActor": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:ThreatActor {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.aliases = coalesce($aliases, v.aliases),
                v.roles = coalesce($roles, v.roles),
                v.goals = coalesce($goals, v.goals),
                v.sophistication = coalesce($sophistication, v.sophistication),
                v.resource_level = coalesce($resource_level, v.resource_level),
                v.primary_motivation = coalesce($primary_motivation, v.primary_motivation),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Malware": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Malware {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.malware_types = coalesce($malware_types, v.malware_types),
                v.is_family = coalesce($is_family, v.is_family),
                v.kill_chain_phases = coalesce($kill_chain_phases, v.kill_chain_phases),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Campaign": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Campaign {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.aliases = coalesce($aliases, v.aliases),
                v.objective = coalesce($objective, v.objective),
                v.stix_first_seen = coalesce($stix_first_seen, v.stix_first_seen),
                v.stix_last_seen = coalesce($stix_last_seen, v.stix_last_seen),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "AttackPattern": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:AttackPattern {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.mitre_id = coalesce($mitre_id, v.mitre_id),
                v.kill_chain_phases = coalesce($kill_chain_phases, v.kill_chain_phases),
                v.external_references =
                    coalesce($external_references, v.external_references),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Vulnerability": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Vulnerability {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.cve_id = coalesce($cve_id, v.cve_id),
                v.external_references =
                    coalesce($external_references, v.external_references),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Tool": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Tool {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.tool_types = coalesce($tool_types, v.tool_types),
                v.kill_chain_phases = coalesce($kill_chain_phases, v.kill_chain_phases),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    # IntrusionSet carries its STIX activity window as stix_first_seen /
    # stix_last_seen, mirroring Campaign, so it never clobbers the graph-wide
    # first_seen/last_seen ingest bookkeeping.
    "IntrusionSet": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:IntrusionSet {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.aliases = coalesce($aliases, v.aliases),
                v.goals = coalesce($goals, v.goals),
                v.resource_level = coalesce($resource_level, v.resource_level),
                v.primary_motivation = coalesce($primary_motivation, v.primary_motivation),
                v.secondary_motivations =
                    coalesce($secondary_motivations, v.secondary_motivations),
                v.stix_first_seen = coalesce($stix_first_seen, v.stix_first_seen),
                v.stix_last_seen = coalesce($stix_last_seen, v.stix_last_seen),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    # STIX identity (victim orgs, report authors, sectors). contact_information
    # is deliberately not stored: it is the PII-bearing field (emails/phones of
    # individuals) and the platform forbids un-pseudonymised PII in the graph.
    "Identity": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Identity {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.identity_class = coalesce($identity_class, v.identity_class),
                v.sectors = coalesce($sectors, v.sectors),
                v.roles = coalesce($roles, v.roles),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    # street_address / postal_code are deliberately not stored (PII
    # minimisation); region/country/city plus coordinates carry the
    # analytic value.
    "Location": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Location {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.region = coalesce($region, v.region),
                v.country = coalesce($country, v.country),
                v.administrative_area =
                    coalesce($administrative_area, v.administrative_area),
                v.city = coalesce($city, v.city),
                v.latitude = coalesce($latitude, v.latitude),
                v.longitude = coalesce($longitude, v.longitude),
                v.precision = coalesce($precision, v.precision),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Report": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Report {stix_id: $stix_id})
            set v.stix_type = $stix_type,
                v.name = coalesce($name, v.name),
                v.description = coalesce($description, v.description),
                v.report_types = coalesce($report_types, v.report_types),
                v.published = coalesce($published, v.published),
                v.object_refs = coalesce($object_refs, v.object_refs),
                v.created = coalesce(v.created, $created),
                v.t_recorded = case
                    when v.t_recorded is null then $now
                    when $modified is not null
                         and $modified > coalesce(v.modified, '')
                    then $now else v.t_recorded end,
                v.modified = coalesce($modified, v.modified),
                v.confidence = coalesce($confidence, v.confidence),
                v.tlp_level = case when $tlp > coalesce(v.tlp_level, 0)
                                   then $tlp else coalesce(v.tlp_level, 0) end,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    # -- Layer 7: Infrastructure & Assets ------------------------------------
    "Host": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Host {canonical_key: $canonical_key})
            set v.name = coalesce(v.name, $name),
                v.host_type = coalesce(v.host_type, $host_type),
                v.platform = $platform,
                v.status = $status,
                v.site = coalesce(v.site, $site),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.primary_ip = $primary_ip,
                v.netbox_id = $netbox_id,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Network": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Network {prefix: $prefix})
            set v.vlan_id = coalesce(v.vlan_id, $vlan_id),
                v.site = coalesce(v.site, $site),
                v.description = coalesce(v.description, $description),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Site": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Site {name: $name})
            set v.slug = coalesce(v.slug, $slug),
                v.region = coalesce(v.region, $region),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Interface": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Interface {canonical_key: $canonical_key})
            set v.name = coalesce(v.name, $name),
                v.mac_address = coalesce(v.mac_address, $mac_address),
                v.enabled = $enabled,
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Service": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Service {canonical_key: $canonical_key})
            set v.name = coalesce(v.name, $name),
                v.protocol = coalesce(v.protocol, $protocol),
                v.ports = coalesce(v.ports, $ports),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "MonitoringAlert": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:MonitoringAlert {fingerprint: $fingerprint})
            set v.alertname = coalesce(v.alertname, $alertname),
                v.severity = coalesce(v.severity, $severity),
                v.status = $status,
                v.instance = coalesce(v.instance, $instance),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.starts_at = coalesce(v.starts_at, $starts_at),
                v.ends_at = $ends_at,
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    # -- Layer 8: IAM --------------------------------------------------------
    "Principal": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Principal {canonical_key: $canonical_key})
            set v.principal_id = coalesce(v.principal_id, $principal_id),
                v.username = coalesce(v.username, $username),
                v.email = coalesce(v.email, $email),
                v.enabled = $enabled,
                v.created_at = coalesce(v.created_at, $created_at),
                v.last_login = $last_login,
                v.source = coalesce(v.source, $source),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Group": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Group {canonical_key: $canonical_key})
            set v.group_id = coalesce(v.group_id, $group_id),
                v.name = coalesce(v.name, $name),
                v.path = coalesce(v.path, $path),
                v.source = coalesce(v.source, $source),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Role": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Role {canonical_key: $canonical_key})
            set v.role_name = coalesce(v.role_name, $role_name),
                v.realm = coalesce(v.realm, $realm),
                v.client_id = coalesce(v.client_id, $client_id),
                v.source = coalesce(v.source, $source),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "Permission": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:Permission {canonical_key: $canonical_key})
            set v.name = coalesce(v.name, $name),
                v.resource = coalesce(v.resource, $resource),
                v.source = coalesce(v.source, $source),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
    "AccessPolicy": """
        select * from ag_catalog.cypher('core_graph', $$
            merge (v:AccessPolicy {canonical_key: $canonical_key})
            set v.name = coalesce(v.name, $name),
                v.source = coalesce(v.source, $source),
                v.tlp_level = coalesce(v.tlp_level, $tlp),
                v.first_seen = coalesce(v.first_seen, $now),
                v.last_seen = $now
            return id(v)
        $$, %s) as (id agtype)
    """,
}

# -- Relationship merge templates (parameterised, never concatenated) --------

# Relationship MERGE templates set the edge `tlp_level` *property* to GREATEST
# of the two endpoint TLPs. The denormalized `tlp_level` *column* that edge RLS
# (022's tlp_edge_read_policy) actually filters on is maintained by the BEFORE
# trigger trg_edge_tlp_sync — but AGE 1.7 executes Cypher through its own
# executor and does NOT fire user triggers on the label tables, so a Cypher
# MERGE leaves the column at its default 0 (edge RLS would then admit every
# edge). _merge_relationship therefore issues a plain SQL UPDATE on the new
# edge after the MERGE — a SQL write *does* fire the trigger — to populate the
# column. Each template returns id(e) so that UPDATE can target the edge.
RELATIONSHIP_TEMPLATES: dict[str, str] = {
    "has_role": """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: $principal_key})
            match (r:Role {canonical_key: $role_key})
            merge (p)-[e:has_role]->(r)
            set e.source = coalesce(e.source, $source),
                e.t_recorded = coalesce(e.t_recorded, $now),
                e.tlp_level = coalesce(e.tlp_level, case
                    when coalesce(p.tlp_level, 0) > coalesce(r.tlp_level, 0)
                        then coalesce(p.tlp_level, 0)
                    else coalesce(r.tlp_level, 0)
                end)
            return id(p), id(e)
        $$, %s) as (id agtype, edge_id agtype)
    """,
    "member_of": """
        select * from ag_catalog.cypher('core_graph', $$
            match (a {canonical_key: $principal_key})
            match (b {canonical_key: $group_key})
            merge (a)-[e:member_of]->(b)
            set e.source = coalesce(e.source, $source),
                e.t_recorded = coalesce(e.t_recorded, $now),
                e.tlp_level = coalesce(e.tlp_level, case
                    when coalesce(a.tlp_level, 0) > coalesce(b.tlp_level, 0)
                        then coalesce(a.tlp_level, 0)
                    else coalesce(b.tlp_level, 0)
                end)
            return id(a), id(e)
        $$, %s) as (id agtype, edge_id agtype)
    """,
    "grants": """
        select * from ag_catalog.cypher('core_graph', $$
            match (r:Role {canonical_key: $role_key})
            match (p:Permission {canonical_key: $permission_key})
            merge (r)-[e:grants]->(p)
            set e.source = coalesce(e.source, $source),
                e.t_recorded = coalesce(e.t_recorded, $now),
                e.tlp_level = coalesce(e.tlp_level, case
                    when coalesce(r.tlp_level, 0) > coalesce(p.tlp_level, 0)
                        then coalesce(r.tlp_level, 0)
                    else coalesce(p.tlp_level, 0)
                end)
            return id(r), id(e)
        $$, %s) as (id agtype, edge_id agtype)
    """,
    "actor_in": """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: $principal_key})
            match (se:SecurityEvent {event_id: $event_id})
            merge (p)-[e:actor_in]->(se)
            set e.source = coalesce(e.source, $source),
                e.t_recorded = coalesce(e.t_recorded, $now),
                e.tlp_level = coalesce(e.tlp_level, case
                    when coalesce(p.tlp_level, 0) > coalesce(se.tlp_level, 0)
                        then coalesce(p.tlp_level, 0)
                    else coalesce(se.tlp_level, 0)
                end)
            return id(p), id(e)
        $$, %s) as (id agtype, edge_id agtype)
    """,
    "manages": """
        select * from ag_catalog.cypher('core_graph', $$
            match (mgr:Principal {canonical_key: $manager_key})
            match (sub:Principal {canonical_key: $subordinate_key})
            merge (mgr)-[e:manages]->(sub)
            set e.source = coalesce(e.source, $source),
                e.t_recorded = coalesce(e.t_recorded, $now),
                e.tlp_level = coalesce(e.tlp_level, case
                    when coalesce(mgr.tlp_level, 0) > coalesce(sub.tlp_level, 0)
                        then coalesce(mgr.tlp_level, 0)
                    else coalesce(sub.tlp_level, 0)
                end)
            return id(mgr), id(e)
        $$, %s) as (id agtype, edge_id agtype)
    """,
    "owns": """
        select * from ag_catalog.cypher('core_graph', $$
            match (p:Principal {canonical_key: $principal_key})
            match (a {canonical_key: $asset_key})
            merge (p)-[e:owns]->(a)
            set e.source = coalesce(e.source, $source),
                e.t_recorded = coalesce(e.t_recorded, $now),
                e.tlp_level = coalesce(e.tlp_level, case
                    when coalesce(p.tlp_level, 0) > coalesce(a.tlp_level, 0)
                        then coalesce(p.tlp_level, 0)
                    else coalesce(a.tlp_level, 0)
                end)
            return id(p), id(e)
        $$, %s) as (id agtype, edge_id agtype)
    """,
}


def _hash_properties(params: dict) -> str:
    """Compute SHA-256 of canonicalized entity properties for audit."""
    canonical = json.dumps(params, sort_keys=True, default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


async def _write_audit_entry(
    conn: psycopg.AsyncConnection[Any],
    entity_id: int | None,
    entity_label: str,
    operation: str,
    new_value_hash: str | None,
    actor: str,
    correlation_id: uuid.UUID | None = None,
) -> None:
    """Insert an entry into the append-only audit log."""
    await conn.execute(
        """
        insert into audit_log (entity_id, entity_label, operation,
                               new_value_hash, actor, correlation_id)
        values (%s, %s, %s, %s, %s, %s)
        """,
        (entity_id, entity_label, operation, new_value_hash, actor, correlation_id),
    )


async def _merge_entity(
    conn: psycopg.AsyncConnection[Any],
    label: str,
    params: dict[str, Any],
) -> int | None:
    """Execute a parameterised Cypher MERGE and return the vertex id."""
    template = MERGE_TEMPLATES.get(label)
    if template is None:
        logger.warning("No merge template for label %s", label)
        return None

    # AGE expects parameters as a JSON-encoded agtype argument
    agtype_param = json.dumps(params)
    row = await conn.execute(template, (agtype_param,))
    result = await row.fetchone()
    if result:
        return int(str(result["id"]).strip('"'))
    return None


async def _merge_relationship(
    conn: psycopg.AsyncConnection[Any],
    rel_type: str,
    params: dict[str, Any],
) -> int | None:
    """Execute a parameterised Cypher MERGE for an edge and return a vertex id.

    After the MERGE, populate the denormalized ``tlp_level`` column that edge
    RLS filters on: AGE does not fire the ``trg_edge_tlp_sync`` BEFORE trigger
    for Cypher writes, so an explicit SQL UPDATE on the new edge(s) is issued to
    fire it (a SQL write does fire the trigger, which recomputes the column from
    the endpoint TLPs). Without this the column stays 0 and the edge is visible
    to every caller regardless of marking. Every returned row is drained — a
    template whose MATCH clauses bind more than one endpoint combination merges
    one edge per row, and each must be synced.
    """
    template = RELATIONSHIP_TEMPLATES.get(rel_type)
    if template is None:
        logger.warning("No relationship template for type %s", rel_type)
        return None

    params["now"] = datetime.now(UTC).isoformat()
    agtype_param = json.dumps(params)
    cur = await conn.execute(template, (agtype_param,))
    results = await cur.fetchall()
    if not results:
        return None

    edge_ids = [int(str(r["edge_id"]).strip('"')) for r in results]
    await sync_edges_tlp(conn, rel_type, edge_ids)
    return int(str(results[0]["id"]).strip('"'))


async def _process_message(
    conn: psycopg.AsyncConnection[Any],
    msg: Any,
) -> None:
    """Process a single enriched entity or relationship message."""
    try:
        payload = json.loads(msg.data.decode())
    except (json.JSONDecodeError, UnicodeDecodeError):
        logger.error("Invalid message payload, skipping")
        await msg.ack()
        return

    # At-least-once dedup: claim this delivery so a redelivery of an
    # already-committed message is skipped instead of re-audited. The claim
    # shares the transaction with the writes below, so it only becomes durable
    # if the whole unit commits (a failed/rolled-back message is retried).
    # The key is the source delivery id carried through enrichment (_idem) when
    # present, else a content hash of this message. Both are derived from message
    # *content* (see ingest.streams.content_msg_id), never a JetStream
    # (stream, seq) pair, so they survive stream recreation: after a stream is
    # rebuilt its sequences restart at 1 and would otherwise collide with
    # surviving claims in the 90-day ledger, silently suppressing fresh
    # intelligence. A new STIX version hashes differently, so updates are
    # reprocessed rather than deduped.
    delivery_key = payload.get("_idem") or content_msg_id(payload)
    claim = await conn.execute(
        "insert into public.processed_messages (delivery_key) values (%s) "
        "on conflict (delivery_key) do nothing",
        (delivery_key,),
    )
    if claim.rowcount == 0:
        await conn.rollback()
        await msg.ack()
        logger.info("Duplicate delivery %s, skipping", delivery_key)
        return

    # Set RLS session variables
    await conn.execute("select set_config('app.max_tlp', '4', true)")

    correlation_id = uuid.uuid4()

    # Route by subject prefix
    is_relationship = msg.subject.startswith("enriched.relationship.")

    if is_relationship:
        rel_type = payload.get("type", "")
        params = {k: v for k, v in payload.items() if k not in ("type", "_idem")}
        vertex_id = await _merge_relationship(conn, rel_type, params)
        label = f"rel:{rel_type}"
    else:
        label = payload.get("label", "")
        params = payload.get("properties", {})
        params["now"] = datetime.now(UTC).isoformat()

        # IAM entities enforce TLP:AMBER floor at the application layer.
        # This is defense-in-depth alongside the RESTRICTIVE RLS policy in 010.
        _IAM_LABELS = {"Principal", "Group", "Role", "Permission", "AccessPolicy"}
        if label in _IAM_LABELS:
            params["tlp"] = max(params.get("tlp", 2), 2)
        else:
            params.setdefault("tlp", 1)

        vertex_id = await _merge_entity(conn, label, params)

        # Re-classification cascade: if this MERGE raised the vertex's TLP, any
        # edge already incident to it must ratchet up too. AGE does not fire the
        # trg_vertex_tlp_cascade trigger for the Cypher SET above, so invoke the
        # equivalent SQL helper explicitly. It short-circuits on a single
        # indexed probe when the vertex has no edges (the common create path).
        if vertex_id is not None:
            await resync_vertex_edges(conn, vertex_id)

    # Write temporal fact if applicable
    if vertex_id and payload.get("temporal"):
        temporal = payload["temporal"]
        await conn.execute(
            """
            insert into temporal_facts
                (edge_id, edge_label, source_id, target_id,
                 fact_type, fact_value, t_valid, source, confidence)
            values (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                temporal.get("edge_id", 0),
                temporal.get("edge_label", "unknown"),
                temporal.get("source_id", 0),
                temporal.get("target_id", 0),
                temporal.get("fact_type", "observation"),
                json.dumps(temporal.get("fact_value", {})),
                datetime.now(UTC),
                temporal.get("source", "graph_writer"),
                temporal.get("confidence", 0.5),
            ),
        )

    await _write_audit_entry(
        conn,
        entity_id=vertex_id,
        entity_label=label,
        operation="MERGE",
        new_value_hash=_hash_properties(params),
        actor="graph_writer",
        correlation_id=correlation_id,
    )

    await conn.commit()
    await msg.ack()
    logger.info("Merged %s vertex_id=%s correlation=%s", label, vertex_id, correlation_id)


async def run(
    pg_dsn: str | None = None,
    nats_url: str | None = None,
) -> None:
    """Main loop: consume from NATS and write to the graph."""
    nc = await nats.connect(nats_url or NATS_URL)
    js = nc.jetstream()
    await ensure_enriched_stream(js)
    await ensure_dlq_stream(js)

    conn = await psycopg.AsyncConnection.connect(pg_dsn or PG_DSN, row_factory=dict_row)
    await conn.set_autocommit(False)

    # Set AGE search path
    await conn.execute("set search_path = ag_catalog, '$user', public")

    sub = await js.subscribe(
        "enriched.>",
        durable="graph_writer",
        config=ConsumerConfig(ack_wait=30),
    )

    logger.info("Graph writer started, consuming enriched.entity.> and enriched.relationship.>")
    _READY_MARKER.touch(exist_ok=True)

    try:
        async for msg in sub.messages:
            try:
                await _process_message(conn, msg)
            except Exception as exc:
                logger.exception("Error processing message, publishing to DLQ")
                await conn.rollback()
                # Publish to DLQ with error details
                try:
                    dlq_payload = {
                        "original_subject": msg.subject,
                        "payload": json.loads(msg.data.decode()) if msg.data else {},
                        "error": str(exc),
                        "retry_count": 0,
                        "first_failed": datetime.now(UTC).isoformat(),
                    }
                    await js.publish(
                        f"dlq.{msg.subject}",
                        json.dumps(dlq_payload, default=str).encode(),
                    )
                except Exception:
                    logger.exception("Failed to publish to DLQ, nacking message")
                await msg.ack()  # Ack original since it's now in DLQ
    finally:
        _READY_MARKER.unlink(missing_ok=True)
        await conn.close()
        await nc.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    asyncio.run(run())
