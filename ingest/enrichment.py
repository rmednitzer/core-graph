"""ingest.enrichment — normalise raw ``ingest.*`` messages to ``enriched.*``.

This is the "NER + Entity Resolution" stage from the architecture diagram.
The structured connectors that publish directly to ``enriched.*`` (netbox,
keycloak, prometheus) do their own inline mapping; the feed-style connectors
(opencti, misp, osint, wazuh) publish *source-shaped* messages to ``ingest.*``
and rely on this stage to turn them into the canonical entity envelope the
graph writer consumes:

    {"label": "<WritableLabel>", "properties": {...}}   ->  enriched.entity.*

Only labels that the graph writer actually has a MERGE template for are
emitted. STIX SDOs (ThreatActor / Malware / Campaign / AttackPattern /
Vulnerability / Tool) are normalised to their canonical envelope keyed on the
STIX id; SDO types without a template (e.g. intrusion-set, identity, location,
report) are still reported as deferred rather than emitted as un-writable
vertices that would be silently dropped downstream.

The functions here are deliberately pure (dict in, list-of-dict out) so the
mapping — the part most prone to silent data-loss bugs — is unit-tested
without a live NATS or AGE stack. enrichment_worker.py owns the I/O.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ingest.ner.tier1_regex import extract_from_stix_pattern

# Entity labels this stage is allowed to emit. MUST stay a subset of
# graph_writer.MERGE_TEMPLATES (enforced by tests/ingest/test_enrichment.py)
# so we never publish an envelope the writer would drop for lack of a template.
WRITABLE_ENTITY_LABELS: frozenset[str] = frozenset(
    {
        "CanonicalIP",
        "CanonicalDomain",
        "Indicator",
        "SecurityEvent",
        # STIX 2.1 SDOs (Layer 1) — the graph writer keys these on stix_id.
        "ThreatActor",
        "Malware",
        "Campaign",
        "AttackPattern",
        "Vulnerability",
        "Tool",
    }
)

# Required property keys per emitted label, mirroring the MERGE templates'
# match keys (e.g. merge (v:Indicator {value, indicator_type})). An envelope
# missing any of these is dropped rather than merged with NULL match keys.
_REQUIRED_PROPS: dict[str, frozenset[str]] = {
    "CanonicalIP": frozenset({"value"}),
    "CanonicalDomain": frozenset({"value"}),
    "Indicator": frozenset({"value", "indicator_type"}),
    "SecurityEvent": frozenset({"event_id"}),
    # STIX SDOs identify on the globally-unique stix_id; name is required so we
    # never merge an anonymous actor/malware vertex.
    "ThreatActor": frozenset({"stix_id", "name"}),
    "Malware": frozenset({"stix_id", "name"}),
    "Campaign": frozenset({"stix_id", "name"}),
    "AttackPattern": frozenset({"stix_id", "name"}),
    "Vulnerability": frozenset({"stix_id", "name"}),
    "Tool": frozenset({"stix_id", "name"}),
}

# IOC type (tier1 NER + STIX-pattern + Wazuh observable forms) -> (label,
# indicator_type). indicator_type is None for the Canonical* labels, whose
# merge key is value alone.
_IOC_LABEL_MAP: dict[str, tuple[str, str | None]] = {
    "ip": ("CanonicalIP", None),
    "ipv4": ("CanonicalIP", None),
    "ipv6": ("CanonicalIP", None),
    "domain": ("CanonicalDomain", None),
    "hostname": ("CanonicalDomain", None),
    "url": ("Indicator", "url"),
    "md5": ("Indicator", "md5"),
    "sha1": ("Indicator", "sha1"),
    "sha256": ("Indicator", "sha256"),
    "hash_md5": ("Indicator", "md5"),
    "hash_sha1": ("Indicator", "sha1"),
    "hash_sha256": ("Indicator", "sha256"),
    "email": ("Indicator", "email-addr"),
    "cve": ("Indicator", "cve"),
    "bitcoin": ("Indicator", "bitcoin-address"),
    "mitre_attack": ("Indicator", "attack-pattern"),
}

# STIX cyber-observable object type -> IOC type (for raw STIX from TAXII).
_STIX_SCO_TO_IOC: dict[str, str] = {
    "ipv4-addr": "ipv4",
    "ipv6-addr": "ipv6",
    "domain-name": "domain",
    "url": "url",
    "email-addr": "email",
}

# STIX file hash algorithm name -> IOC type.
_STIX_HASH_ALGOS: dict[str, str] = {
    "MD5": "md5",
    "SHA-1": "sha1",
    "SHA1": "sha1",
    "SHA-256": "sha256",
    "SHA256": "sha256",
}

# Standard TLP marking-definition UUIDs -> level, so STIX markings from TAXII
# partners are honoured rather than defaulted: a TLP-enforcing platform must
# never under-classify ingested intelligence.
_STIX_TLP_MARKINGS: dict[str, int] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": 0,  # TLP:CLEAR
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": 1,  # TLP:GREEN
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": 2,  # TLP:AMBER
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": 3,  # TLP:AMBER+STRICT
    "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37": 4,  # TLP:RED
}


def _stix_tlp(obj: dict[str, Any], default: int) -> int:
    """Highest TLP level among a STIX object's object_marking_refs."""
    levels = [
        _STIX_TLP_MARKINGS[m] for m in obj.get("object_marking_refs", []) if m in _STIX_TLP_MARKINGS
    ]
    return max(levels) if levels else default


# STIX SDO type -> graph vertex label (only types the writer has a template for;
# intrusion-set/identity/location/report remain deferred).
_STIX_TYPE_TO_SDO: dict[str, str] = {
    "threat-actor": "ThreatActor",
    "malware": "Malware",
    "campaign": "Campaign",
    "attack-pattern": "AttackPattern",
    "vulnerability": "Vulnerability",
    "tool": "Tool",
}
_SDO_LABELS: frozenset[str] = frozenset(_STIX_TYPE_TO_SDO.values())
_SDO_LABEL_TO_STIX_TYPE: dict[str, str] = {v: k for k, v in _STIX_TYPE_TO_SDO.items()}

# Optional property keys per SDO label, mirroring the graph_writer MERGE
# template. The normaliser always emits every key (defaulting to None) so AGE
# never sees a referenced $param that is absent from the agtype map.
_SDO_PROP_KEYS: dict[str, tuple[str, ...]] = {
    "ThreatActor": (
        "description",
        "aliases",
        "roles",
        "goals",
        "sophistication",
        "resource_level",
        "primary_motivation",
    ),
    "Malware": ("description", "malware_types", "is_family", "kill_chain_phases"),
    "Campaign": ("description", "aliases", "objective"),
    "AttackPattern": ("description", "mitre_id", "kill_chain_phases", "external_references"),
    "Vulnerability": ("description", "cve_id", "external_references"),
    "Tool": ("description", "tool_types", "kill_chain_phases"),
}


def _external_id(src: dict[str, Any], source_name: str) -> str | None:
    """Pull external_references[].external_id for a given source_name."""
    for ref in src.get("external_references") or []:
        if str(ref.get("source_name", "")).lower() == source_name:
            return ref.get("external_id")
    return None


def sdo_entity(label: str, src: dict[str, Any], tlp: int, source: str) -> dict[str, Any] | None:
    """Normalise a STIX SDO (raw object or pre-mapped props) to an envelope.

    Always emits the full key set the writer's template references, so a partial
    connector payload can never trigger a missing-``$param`` AGE error. Returns
    None when the identity keys (stix_id, name) are absent.
    """
    stix_id = src.get("stix_id") or src.get("id")
    name = src.get("name")
    if not stix_id or not name:
        return None
    props: dict[str, Any] = {
        "stix_id": stix_id,
        "name": name,
        "tlp": int(tlp),
        "source": source,
        # STIX common fields: the TAXII endpoint filters by stix_type and
        # orders by t_recorded (set by the writer), so an SDO without stix_type
        # is invisible to match[type] requests. created/modified/confidence are
        # carried through so TAXII clients receive the full object.
        "stix_type": src.get("stix_type") or src.get("type") or _SDO_LABEL_TO_STIX_TYPE[label],
        "created": src.get("created"),
        "modified": src.get("modified"),
        "confidence": src.get("confidence"),
    }
    for key in _SDO_PROP_KEYS[label]:
        props[key] = src.get(key)
    if label == "Campaign":
        # Keep the campaign's STIX activity window distinct from the graph-wide
        # first_seen/last_seen ingest bookkeeping the writer maintains.
        props["stix_first_seen"] = src.get("stix_first_seen") or src.get("first_seen")
        props["stix_last_seen"] = src.get("stix_last_seen") or src.get("last_seen")
    if label == "Vulnerability" and not props.get("cve_id"):
        cve = _external_id(src, "cve")
        if not cve and str(name).upper().startswith("CVE-"):
            cve = name
        props["cve_id"] = cve
    if label == "AttackPattern" and not props.get("mitre_id"):
        props["mitre_id"] = _external_id(src, "mitre-attack")
    return {"label": label, "properties": props}


def ioc_entity(
    ioc_type: str | None,
    value: Any,
    tlp: int,
    source: str,
) -> dict[str, Any] | None:
    """Map a typed IOC to a canonical entity envelope, or None if unmappable."""
    if not ioc_type or value in (None, ""):
        return None
    label_type = _IOC_LABEL_MAP.get(str(ioc_type).lower())
    if label_type is None:
        return None
    label, indicator_type = label_type
    props: dict[str, Any] = {"value": str(value), "tlp": int(tlp), "source": source}
    if indicator_type is not None:
        props["indicator_type"] = indicator_type
    return {"label": label, "properties": props}


def _is_emittable(envelope: dict[str, Any]) -> bool:
    """True if the envelope has a writable label with all required props set."""
    label = envelope.get("label")
    if label not in WRITABLE_ENTITY_LABELS:
        return False
    props = envelope.get("properties") or {}
    return all(props.get(k) not in (None, "") for k in _REQUIRED_PROPS[label])


def entities_from_osint(payload: dict[str, Any], default_tlp: int) -> list[dict[str, Any]]:
    """OSINT IOC message {label: <ioc_type>, value, source} -> entity envelope."""
    ent = ioc_entity(
        payload.get("label") or payload.get("type"),
        payload.get("value"),
        int(payload.get("tlp", default_tlp)),
        payload.get("source", "osint"),
    )
    return [ent] if ent else []


def entities_from_premapped(payload: dict[str, Any], default_tlp: int) -> list[dict[str, Any]]:
    """Already-mapped {label, properties} envelopes (misp, opencti).

    A STIX ``indicator`` carries a STIX *pattern* rather than a scalar value;
    its observables are exploded into Canonical*/Indicator entities. Other
    pre-mapped envelopes are emitted as-is when writable, dropped otherwise.
    """
    label = payload.get("label")
    props = dict(payload.get("properties") or {})
    source = payload.get("source") or props.get("source") or "threatintel"
    tlp = int(props.get("tlp", default_tlp))

    if label == "Indicator" and props.get("pattern") and not props.get("value"):
        return entities_from_stix_pattern(props["pattern"], tlp, source)

    if label in _SDO_LABELS:
        ent = sdo_entity(label, props, tlp, source)
        return [ent] if ent else []

    props.setdefault("tlp", tlp)
    props.setdefault("source", source)
    envelope = {"label": label, "properties": props}
    return [envelope] if _is_emittable(envelope) else []


def entities_from_stix_pattern(pattern: str, tlp: int, source: str) -> list[dict[str, Any]]:
    """Explode a STIX 2.1 indicator pattern into canonical entity envelopes."""
    out: list[dict[str, Any]] = []
    for ioc in extract_from_stix_pattern(pattern):
        ent = ioc_entity(ioc["type"], ioc["value"], tlp, source)
        if ent:
            out.append(ent)
    return out


def entities_from_stix_object(obj: dict[str, Any], default_tlp: int) -> list[dict[str, Any]]:
    """Raw STIX 2.1 object (from TAXII) -> canonical entity envelopes.

    Handles SDOs (threat-actor, malware, campaign, attack-pattern,
    vulnerability, tool), indicator patterns, and cyber-observable objects
    (addresses, domains, URLs, files). SDO types without a writer template
    (intrusion-set, identity, location, report, ...) are deferred.
    """
    stix_type = obj.get("type", "")
    tlp = _stix_tlp(obj, default_tlp)
    if stix_type == "indicator" and obj.get("pattern"):
        return entities_from_stix_pattern(obj["pattern"], tlp, "taxii")
    if stix_type in _STIX_TYPE_TO_SDO:
        ent = sdo_entity(_STIX_TYPE_TO_SDO[stix_type], obj, tlp, "taxii")
        return [ent] if ent else []
    if stix_type in _STIX_SCO_TO_IOC:
        ent = ioc_entity(_STIX_SCO_TO_IOC[stix_type], obj.get("value"), tlp, "taxii")
        return [ent] if ent else []
    if stix_type == "file":
        out: list[dict[str, Any]] = []
        for algo, val in (obj.get("hashes") or {}).items():
            ioc_type = _STIX_HASH_ALGOS.get(str(algo).upper())
            ent = ioc_entity(ioc_type, val, tlp, "taxii") if ioc_type else None
            if ent:
                out.append(ent)
        return out
    return []


def entities_from_threatintel(payload: dict[str, Any], default_tlp: int) -> list[dict[str, Any]]:
    """Threat intel by shape: raw STIX (TAXII) vs pre-mapped envelope (opencti/misp)."""
    if "type" in payload and "label" not in payload:
        return entities_from_stix_object(payload, default_tlp)
    return entities_from_premapped(payload, default_tlp)


def entities_from_ocsf(event: dict[str, Any], default_tlp: int) -> list[dict[str, Any]]:
    """Wazuh OCSF-shaped event -> a SecurityEvent plus its IP/hash observables."""
    out: list[dict[str, Any]] = []
    finding = event.get("finding_info") or {}
    # A per-occurrence id: prefer the finding uid, but fold in the event body
    # so distinct alerts sharing a rule id stay distinct vertices while exact
    # redeliveries merge idempotently.
    digest = hashlib.sha256(json.dumps(event, sort_keys=True, default=str).encode()).hexdigest()[
        :32
    ]
    event_id = f"{finding.get('uid', 'wazuh')}:{digest}"

    out.append(
        {
            "label": "SecurityEvent",
            "properties": {
                "event_id": event_id,
                "category": event.get("category", "other"),
                "severity": int(event.get("severity_id", 0) or 0),
                "tlp": default_tlp,
                "source": "wazuh",
            },
        }
    )

    for obs in event.get("observables") or []:
        otype = str(obs.get("type", ""))
        # Wazuh emits user observables, but auto-creating IAM Principals from
        # SIEM telemetry would breach the Layer-8 AMBER floor design; skip them.
        if otype == "user":
            continue
        ent = ioc_entity(otype, obs.get("value"), default_tlp, "wazuh")
        if ent:
            out.append(ent)
    return out


def enrich(subject: str, payload: dict[str, Any], default_tlp: int = 1) -> list[dict[str, Any]]:
    """Dispatch a raw ingest message to entity envelopes by subject prefix."""
    if subject.startswith("ingest.osint"):
        return entities_from_osint(payload, default_tlp)
    if subject.startswith("ingest.siem") or subject.startswith("ingest.api"):
        return entities_from_ocsf(payload, default_tlp)
    if subject.startswith("ingest.threatintel") or subject.startswith("ingest.taxii"):
        return entities_from_threatintel(payload, default_tlp)
    return []
