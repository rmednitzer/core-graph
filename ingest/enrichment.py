"""ingest.enrichment — normalise raw ``ingest.*`` messages to ``enriched.*``.

This is the "NER + Entity Resolution" stage from the architecture diagram.
The structured connectors that publish directly to ``enriched.*`` (netbox,
keycloak, prometheus) do their own inline mapping; the feed-style connectors
(opencti, misp, osint, wazuh) publish *source-shaped* messages to ``ingest.*``
and rely on this stage to turn them into the canonical entity envelope the
graph writer consumes:

    {"label": "<WritableLabel>", "properties": {...}}   ->  enriched.entity.*

Only labels that the graph writer actually has a MERGE template for are
emitted; STIX SDOs such as ThreatActor / Malware / Campaign have no template
yet (tracked in the audit roadmap) and are reported as deferred rather than
emitted as un-writable vertices that would be silently dropped downstream.

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
    {"CanonicalIP", "CanonicalDomain", "Indicator", "SecurityEvent"}
)

# Required property keys per emitted label, mirroring the MERGE templates'
# match keys (e.g. merge (v:Indicator {value, indicator_type})). An envelope
# missing any of these is dropped rather than merged with NULL match keys.
_REQUIRED_PROPS: dict[str, frozenset[str]] = {
    "CanonicalIP": frozenset({"value"}),
    "CanonicalDomain": frozenset({"value"}),
    "Indicator": frozenset({"value", "indicator_type"}),
    "SecurityEvent": frozenset({"event_id"}),
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
    if subject.startswith("ingest.siem"):
        return entities_from_ocsf(payload, default_tlp)
    if subject.startswith("ingest.threatintel"):
        return entities_from_premapped(payload, default_tlp)
    return []
