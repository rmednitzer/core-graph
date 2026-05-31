"""Unit tests for ingest.enrichment — the ingest.* -> enriched.* mapping.

These cover the pure mapping logic (no NATS/AGE), which is where silent
data-loss bugs would otherwise hide.
"""

from __future__ import annotations

from ingest import enrichment
from ingest.graph_writer import MERGE_TEMPLATES


def test_writable_labels_are_a_subset_of_graph_writer_templates():
    # The enrichment stage must never emit a label the writer cannot MERGE.
    assert enrichment.WRITABLE_ENTITY_LABELS <= set(MERGE_TEMPLATES)


def test_required_props_match_merge_template_match_keys():
    # Each emitted label declares exactly the merge-key props the template needs.
    assert enrichment._REQUIRED_PROPS["CanonicalIP"] == frozenset({"value"})
    assert enrichment._REQUIRED_PROPS["Indicator"] == frozenset({"value", "indicator_type"})
    assert enrichment._REQUIRED_PROPS["SecurityEvent"] == frozenset({"event_id"})


def test_ioc_entity_ip_maps_to_canonical_ip():
    ent = enrichment.ioc_entity("ipv4", "198.51.100.7", 1, "osint")
    assert ent == {
        "label": "CanonicalIP",
        "properties": {"value": "198.51.100.7", "tlp": 1, "source": "osint"},
    }


def test_ioc_entity_domain_maps_to_canonical_domain():
    ent = enrichment.ioc_entity("domain", "evil.example.org", 2, "osint")
    assert ent["label"] == "CanonicalDomain"
    assert ent["properties"]["value"] == "evil.example.org"
    assert "indicator_type" not in ent["properties"]


def test_ioc_entity_hash_and_url_carry_indicator_type():
    h = enrichment.ioc_entity("sha256", "a" * 64, 1, "osint")
    assert h["label"] == "Indicator"
    assert h["properties"]["indicator_type"] == "sha256"
    u = enrichment.ioc_entity("url", "https://bad.example/x", 1, "osint")
    assert u["properties"]["indicator_type"] == "url"


def test_ioc_entity_unmappable_or_empty_returns_none():
    assert enrichment.ioc_entity("yara_rule", "rulename", 1, "osint") is None
    assert enrichment.ioc_entity("ipv4", "", 1, "osint") is None
    assert enrichment.ioc_entity(None, "x", 1, "osint") is None


def test_entities_from_osint_uses_label_as_ioc_type():
    payload = {"label": "domain", "value": "bad.example.com", "source": "feedX"}
    out = enrichment.entities_from_osint(payload, default_tlp=1)
    assert len(out) == 1
    assert out[0]["label"] == "CanonicalDomain"
    assert out[0]["properties"]["source"] == "feedX"


def test_premapped_misp_envelope_passes_through():
    # MISP already produces template-backed envelopes; they should survive.
    payload = {
        "label": "Indicator",
        "properties": {"value": "1.2.3.4", "indicator_type": "ip-src", "tlp": 2},
        "source": "misp",
    }
    out = enrichment.entities_from_premapped(payload, default_tlp=1)
    # The stage emits {label, properties} only; the top-level "source" is folded
    # into properties.source and not echoed back at the envelope top level.
    assert out == [
        {
            "label": "Indicator",
            "properties": {
                "value": "1.2.3.4",
                "indicator_type": "ip-src",
                "tlp": 2,
                "source": "misp",
            },
        }
    ]


def test_premapped_sdo_without_stix_id_is_dropped():
    # SDOs identify on stix_id; an envelope lacking it must not merge an
    # anonymous vertex.
    payload = {"label": "ThreatActor", "properties": {"name": "APT-X", "tlp": 2}}
    assert enrichment.entities_from_premapped(payload, default_tlp=1) == []


def test_premapped_sdo_with_stix_id_is_emitted():
    # OpenCTI/MISP envelopes carrying a stix_id now produce a writable SDO.
    payload = {
        "label": "ThreatActor",
        "properties": {
            "stix_id": "threat-actor--1234",
            "name": "APT-X",
            "aliases": ["GroupX"],
            "tlp": 2,
        },
        "source": "opencti",
    }
    out = enrichment.entities_from_premapped(payload, default_tlp=1)
    assert len(out) == 1
    assert out[0]["label"] == "ThreatActor"
    assert out[0]["properties"]["stix_id"] == "threat-actor--1234"
    assert out[0]["properties"]["aliases"] == ["GroupX"]
    assert out[0]["properties"]["tlp"] == 2
    assert out[0]["properties"]["source"] == "opencti"
    assert out[0]["properties"]["stix_type"] == "threat-actor"  # TAXII match[type]


def test_premapped_sdo_empty_optionals_become_null_to_preserve_on_merge():
    # Connectors default absent optional SDO fields to []/"" (e.g. OpenCTI's
    # malware_types). The normaliser collapses those empties to None so the graph
    # writer's ON MATCH coalesce() preserves previously-enriched values instead
    # of overwriting a populated vertex with an empty partial update. Legitimate
    # scalars such as is_family=False are preserved as-is.
    payload = {
        "label": "Malware",
        "properties": {
            "stix_id": "malware--empty",
            "name": "EmptyPartial",
            "malware_types": [],
            "kill_chain_phases": [],
            "is_family": False,
            "description": "",
            "tlp": 2,
        },
        "source": "opencti",
    }
    out = enrichment.entities_from_premapped(payload, default_tlp=1)
    assert len(out) == 1
    props = out[0]["properties"]
    assert props["malware_types"] is None
    assert props["kill_chain_phases"] is None
    assert props["description"] is None
    # False is a real value, not "absent": it must survive to the writer.
    assert props["is_family"] is False


def test_premapped_indicator_missing_value_is_dropped():
    payload = {"label": "Indicator", "properties": {"indicator_type": "url", "tlp": 1}}
    assert enrichment.entities_from_premapped(payload, default_tlp=1) == []


def test_premapped_stix_indicator_pattern_is_exploded():
    payload = {
        "label": "Indicator",
        "properties": {
            "pattern": "[ipv4-addr:value = '198.51.100.1'] OR [domain-name:value = 'bad.example']",
            "tlp": 2,
        },
        "source": "opencti",
    }
    out = enrichment.entities_from_premapped(payload, default_tlp=1)
    labels = sorted(e["label"] for e in out)
    assert labels == ["CanonicalDomain", "CanonicalIP"]
    assert all(e["properties"]["tlp"] == 2 for e in out)


def test_ocsf_event_yields_security_event_and_observables():
    event = {
        "category": "network_activity",
        "severity_id": 7,
        "finding_info": {"uid": "5710"},
        "observables": [
            {"type": "ip", "value": "203.0.113.5"},
            {"type": "user", "value": "root"},
            {"type": "hash_sha256", "value": "b" * 64},
        ],
    }
    out = enrichment.entities_from_ocsf(event, default_tlp=1)
    by_label = {e["label"] for e in out}
    # SecurityEvent + CanonicalIP + Indicator(hash); the user observable is skipped.
    assert by_label == {"SecurityEvent", "CanonicalIP", "Indicator"}
    sec = next(e for e in out if e["label"] == "SecurityEvent")
    assert sec["properties"]["category"] == "network_activity"
    assert sec["properties"]["severity"] == 7
    assert sec["properties"]["event_id"].startswith("5710:")


def test_ocsf_event_id_is_deterministic_per_event():
    event = {"category": "finding", "severity_id": 3, "observables": []}
    a = enrichment.entities_from_ocsf(event, 1)[0]["properties"]["event_id"]
    b = enrichment.entities_from_ocsf(dict(event), 1)[0]["properties"]["event_id"]
    assert a == b  # identical events merge idempotently


def test_enrich_dispatches_by_subject_prefix():
    assert enrichment.enrich("ingest.osint.feedX", {"label": "ipv4", "value": "8.8.8.8"})
    assert enrichment.enrich("ingest.siem.alerts", {"category": "x", "observables": []})
    assert enrichment.enrich(
        "ingest.threatintel.misp",
        {"label": "CanonicalIP", "properties": {"value": "9.9.9.9"}},
    )
    assert enrichment.enrich("ingest.unknown.x", {"foo": "bar"}) == []


def test_raw_stix_observable_maps_to_canonical_ip():
    obj = {"type": "ipv4-addr", "value": "198.51.100.9"}
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert out == [
        {
            "label": "CanonicalIP",
            "properties": {"value": "198.51.100.9", "tlp": 1, "source": "taxii"},
        }
    ]


def test_raw_stix_indicator_pattern_exploded():
    obj = {"type": "indicator", "pattern": "[domain-name:value = 'bad.example']"}
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert [e["label"] for e in out] == ["CanonicalDomain"]


def test_raw_stix_file_hashes_become_indicators():
    obj = {"type": "file", "hashes": {"SHA-256": "c" * 64, "MD5": "d" * 32}}
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    types = sorted(e["properties"]["indicator_type"] for e in out)
    assert types == ["md5", "sha256"]


def test_raw_stix_sdo_without_id_is_dropped():
    assert enrichment.entities_from_stix_object({"type": "malware", "name": "X"}, 1) == []


def test_raw_stix_unsupported_sdo_is_deferred():
    # intrusion-set has no writer template; defer rather than emit un-writable.
    obj = {"type": "intrusion-set", "id": "intrusion-set--9", "name": "Y"}
    assert enrichment.entities_from_stix_object(obj, 1) == []


def test_raw_stix_malware_sdo_is_emitted():
    obj = {
        "type": "malware",
        "id": "malware--abcd",
        "name": "Emotet",
        "malware_types": ["trojan"],
        "is_family": True,
    }
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert len(out) == 1
    assert out[0]["label"] == "Malware"
    assert out[0]["properties"]["stix_id"] == "malware--abcd"
    assert out[0]["properties"]["malware_types"] == ["trojan"]
    assert out[0]["properties"]["source"] == "taxii"
    assert out[0]["properties"]["stix_type"] == "malware"  # TAXII match[type]


def test_raw_stix_vulnerability_extracts_cve_id():
    obj = {
        "type": "vulnerability",
        "id": "vulnerability--v1",
        "name": "CVE-2026-0001",
        "external_references": [{"source_name": "cve", "external_id": "CVE-2026-0001"}],
    }
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert out[0]["label"] == "Vulnerability"
    assert out[0]["properties"]["cve_id"] == "CVE-2026-0001"


def test_raw_stix_attack_pattern_extracts_mitre_id():
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--ap1",
        "name": "Spearphishing",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T1566"}],
    }
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert out[0]["properties"]["mitre_id"] == "T1566"


def test_raw_stix_sdo_marking_is_honoured():
    obj = {
        "type": "threat-actor",
        "id": "threat-actor--ta1",
        "name": "APT-Y",
        "object_marking_refs": ["marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"],
    }
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert out[0]["properties"]["tlp"] == 4


def test_stix_tlp_marking_is_honoured_not_defaulted():
    # TLP:RED marking must win over the GREEN default, never under-classify.
    obj = {
        "type": "ipv4-addr",
        "value": "203.0.113.9",
        "object_marking_refs": ["marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"],
    }
    out = enrichment.entities_from_stix_object(obj, default_tlp=1)
    assert out[0]["properties"]["tlp"] == 4


def test_enrich_routes_taxii_and_api():
    # TAXII raw STIX -> threatintel handler; API OCSF -> ocsf handler.
    assert enrichment.enrich("ingest.taxii.c1", {"type": "ipv4-addr", "value": "1.1.1.1"})
    assert enrichment.enrich("ingest.api.events", {"category": "finding", "class_uid": 1})


def test_sdo_templates_only_reference_params_the_normaliser_emits():
    # The SDO MERGE templates are not exercised by the unit suite (they need a
    # live AGE), so guard the runtime failure mode that matters: every $param a
    # template references must be produced by sdo_entity (plus $now, which the
    # writer injects), else AGE raises "parameter does not exist" at write time.
    import re

    from ingest.graph_writer import MERGE_TEMPLATES

    # A maximally-populated source so sdo_entity emits its full key set.
    full_src = {
        "id": "x--1",
        "type": "x",
        "name": "n",
        "stix_type": "x",
        "created": "c",
        "modified": "m",
        "confidence": 50,
        "description": "d",
        "aliases": [],
        "roles": [],
        "goals": [],
        "sophistication": "",
        "resource_level": "",
        "primary_motivation": "",
        "malware_types": [],
        "is_family": True,
        "kill_chain_phases": [],
        "objective": "",
        "external_references": [],
        "mitre_id": "",
        "cve_id": "",
        "tool_types": [],
        "first_seen": "",
        "last_seen": "",
    }
    for stix_type, label in enrichment._STIX_TYPE_TO_SDO.items():
        ent = enrichment.sdo_entity(
            label, dict(full_src, type=stix_type, stix_type=stix_type), 2, "t"
        )
        produced = set(ent["properties"]) | {"now"}
        referenced = set(re.findall(r"\$(\w+)", MERGE_TEMPLATES[label])) - {"1"}
        missing = referenced - produced
        assert not missing, f"{label} template references unproduced params: {sorted(missing)}"
