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
    assert out == [payload | {"properties": payload["properties"] | {"source": "misp"}}]


def test_premapped_unwritable_sdo_is_dropped():
    # STIX SDOs have no MERGE template yet; do not emit droppable vertices.
    payload = {"label": "ThreatActor", "properties": {"name": "APT-X", "tlp": 2}}
    assert enrichment.entities_from_premapped(payload, default_tlp=1) == []


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


def test_raw_stix_sdo_is_deferred():
    assert enrichment.entities_from_stix_object({"type": "malware", "name": "X"}, 1) == []


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
