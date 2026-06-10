"""Unit tests for the OpenCTI adapter's STIX SDO mapping.

Covers the pre-mapped envelope path the integration suite does not exercise
(it drives the raw-STIX TAXII path): the adapter's `_map_stix_object` output
must compose with `enrichment.entities_from_premapped` so the four SDO types
added in the completion pass survive the full OpenCTI → enriched mapping.
"""

from __future__ import annotations

from ingest import enrichment
from ingest.connectors.opencti.adapter import _map_stix_object

_RED = "marking-definition--826578e1-40ad-459f-bc73-ede076f81f37"


def _enrich(stix_object: dict) -> list[dict]:
    """Run an OpenCTI SSE object through the adapter + enrichment stages."""
    payload = _map_stix_object(stix_object)
    assert payload is not None, "adapter must map this STIX type"
    return enrichment.entities_from_premapped(payload, default_tlp=1)


def test_intrusion_set_maps_and_renames_activity_window():
    out = _enrich(
        {
            "type": "intrusion-set",
            "id": "intrusion-set--a1",
            "name": "APT Quartz",
            "aliases": ["Quartz Group"],
            "resource_level": "government",
            "secondary_motivations": ["coercion"],
            "first_seen": "2024-01-01T00:00:00Z",
            "last_seen": "2026-01-01T00:00:00Z",
            "object_marking_refs": [_RED],
        }
    )
    assert len(out) == 1
    props = out[0]["properties"]
    assert out[0]["label"] == "IntrusionSet"
    assert props["stix_id"] == "intrusion-set--a1"
    assert props["aliases"] == ["Quartz Group"]
    assert props["secondary_motivations"] == ["coercion"]
    assert props["stix_first_seen"] == "2024-01-01T00:00:00Z"
    assert props["stix_last_seen"] == "2026-01-01T00:00:00Z"
    assert "first_seen" not in props and "last_seen" not in props
    assert props["tlp"] == 4  # marking honoured, never under-classified


def test_identity_maps_without_contact_information():
    out = _enrich(
        {
            "type": "identity",
            "id": "identity--b2",
            "name": "ACME Energy",
            "identity_class": "organization",
            "sectors": ["energy"],
            "contact_information": "soc@acme.example",
        }
    )
    props = out[0]["properties"]
    assert out[0]["label"] == "Identity"
    assert props["identity_class"] == "organization"
    assert props["sectors"] == ["energy"]
    assert "contact_information" not in props, "PII field must never be carried"


def test_location_maps_coordinates_and_drops_address_fields():
    out = _enrich(
        {
            "type": "location",
            "id": "location--c3",
            "name": "Vienna",
            "country": "AT",
            "city": "Vienna",
            "latitude": 48.2,
            "longitude": 16.37,
            "street_address": "Ringstrasse 1",
            "postal_code": "1010",
        }
    )
    props = out[0]["properties"]
    assert out[0]["label"] == "Location"
    assert props["country"] == "AT"
    assert props["latitude"] == 48.2
    assert "street_address" not in props and "postal_code" not in props


def test_report_maps_published_and_object_refs():
    out = _enrich(
        {
            "type": "report",
            "id": "report--d4",
            "name": "Quartz quarterly",
            "report_types": ["campaign"],
            "published": "2026-03-01T00:00:00Z",
            "object_refs": ["intrusion-set--a1"],
        }
    )
    props = out[0]["properties"]
    assert out[0]["label"] == "Report"
    assert props["report_types"] == ["campaign"]
    assert props["published"] == "2026-03-01T00:00:00Z"
    assert props["object_refs"] == ["intrusion-set--a1"]


def test_unmapped_stix_type_returns_none():
    assert _map_stix_object({"type": "note", "id": "note--e5"}) is None


def test_adapter_empty_string_defaults_do_not_clobber_on_merge():
    # The adapter defaults absent optionals to ""/[]; enrichment must collapse
    # them to None so the writer's coalesce() preserves existing intelligence.
    out = _enrich({"type": "intrusion-set", "id": "intrusion-set--f6", "name": "X"})
    props = out[0]["properties"]
    assert props["resource_level"] is None
    assert props["aliases"] is None
    assert props["stix_first_seen"] is None
