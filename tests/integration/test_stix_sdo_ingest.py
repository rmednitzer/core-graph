"""Integration tests for the completed STIX SDO set (ADR-0007 roadmap #1).

Raw STIX intrusion-set / identity / location / report objects published to
``ingest.taxii.*`` flow through the real enrichment worker and graph writer
into AGE, and surface through the TAXII threat-intel collection. This is the
AGE-live MERGE validation the roadmap required before shipping the templates.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from httpx import ASGITransport, AsyncClient

from tests.integration._helpers import poll_cypher

pytestmark = [pytest.mark.integration, pytest.mark.asyncio]

_SUBJECT = "ingest.taxii.threat-intel"


async def _publish_stix(nats_js, obj: dict) -> None:
    await nats_js.publish(_SUBJECT, json.dumps(obj).encode())


def _props(rows) -> dict:
    """Decode an agtype properties() row into a dict (one cast site)."""
    return json.loads(str(rows[0]["props"]))


async def test_intrusion_set_merges_and_updates_without_duplicating(
    nats_js, enrichment_worker, graph_writer, pg_conn
) -> None:
    """An intrusion-set SDO merges once; a newer `modified` updates in place."""
    stix_id = "intrusion-set--11111111-1111-4111-8111-111111111111"
    await _publish_stix(
        nats_js,
        {
            "type": "intrusion-set",
            "id": stix_id,
            "name": "APT Quartz",
            "resource_level": "government",
            "first_seen": "2024-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
        },
    )
    rows = await poll_cypher(
        pg_conn,
        f"""
        select * from ag_catalog.cypher('core_graph', $$
            match (v:IntrusionSet {{stix_id: '{stix_id}'}})
            return v.stix_first_seen
        $$) as (w agtype)
        """,
    )
    assert rows, "IntrusionSet vertex should exist after the two-stage pipeline"
    assert "2024-01-01" in str(rows[0]["w"])

    # A newer STIX version must update the same vertex, not create a second.
    await _publish_stix(
        nats_js,
        {
            "type": "intrusion-set",
            "id": stix_id,
            "name": "APT Quartz (renamed)",
            "modified": "2026-02-01T00:00:00Z",
        },
    )
    rows = await poll_cypher(
        pg_conn,
        f"""
        select * from ag_catalog.cypher('core_graph', $$
            match (v:IntrusionSet {{stix_id: '{stix_id}'}})
            where v.name = 'APT Quartz (renamed)'
            return v.name
        $$) as (w agtype)
        """,
    )
    assert rows, "rename should be applied on the existing vertex"

    cur = await pg_conn.execute(
        f"""
        select * from ag_catalog.cypher('core_graph', $$
            match (v:IntrusionSet {{stix_id: '{stix_id}'}})
            return count(v)
        $$) as (cnt agtype)
        """
    )
    count_rows = await cur.fetchall()
    assert int(str(count_rows[0]["cnt"])) == 1, "update must not duplicate the vertex"
    # The sparse re-report omitted resource_level; coalesce must preserve it.
    cur = await pg_conn.execute(
        f"""
        select * from ag_catalog.cypher('core_graph', $$
            match (v:IntrusionSet {{stix_id: '{stix_id}'}})
            return v.resource_level
        $$) as (rl agtype)
        """
    )
    rl_rows = await cur.fetchall()
    assert "government" in str(rl_rows[0]["rl"])


async def test_identity_location_report_merge_into_age(
    nats_js, enrichment_worker, graph_writer, pg_conn
) -> None:
    """The remaining SDO labels merge; PII fields are never written."""
    await _publish_stix(
        nats_js,
        {
            "type": "identity",
            "id": "identity--22222222-2222-4222-8222-222222222222",
            "name": "ACME Energy",
            "identity_class": "organization",
            "sectors": ["energy"],
            "contact_information": "soc@acme.example",
        },
    )
    await _publish_stix(
        nats_js,
        {
            "type": "location",
            "id": "location--33333333-3333-4333-8333-333333333333",
            "country": "AT",
            "latitude": 48.2,
            "longitude": 16.37,
        },
    )
    await _publish_stix(
        nats_js,
        {
            "type": "report",
            "id": "report--44444444-4444-4444-8444-444444444444",
            "name": "Quartz quarterly",
            "published": "2026-03-01T00:00:00Z",
            "report_types": ["campaign"],
            "object_refs": ["intrusion-set--11111111-1111-4111-8111-111111111111"],
        },
    )

    rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:Identity {stix_id: 'identity--22222222-2222-4222-8222-222222222222'})
            return properties(v)
        $$) as (props agtype)
        """,
    )
    assert rows, "Identity vertex should exist"
    props = _props(rows)
    assert props["identity_class"] == "organization"
    assert "contact_information" not in props, "PII field must never reach the graph"

    rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:Location {stix_id: 'location--33333333-3333-4333-8333-333333333333'})
            return properties(v)
        $$) as (props agtype)
        """,
    )
    assert rows, "Location vertex should exist"
    props = _props(rows)
    assert props["name"] == "AT", "nameless location gets a synthesised display name"
    assert props["latitude"] == 48.2

    rows = await poll_cypher(
        pg_conn,
        """
        select * from ag_catalog.cypher('core_graph', $$
            match (v:Report {stix_id: 'report--44444444-4444-4444-8444-444444444444'})
            return properties(v)
        $$) as (props agtype)
        """,
    )
    assert rows, "Report vertex should exist"
    props = _props(rows)
    assert props["published"] == "2026-03-01T00:00:00Z"
    assert props["object_refs"] == ["intrusion-set--11111111-1111-4111-8111-111111111111"]


async def test_taxii_threat_intel_collection_serves_new_sdo_types(
    nats_js, enrichment_worker, graph_writer, pg_conn
) -> None:
    """The TAXII collection returns the new SDOs (UNION spans the new labels).

    Also exercises the threat-intel label list against live AGE — including
    `Infrastructure`, which is advertised but has no vlabel; AGE returns an
    empty contribution for it rather than erroring.
    """
    from api.rest.main import app

    stix_id = "intrusion-set--55555555-5555-4555-8555-555555555555"
    await _publish_stix(
        nats_js,
        {"type": "intrusion-set", "id": stix_id, "name": "APT Feldspar"},
    )
    await poll_cypher(
        pg_conn,
        f"""
        select * from ag_catalog.cypher('core_graph', $$
            match (v:IntrusionSet {{stix_id: '{stix_id}'}})
            return v.name
        $$) as (w agtype)
        """,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for _ in range(20):
            resp = await client.get(
                "/taxii2/default/collections/threat-intel/objects/",
                params={"match[type]": "intrusion-set", "match[id]": stix_id},
            )
            assert resp.status_code == 200
            bundle = resp.json()
            if bundle.get("objects"):
                break
            await asyncio.sleep(0.3)

    assert bundle["type"] == "bundle"
    ids = {o.get("stix_id") for o in bundle["objects"]}
    assert stix_id in ids, "new SDO must be visible through TAXII get-objects"
