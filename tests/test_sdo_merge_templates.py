"""Unit guards for the STIX SDO MERGE templates' ON MATCH semantics.

The MERGE behaviour itself needs a live AGE graph and is exercised by the
integration suite; here we pin the structural invariants that are easy to
regress when editing the (verbatim, parameterised) Cypher template strings.
"""

from __future__ import annotations

import pytest

from ingest.graph_writer import MERGE_TEMPLATES

_SDO_LABELS = (
    "ThreatActor",
    "Malware",
    "Campaign",
    "AttackPattern",
    "Vulnerability",
    "Tool",
    "IntrusionSet",
    "Identity",
    "Location",
    "Report",
)


@pytest.mark.parametrize("label", _SDO_LABELS)
def test_sdo_templates_refresh_t_recorded_only_on_newer_modified(label: str) -> None:
    # Finding: TAXII keyset pagination filters on v.t_recorded, so an in-place
    # update to an already-paged SDO is invisible unless t_recorded advances.
    # Each SDO ON MATCH must bump t_recorded only when the incoming STIX
    # `modified` is newer, so genuine new versions resurface to clients while
    # no-op redeliveries (same modified) don't churn the cursor.
    tmpl = MERGE_TEMPLATES[label]
    assert "v.t_recorded = case" in tmpl, f"{label} ON MATCH must guard t_recorded"
    assert "$modified > coalesce(v.modified" in tmpl, f"{label} must compare modified"


@pytest.mark.parametrize("label", _SDO_LABELS)
def test_sdo_t_recorded_refresh_precedes_modified_assignment(label: str) -> None:
    # The t_recorded comparison reads the *prior* v.modified, so its assignment
    # must come before `v.modified = coalesce(...)` in the ON MATCH SET list.
    tmpl = MERGE_TEMPLATES[label]
    assert tmpl.index("v.t_recorded = case") < tmpl.index("v.modified = coalesce"), (
        f"{label}: t_recorded must be set before v.modified"
    )
