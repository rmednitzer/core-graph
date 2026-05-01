"""Static checks for the relationship MERGE templates in graph_writer.

After Phase 2 every relationship template must set `e.tlp_level` explicitly
so that we don't rely on the migration-022 trigger as the sole path. The
trigger remains as the safety net but the writer is the documented primary
mechanism for assigning edge TLP.
"""

from __future__ import annotations

import re

from ingest.graph_writer import RELATIONSHIP_TEMPLATES


def test_every_template_sets_tlp_level() -> None:
    missing: list[str] = []
    for rel_type, cypher in RELATIONSHIP_TEMPLATES.items():
        if "tlp_level" not in cypher.lower():
            missing.append(rel_type)
    assert not missing, f"Edge templates missing explicit tlp_level assignment: {missing}"


def test_every_template_uses_greatest_pattern() -> None:
    """tlp_level should derive from the GREATER endpoint TLP."""
    bad: list[str] = []
    for rel_type, cypher in RELATIONSHIP_TEMPLATES.items():
        # Either GREATEST(...) or `case when ... > ... then ... else ... end`.
        has_case = re.search(
            r"case\s+when.+tlp_level.+>.+tlp_level",
            cypher,
            re.DOTALL | re.IGNORECASE,
        )
        has_greatest = re.search(r"greatest\s*\(", cypher, re.IGNORECASE)
        if not (has_case or has_greatest):
            bad.append(rel_type)
    assert not bad, f"Edge templates do not derive tlp_level from endpoints: {bad}"
