"""api.utils.cypher_safety — Cypher structural element validation.

AGE cannot parameterize vertex/edge labels or property keys. Any value
interpolated into a Cypher query string as a structural element must be
validated against PostgreSQL identifier rules before interpolation.

See: CVE-2022-45786
"""

from __future__ import annotations

import re

_LABEL_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]{0,62}$")


def validate_label(label: str) -> str:
    """Validate and return a label safe for Cypher interpolation.

    Raises ValueError if the label contains characters outside the
    PostgreSQL identifier set [a-zA-Z0-9_] or exceeds 63 characters.
    """
    if not _LABEL_RE.match(label):
        raise ValueError(
            f"Invalid Cypher label: {label!r}. Labels must match [a-zA-Z_][a-zA-Z0-9_]{{0,62}}."
        )
    return label
