"""Static safety scan of Cypher template files.

Apache AGE's openCypher dialect supports `||` for string concatenation but not
`+`. Templates that use `'foo' + ...` parse on Neo4j but fail on AGE. This test
fails CI if any .cypher template uses string concatenation with `+`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

QUERIES_DIR = (
    Path(__file__).resolve().parent.parent
    / "api"
    / "mcp"
    / "skills"
    / "queries"
)

# Match `'…' +` or `+ '…'` or `" … " +` etc. (a `+` adjacent to a string literal).
_CONCAT_PATTERN = re.compile(
    r"""(?x)
        (?: ' [^'\n]* ' \s* \+ )      # 'literal' +
      | (?: " [^"\n]* " \s* \+ )      # "literal" +
      | (?: \+ \s* ' [^'\n]* ' )      # + 'literal'
      | (?: \+ \s* " [^"\n]* " )      # + "literal"
    """
)

_CYPHER_FILES = sorted(QUERIES_DIR.glob("*.cypher"))


@pytest.mark.parametrize(
    "cypher_path",
    _CYPHER_FILES,
    ids=lambda p: p.name,
)
def test_no_string_concatenation_with_plus(cypher_path: Path) -> None:
    """Reject string concatenation with `+` (AGE only supports `||`)."""
    text = cypher_path.read_text()
    matches = _CONCAT_PATTERN.findall(text)
    assert not matches, (
        f"{cypher_path.name}: AGE does not support `+` for string concat. "
        f"Use `||` or compute the value parameter-side. Found: {matches!r}"
    )


def test_at_least_one_template_present() -> None:
    """Sanity: ensure the scan actually saw query templates."""
    assert _CYPHER_FILES, f"No .cypher files under {QUERIES_DIR}"
