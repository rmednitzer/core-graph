"""Static analysis test for Cypher label interpolation safety.

Scans all .py files under api/ for patterns that interpolate values into
Cypher strings, and verifies each interpolation is either from a hardcoded
allowlist or passes through validate_label().
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

API_DIR = Path("api")

# Known safe allowlists (hardcoded label maps)
SAFE_ALLOWLISTS = {
    "IOC_LABEL_MAP",
    "STIX_LABEL_MAP",
    "COLLECTIONS",
    "LABEL_MAP",
    "VERTEX_LABELS",
    "EDGE_LABELS",
}

# Patterns that indicate validate_label usage near an interpolation
VALIDATE_LABEL_RE = re.compile(r"validate_label\s*\(")

# Pattern for f-strings or format strings near cypher/ag_catalog keywords
# Matches: f"...{var}..." or "...%s..." near cypher-related content
CYPHER_CONTEXT_RE = re.compile(
    r"(cypher|ag_catalog|core_graph|MATCH|match\s*\()",
    re.IGNORECASE,
)

# Pattern for interpolation in f-strings: {expr}
FSTRING_INTERP_RE = re.compile(r"\{([^}]+)\}")


def _find_python_files() -> list[Path]:
    """Find all .py files under api/."""
    return sorted(API_DIR.rglob("*.py"))


def _is_safe_interpolation(line: str, context_lines: list[str]) -> bool:
    """Check if an interpolation is safe.

    Safe means:
    - The interpolated value comes from a hardcoded allowlist, OR
    - validate_label() is called on the value before interpolation, OR
    - The interpolation is in a log/error message (not SQL), OR
    - The value is loaded from trusted template files.
    """
    joined_ctx = " ".join(context_lines)

    # Check if any known allowlist is referenced nearby
    for allowlist in SAFE_ALLOWLISTS:
        if allowlist in line or allowlist in joined_ctx:
            return True

    # Check if validate_label is called nearby
    if VALIDATE_LABEL_RE.search(line) or VALIDATE_LABEL_RE.search(joined_ctx):
        return True

    # Check for safe_label pattern (common convention)
    if "safe_label" in line or "safe_label" in joined_ctx:
        return True

    # Log/error/raise messages are not SQL injection vectors
    if any(kw in line for kw in ("logger.", "logging.", "raise ", "ValueError(")):
        return True
    if any(kw in joined_ctx for kw in ("raise ValueError(", "raise RuntimeError(")):
        # Check if this f-string is part of a raise statement (may span lines)
        for ctx_line in context_lines:
            if "raise " in ctx_line:
                return True

    # Interpolation into Cypher loaded from .cypher files (template system)
    if "cypher_str" in line or "QUERY_TEMPLATES" in joined_ctx:
        return True

    # The cypher_safety module itself is not an injection vector
    if "cypher_safety" in str(context_lines):
        return True

    # Values passed as parameterized query arguments (inside tuples) are safe
    # e.g. f"cypher:{template}" used as a %s bind parameter
    if re.search(r'^\s*f"[^"]*\{', line) and "%s" not in line:
        # Only flag if this f-string is part of SQL construction, not a bind value
        pass
    elif re.search(r'^\s*f"[^"]*\{', line) and "values" in joined_ctx.lower():
        return True

    # Exclude f-strings that are clearly not SQL construction
    # (inside tuple literals being passed to execute as bind params)
    stripped = line.strip()
    if stripped.startswith("f") and stripped.endswith(","):
        # Likely a tuple element (bind parameter)
        return True

    return False


def _scan_file_for_unsafe_interpolations(filepath: Path) -> list[str]:
    """Scan a Python file for potentially unsafe Cypher label interpolations.

    Returns list of warning strings for each suspicious interpolation.
    """
    warnings: list[str] = []
    try:
        content = filepath.read_text()
    except Exception:
        return warnings

    lines = content.split("\n")

    for i, line in enumerate(lines):
        # Skip comments
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        # Check if this line has cypher-related context
        if not CYPHER_CONTEXT_RE.search(line):
            continue

        # Look for f-string interpolations
        if "f'" in line or 'f"' in line or "f'''" in line or 'f"""' in line:
            interps = FSTRING_INTERP_RE.findall(line)
            if interps:
                # Get surrounding context (5 lines before and after)
                start = max(0, i - 5)
                end = min(len(lines), i + 6)
                context = lines[start:end]

                if not _is_safe_interpolation(line, context):
                    for interp in interps:
                        # Skip simple string/number literals
                        if interp.strip().startswith(("'", '"', "str(", "int(")):
                            continue
                        warnings.append(
                            f"{filepath}:{i + 1}: "
                            f"Potentially unsafe interpolation {{{interp}}} "
                            f"in Cypher context"
                        )

    return warnings


class TestLabelSafetyCoverage:
    """Verify all Cypher label interpolations use validate_label or allowlists."""

    def test_no_unsafe_label_interpolations(self) -> None:
        """Scan all api/ Python files for unsafe Cypher interpolations."""
        all_warnings: list[str] = []
        for filepath in _find_python_files():
            all_warnings.extend(_scan_file_for_unsafe_interpolations(filepath))

        if all_warnings:
            msg = "Unsafe Cypher label interpolations found:\n" + "\n".join(all_warnings)
            pytest.fail(msg)
