#!/usr/bin/env python3
"""License-policy gate over the installed runtime dependency closure.

Walks every distribution importable in the current environment, resolves its
license expression (PEP 639 ``License-Expression``, falling back to the legacy
``License`` field, falling back to trove classifiers), writes a JSON report,
and exits non-zero when a *denied* license is found.

Policy (NOTICE / Apache-2.0 distribution):

- Denied: GPL, AGPL, SSPL families — strong copyleft that would encumber
  distributing the platform image. LGPL is deliberately **allowed** (psycopg
  is LGPL-3.0; Python imports of an unmodified library satisfy its terms).
- Dual licenses joined with OR pass when at least one arm is not denied
  (the permissive arm is elected). WITH-exception clauses do not neutralise
  an arm: 'GPL-2.0-only WITH Classpath-exception-2.0' stays denied.
- Missing/unparseable metadata is reported as UNKNOWN but does not fail the
  gate — several upstream wheels simply omit the field; failing on absence
  would make the gate cry wolf. The report artifact keeps them visible.

Run in CI against a venv holding *runtime* dependencies only (``pip install
.``); dev tooling (e.g. the GPL-licensed yamllint) is not distributed and must
not be scanned.

Usage: license_gate.py [--report PATH]
"""

from __future__ import annotations

import argparse
import json
import sys
from importlib import metadata

DENIED_PREFIXES = ("GPL-", "AGPL-", "SSPL-")
DENIED_BARE = {"GPL", "AGPL", "SSPL", "GPL2", "GPL3", "GPLv2", "GPLv3", "AGPL3", "AGPLv3"}

# Free-text markers for the legacy License field and trove classifiers, which
# carry prose ("GNU General Public License v2.0") rather than SPDX tokens.
DENIED_TEXT_MARKERS = (
    "GNU General Public License",
    "GNU Affero General Public License",
    "Server Side Public License",
)
ALLOWED_TEXT_MARKERS = ("Lesser General Public License",)

# package name (normalised) -> justification, for explicitly reviewed
# exceptions. Empty at introduction; additions require a NOTICE update.
ALLOWLIST: dict[str, str] = {}


def _tokens(expression: str) -> list[str]:
    for ch in "()":
        expression = expression.replace(ch, " ")
    return expression.split()


def _token_denied(token: str) -> bool:
    return token in DENIED_BARE or any(token.startswith(p) for p in DENIED_PREFIXES)


def _arm_denied(arm_tokens: list[str]) -> bool:
    """A single OR-arm is denied when any of its license ids is denied.

    Tokens following WITH are SPDX *exception* names (Classpath-exception-2.0,
    ...) — they modify the license but never neutralise it, so they are
    excluded from the check rather than counted as clean license ids.
    """
    license_ids: list[str] = []
    skip_next = False
    for tok in arm_tokens:
        if skip_next:
            skip_next = False
            continue
        if tok.upper() == "WITH":
            skip_next = True
            continue
        if tok.upper() != "AND":
            license_ids.append(tok)
    return any(_token_denied(t) for t in license_ids)


def _expression_denied(expression: str) -> bool:
    """True when every OR-arm of the expression contains a denied license.

    Dual licensing elects the permissive arm: 'GPL-2.0-only OR MIT' passes.
    'GPL-2.0-only WITH Classpath-exception-2.0' stays denied — the exception
    narrows the copyleft but the platform policy keys on the license family.
    """
    tokens = _tokens(expression)
    arms: list[list[str]] = [[]]
    for tok in tokens:
        if tok.upper() == "OR":
            arms.append([])
        else:
            arms[-1].append(tok)
    return all(_arm_denied(arm) for arm in arms if arm)


def _text_denied(text: str) -> bool:
    """Prose check for legacy License fields and classifier strings."""
    if any(m in text for m in ALLOWED_TEXT_MARKERS):
        return False
    return any(m in text for m in DENIED_TEXT_MARKERS)


def _classifiers_denied(classifiers: list[str]) -> bool:
    """Denied when classifiers state a denied license and no permissive one.

    A package may list several License classifiers (dual licensing); it passes
    when at least one is not denied.
    """
    relevant = [c for c in classifiers if "License" in c]
    if not relevant:
        return False
    denied = [c for c in relevant if _text_denied(c)]
    return len(denied) == len(relevant)


def scan() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Return (report_rows, denied_rows) over the current environment."""
    report: list[dict[str, str]] = []
    denied: list[dict[str, str]] = []
    for dist in sorted(metadata.distributions(), key=lambda d: d.metadata["Name"].lower()):
        name = dist.metadata["Name"]
        if name.lower().replace("_", "-") in ("core-graph", "pip", "setuptools", "wheel"):
            continue
        expression = dist.metadata.get("License-Expression") or ""
        legacy = dist.metadata.get("License") or ""
        classifiers = dist.metadata.get_all("Classifier") or []
        effective = expression or legacy
        row = {
            "name": name,
            "version": dist.version,
            "license": effective or "UNKNOWN",
            "source": "expression" if expression else ("legacy" if legacy else "classifier"),
        }
        report.append(row)

        if name.lower().replace("_", "-") in ALLOWLIST:
            continue
        # Precedence: a PEP 639 License-Expression is authoritative SPDX. The
        # legacy License field may carry SPDX tokens *or* prose, so it gets
        # both checks. Classifiers are the last resort (PEP 639 deprecates
        # them, and a stale classifier must not override a clean expression).
        if expression:
            is_denied = _expression_denied(expression)
        elif legacy:
            is_denied = _expression_denied(legacy) or _text_denied(legacy)
        else:
            is_denied = _classifiers_denied(classifiers)
        if is_denied:
            denied.append(row)
    return report, denied


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", default="license-report.json")
    args = parser.parse_args()

    report, denied = scan()
    with open(args.report, "w", encoding="utf-8") as fh:
        json.dump({"packages": report, "denied": denied}, fh, indent=2)
    print(f"license_gate: {len(report)} packages scanned -> {args.report}")

    unknown = [r["name"] for r in report if r["license"] == "UNKNOWN"]
    if unknown:
        print(f"license_gate: {len(unknown)} package(s) without license metadata: ", end="")
        print(", ".join(unknown))

    if denied:
        print("license_gate: DENIED licenses found:", file=sys.stderr)
        for row in denied:
            print(f"  {row['name']}=={row['version']}: {row['license']}", file=sys.stderr)
        return 1
    print("license_gate: no denied licenses in the runtime closure")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
