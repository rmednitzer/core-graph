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
  (the permissive arm is elected).
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
DENIED_BARE = {"GPL", "AGPL", "SSPL", "GPLv2", "GPLv3", "AGPLv3"}

# Trove classifier substrings for packages that publish no expression field.
DENIED_CLASSIFIER_MARKERS = (
    "GNU General Public License",
    "GNU Affero General Public License",
    "Server Side Public License",
)
ALLOWED_CLASSIFIER_MARKERS = ("Lesser General Public License",)

# package name (normalised) -> justification, for explicitly reviewed
# exceptions. Empty at introduction; additions require a NOTICE update.
ALLOWLIST: dict[str, str] = {}


def _expression_tokens(expression: str) -> list[str]:
    for ch in "()":
        expression = expression.replace(ch, " ")
    return expression.split()


def _token_denied(token: str) -> bool:
    return token in DENIED_BARE or any(token.startswith(p) for p in DENIED_PREFIXES)


def _expression_denied(expression: str) -> bool:
    """True when every OR-arm of the expression contains a denied license."""
    tokens = _expression_tokens(expression)
    if not any(_token_denied(t) for t in tokens):
        return False
    # Dual-licensed: pass when an OR exists and some license token is clean.
    if any(t.upper() == "OR" for t in tokens):
        license_tokens = [t for t in tokens if t.upper() not in ("OR", "AND", "WITH")]
        return all(_token_denied(t) for t in license_tokens)
    return True


def _classifiers_denied(classifiers: list[str]) -> bool:
    relevant = [c for c in classifiers if "License" in c]
    for c in relevant:
        if any(m in c for m in ALLOWED_CLASSIFIER_MARKERS):
            continue
        if any(m in c for m in DENIED_CLASSIFIER_MARKERS):
            # Another classifier may state a permissive dual license.
            others = [o for o in relevant if o != c]
            if not others:
                return True
            if all(any(m in o for m in DENIED_CLASSIFIER_MARKERS) for o in others):
                return True
    return False


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
        is_denied = _expression_denied(effective) if effective else _classifiers_denied(classifiers)
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
