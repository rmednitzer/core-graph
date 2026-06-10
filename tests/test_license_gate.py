"""Unit tests for scripts/license_gate.py policy logic.

Pins the SPDX-expression semantics the review found exploitable: WITH-exception
names must not neutralise a denied arm, free-text legacy License fields must be
caught, and dual licensing must elect the permissive arm.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "license_gate", Path(__file__).resolve().parents[1] / "scripts" / "license_gate.py"
)
license_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_spec and license_gate)


def test_plain_denied_families():
    assert license_gate._expression_denied("GPL-3.0-only")
    assert license_gate._expression_denied("AGPL-3.0-or-later")
    assert license_gate._expression_denied("SSPL-1.0")
    assert license_gate._expression_denied("GPL-2.0+")


def test_lgpl_and_permissive_pass():
    assert not license_gate._expression_denied("LGPL-3.0-only")
    assert not license_gate._expression_denied("MIT")
    assert not license_gate._expression_denied("Apache-2.0")


def test_dual_license_elects_the_permissive_arm():
    assert not license_gate._expression_denied("GPL-2.0-only OR MIT")
    assert not license_gate._expression_denied("MIT OR GPL-3.0-or-later")


def test_with_exception_does_not_neutralise_a_denied_arm():
    # Review finding: exception names were counted as clean license tokens,
    # letting an all-GPL expression through.
    assert license_gate._expression_denied("GPL-2.0-only WITH Classpath-exception-2.0")
    assert license_gate._expression_denied(
        "GPL-2.0-only WITH Classpath-exception-2.0 OR GPL-3.0-or-later WITH Classpath-exception-2.0"
    )
    # ... but a genuinely permissive OR-arm still wins.
    assert not license_gate._expression_denied(
        "GPL-2.0-only WITH Classpath-exception-2.0 OR Apache-2.0"
    )


def test_and_composition_denies_when_any_part_is_denied():
    assert license_gate._expression_denied("MIT AND GPL-3.0-only")


def test_legacy_free_text_is_caught():
    # Review finding: prose legacy License fields bypassed the token check.
    assert license_gate._text_denied("GNU General Public License v2.0")
    assert license_gate._text_denied("GNU Affero General Public License v3")
    assert not license_gate._text_denied("GNU Lesser General Public License v3 (LGPLv3)")
    assert not license_gate._text_denied("MIT License")
    assert license_gate._expression_denied("GPL2") or license_gate._text_denied("GPL2")


def test_classifiers_pass_when_any_arm_is_permissive():
    gpl = "License :: OSI Approved :: GNU General Public License v3 (GPLv3)"
    mit = "License :: OSI Approved :: MIT License"
    lgpl = "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)"
    assert license_gate._classifiers_denied([gpl])
    assert not license_gate._classifiers_denied([gpl, mit])  # dual-licensed
    assert not license_gate._classifiers_denied([lgpl])
    assert not license_gate._classifiers_denied([])


def test_scan_runs_against_the_current_environment():
    report, denied = license_gate.scan()
    assert report, "scan should see installed distributions"
    # The dev environment contains GPL tooling (e.g. yamllint); the gate's CI
    # job runs against a runtime-only venv, so only assert shape here.
    assert all({"name", "version", "license", "source"} <= set(r) for r in report)
