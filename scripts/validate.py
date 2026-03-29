#!/usr/bin/env python3
"""scripts/validate.py — Validation checks for core-graph repository.

Checks:
1. Migration file numbering is sequential with no gaps.
2. YAML syntax in policies/ directory.
3. Basic secret detection in the codebase.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXIT_CODE = 0


def fail(msg: str) -> None:
    """Print failure message and set exit code."""
    global EXIT_CODE  # noqa: PLW0603
    print(f"  FAIL: {msg}", file=sys.stderr)
    EXIT_CODE = 1


def ok(msg: str) -> None:
    """Print success message."""
    print(f"  OK: {msg}")


# -- Check 1: Migration numbering ---------------------------------------------


def check_migration_numbering() -> None:
    """Verify migration files are sequentially numbered with no gaps."""
    print("==> Checking migration file numbering")
    migrations_dir = REPO_ROOT / "schema" / "migrations"
    if not migrations_dir.exists():
        fail("schema/migrations/ directory not found")
        return

    files = sorted(migrations_dir.glob("*.sql"))
    if not files:
        fail("No migration files found")
        return

    numbers: list[int] = []
    for f in files:
        match = re.match(r"^(\d+)_", f.name)
        if not match:
            fail(f"Migration file does not start with a number: {f.name}")
            continue
        numbers.append(int(match.group(1)))

    # Check sequential numbering starting from 1
    for i, num in enumerate(numbers, start=1):
        if num != i:
            fail(f"Expected migration {i:03d}, found {num:03d}")
            return

    ok(f"Migration numbering sequential: 001 through {numbers[-1]:03d}")


# -- Check 2: YAML syntax -----------------------------------------------------


def check_yaml_syntax() -> None:
    """Validate YAML files in policies/ directory."""
    print("==> Checking YAML syntax in policies/")
    policies_dir = REPO_ROOT / "policies"
    if not policies_dir.exists():
        fail("policies/ directory not found")
        return

    yaml_files = list(policies_dir.rglob("*.yaml")) + list(policies_dir.rglob("*.yml"))
    if not yaml_files:
        ok("No YAML files to check")
        return

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("  SKIP: PyYAML not installed, skipping YAML syntax check")
        return

    for yf in yaml_files:
        try:
            with open(yf) as fh:
                yaml.safe_load(fh)
            ok(f"Valid YAML: {yf.relative_to(REPO_ROOT)}")
        except yaml.YAMLError as e:
            fail(f"Invalid YAML in {yf.relative_to(REPO_ROOT)}: {e}")


# -- Check 3: Secret detection ------------------------------------------------

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API key", re.compile(r"(?i)api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]")),
    ("Generic secret", re.compile(r"(?i)secret\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"]")),
    ("Private key header", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
]

IGNORE_DIRS = {".git", "__pycache__", ".pytest_cache", "node_modules", ".venv", "venv"}
IGNORE_EXTENSIONS = {".pyc", ".pyo", ".so", ".dylib", ".png", ".jpg", ".gif", ".ico"}


def check_secrets() -> None:
    """Scan for potential secrets in the codebase."""
    print("==> Checking for potential secrets")

    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORE_DIRS for part in path.parts):
            continue
        if path.suffix in IGNORE_EXTENSIONS:
            continue

        try:
            content = path.read_text(errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue

        for name, pattern in SECRET_PATTERNS:
            if pattern.search(content):
                fail(
                    f"Potential secret ({name}) found in {path.relative_to(REPO_ROOT)} "
                    "(secret contents not logged)"
                )

    ok("No obvious secrets detected")


# -- Main ----------------------------------------------------------------------


def main() -> None:
    """Run all validation checks."""
    check_migration_numbering()
    check_yaml_syntax()
    check_secrets()
    sys.exit(EXIT_CODE)


if __name__ == "__main__":
    main()
