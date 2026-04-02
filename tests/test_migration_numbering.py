"""Tests for migration file sequencing and naming."""

import re
from pathlib import Path


def test_migration_numbering_sequential() -> None:
    """All migration files are sequentially numbered with no gaps."""
    migrations = sorted(Path("schema/migrations").glob("*.sql"))
    numbers: list[int] = []
    for f in migrations:
        m = re.match(r"^(\d+)_", f.name)
        assert m, f"Migration {f.name} does not start with a number"
        numbers.append(int(m.group(1)))

    for i, num in enumerate(numbers, start=1):
        assert num == i, f"Gap in migrations: expected {i:03d}, got {num:03d}"
