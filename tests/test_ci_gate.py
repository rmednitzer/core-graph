"""Prevent required CI from going green before a blocking PR job finishes."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_aggregate_covers_all_pull_request_validation_jobs() -> None:
    workflows = ROOT / ".github" / "workflows"
    aggregate = yaml.safe_load((workflows / "ci-gate.yml").read_text())
    required = set(aggregate["jobs"]["ci-success"]["env"]["REQUIRED_CHECKS"].splitlines())
    expected = set()
    for filename in ("lint.yml", "test.yml", "security.yml", "eval.yml"):
        workflow = yaml.safe_load((workflows / filename).read_text())
        expected.update(job.get("name", key) for key, job in workflow["jobs"].items())
    assert required == expected
