"""ingest.connectors.osint.config — Pydantic models for OSINT feed configuration."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


class FeedSource(BaseModel):
    """Configuration for a single OSINT feed."""

    name: str
    url: str
    format: str = "json"
    interval: int = 300
    subject: str


class FeedsConfig(BaseModel):
    """Top-level configuration for OSINT feeds."""

    feeds: list[FeedSource]


def load_feeds_config(path: str | Path | None = None) -> FeedsConfig:
    """Load feed configuration from a YAML file.

    Args:
        path: Path to YAML config. Defaults to feeds.yaml next to this module.
    """
    if path is None:
        path = Path(__file__).parent / "feeds.yaml"
    with open(path) as f:
        data = yaml.safe_load(f)
    return FeedsConfig(**data)
