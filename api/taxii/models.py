"""api.taxii.models — Pydantic models for TAXII 2.1 response types."""

from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveryResponse(BaseModel):
    """TAXII 2.1 Discovery response (Section 4.1)."""

    title: str
    description: str | None = None
    contact: str | None = None
    default: str | None = None
    api_roots: list[str] = Field(default_factory=list)


class APIRootResponse(BaseModel):
    """TAXII 2.1 API Root response (Section 4.2)."""

    title: str
    description: str | None = None
    versions: list[str] = Field(default_factory=list)
    max_content_length: int = 10_485_760


class CollectionResource(BaseModel):
    """TAXII 2.1 Collection resource (Section 5.2)."""

    id: str
    title: str
    description: str | None = None
    can_read: bool = True
    can_write: bool = True
    media_types: list[str] = Field(default_factory=lambda: ["application/stix+json;version=2.1"])


class CollectionsResponse(BaseModel):
    """TAXII 2.1 Collections response (Section 5.1)."""

    collections: list[CollectionResource] = Field(default_factory=list)


class STIXBundle(BaseModel):
    """STIX 2.1 Bundle."""

    type: str = "bundle"
    id: str = ""
    objects: list[dict] = Field(default_factory=list)


class StatusResource(BaseModel):
    """TAXII 2.1 Status resource (Section 5.4)."""

    id: str
    status: str = "complete"
    total_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    pending_count: int = 0


class ErrorMessage(BaseModel):
    """TAXII 2.1 Error message (Section 3.6)."""

    title: str
    description: str | None = None
    error_id: str | None = None
    error_code: str | None = None
    http_status: int | None = None
