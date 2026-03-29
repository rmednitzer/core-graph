"""evidence.signing.minio — MinIO evidence store.

Uploads signed evidence blobs to MinIO with object-lock retention,
verifies lock status, generates pre-signed URLs, and lists objects.
"""

from __future__ import annotations

import io
import logging
from datetime import timedelta
from typing import Any

from minio import Minio
from minio.commonconfig import COMPLIANCE

from api import config

logger = logging.getLogger(__name__)

_client: Minio | None = None


def _get_client() -> Minio:
    """Lazily initialise the MinIO client."""
    global _client
    if _client is None:
        _client = Minio(
            config.MINIO_ENDPOINT,
            access_key=config.MINIO_ACCESS_KEY,
            secret_key=config.MINIO_SECRET_KEY,
            secure=config.MINIO_USE_SSL,
        )
    return _client


def upload_evidence(
    object_name: str,
    data: bytes,
    content_type: str = "application/octet-stream",
    metadata: dict[str, str] | None = None,
    retention_days: int = 2555,
) -> dict[str, Any]:
    """Upload a signed evidence blob to MinIO with object-lock retention.

    Args:
        object_name: Object key in the evidence bucket.
        data: Raw bytes to store.
        content_type: MIME type of the evidence.
        metadata: Optional user metadata.
        retention_days: Retention period in days (default ~7 years).

    Returns:
        Dict with object_name, etag, and version_id.
    """
    client = _get_client()
    bucket = config.MINIO_EVIDENCE_BUCKET

    result = client.put_object(
        bucket,
        object_name,
        io.BytesIO(data),
        length=len(data),
        content_type=content_type,
        metadata=metadata,
    )

    logger.info(
        "Uploaded evidence %s (etag=%s, version=%s)",
        object_name,
        result.etag,
        result.version_id,
    )

    return {
        "object_name": result.object_name,
        "etag": result.etag,
        "version_id": result.version_id,
    }


def verify_locked(object_name: str) -> bool:
    """Verify that an evidence object exists and is locked.

    Returns True if the object has a COMPLIANCE retention lock.
    """
    client = _get_client()
    bucket = config.MINIO_EVIDENCE_BUCKET

    try:
        retention = client.get_object_retention(bucket, object_name)
        return retention.mode == COMPLIANCE
    except Exception:
        logger.warning("Could not verify lock on %s", object_name)
        return False


def presigned_url(
    object_name: str,
    expires: timedelta = timedelta(hours=1),
) -> str:
    """Generate a time-limited pre-signed URL for auditor access.

    Args:
        object_name: Object key in the evidence bucket.
        expires: How long the URL should remain valid.

    Returns:
        Pre-signed HTTPS URL string.
    """
    client = _get_client()
    return client.presigned_get_object(
        config.MINIO_EVIDENCE_BUCKET,
        object_name,
        expires=expires,
    )


def list_evidence(prefix: str = "") -> list[dict[str, Any]]:
    """List evidence objects by prefix (e.g., by incident ID).

    Args:
        prefix: Object name prefix to filter by.

    Returns:
        List of dicts with object_name, size, last_modified, etag.
    """
    client = _get_client()
    objects = client.list_objects(
        config.MINIO_EVIDENCE_BUCKET,
        prefix=prefix,
        recursive=True,
    )

    results: list[dict[str, Any]] = []
    for obj in objects:
        results.append(
            {
                "object_name": obj.object_name,
                "size": obj.size,
                "last_modified": obj.last_modified.isoformat() if obj.last_modified else None,
                "etag": obj.etag,
            }
        )
    return results
