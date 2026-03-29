"""api.authz.spicedb — SpiceDB ReBAC client.

Provides relationship-based access control via SpiceDB (Zanzibar model).
All operations are async. Connection errors result in deny-by-default
(fail closed).
"""

from __future__ import annotations

import logging

from authzed.api.v1 import (
    CheckPermissionRequest,
    CheckPermissionResponse,
    DeleteRelationshipsRequest,
    LookupResourcesRequest,
    ObjectReference,
    Relationship,
    RelationshipFilter,
    RelationshipUpdate,
    SubjectReference,
    WriteRelationshipsRequest,
)
from grpcutil import insecure_bearer_token_credentials

from api import config

logger = logging.getLogger(__name__)

_client = None


def _get_client():
    """Lazily initialise the SpiceDB client."""
    global _client
    if _client is None:
        from authzed.api.v1 import Client

        _client = Client(
            config.SPICEDB_ENDPOINT,
            insecure_bearer_token_credentials(config.SPICEDB_TOKEN),
        )
    return _client


async def check_permission(
    subject: str,
    permission: str,
    resource_type: str,
    resource_id: str,
) -> bool:
    """Check if a subject has a permission on a resource.

    Returns False (deny) on any connection or RPC error (fail closed).
    """
    try:
        client = _get_client()
        response = await client.CheckPermission(
            CheckPermissionRequest(
                resource=ObjectReference(object_type=resource_type, object_id=resource_id),
                permission=permission,
                subject=SubjectReference(
                    object=ObjectReference(object_type="user", object_id=subject),
                ),
            )
        )
        return response.permissionship == CheckPermissionResponse.PERMISSIONSHIP_HAS_PERMISSION
    except Exception:
        logger.exception("SpiceDB check_permission failed, denying by default")
        return False


async def lookup_resources(
    subject: str,
    permission: str,
    resource_type: str,
) -> list[str]:
    """Return all resource IDs the subject can access with the given permission.

    Returns empty list on error (fail closed).
    """
    try:
        client = _get_client()
        resource_ids: list[str] = []
        async for response in client.LookupResources(
            LookupResourcesRequest(
                resource_object_type=resource_type,
                permission=permission,
                subject=SubjectReference(
                    object=ObjectReference(object_type="user", object_id=subject),
                ),
            )
        ):
            resource_ids.append(response.resource_object_id)
        return resource_ids
    except Exception:
        logger.exception("SpiceDB lookup_resources failed, returning empty")
        return []


async def write_relationship(
    resource_type: str,
    resource_id: str,
    relation: str,
    subject_type: str,
    subject_id: str,
) -> None:
    """Write a relationship tuple to SpiceDB."""
    try:
        client = _get_client()
        await client.WriteRelationships(
            WriteRelationshipsRequest(
                updates=[
                    RelationshipUpdate(
                        operation=RelationshipUpdate.OPERATION_TOUCH,
                        relationship=Relationship(
                            resource=ObjectReference(
                                object_type=resource_type, object_id=resource_id
                            ),
                            relation=relation,
                            subject=SubjectReference(
                                object=ObjectReference(
                                    object_type=subject_type, object_id=subject_id
                                ),
                            ),
                        ),
                    )
                ]
            )
        )
    except Exception:
        logger.exception("SpiceDB write_relationship failed")
        raise


async def delete_relationship(
    resource_type: str,
    resource_id: str,
    relation: str,
    subject_type: str,
    subject_id: str,
) -> None:
    """Delete a relationship tuple from SpiceDB."""
    try:
        client = _get_client()
        await client.DeleteRelationships(
            DeleteRelationshipsRequest(
                relationship_filter=RelationshipFilter(
                    resource_type=resource_type,
                    optional_resource_id=resource_id,
                    optional_relation=relation,
                    optional_subject_filter=SubjectReference(
                        object=ObjectReference(object_type=subject_type, object_id=subject_id),
                    ),
                ),
            )
        )
    except Exception:
        logger.exception("SpiceDB delete_relationship failed")
        raise
