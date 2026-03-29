#!/usr/bin/env bash
# init-minio.sh — Post-startup MinIO bucket initialisation.
# Creates evidence bucket with object-lock and backups bucket.

set -euo pipefail

MINIO_ENDPOINT="${CG_MINIO_ENDPOINT:-localhost:9000}"
MINIO_USER="${CG_MINIO_ACCESS_KEY:-cg_admin}"
MINIO_PASS="${CG_MINIO_SECRET_KEY:-cg_dev_only_minio}"
ALIAS="cg"

echo "==> Configuring MinIO client"
mc alias set "$ALIAS" "http://${MINIO_ENDPOINT}" "$MINIO_USER" "$MINIO_PASS"

echo "==> Creating evidence bucket with object-lock"
mc mb --with-lock "${ALIAS}/evidence" 2>/dev/null || echo "    Bucket evidence already exists"
mc retention set --default COMPLIANCE 7y "${ALIAS}/evidence" 2>/dev/null || echo "    Retention already configured"

echo "==> Creating backups bucket"
mc mb "${ALIAS}/backups" 2>/dev/null || echo "    Bucket backups already exists"

echo "==> Bucket status"
mc ls "$ALIAS"
echo "==> MinIO initialisation complete"
