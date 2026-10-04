#!/usr/bin/env bash
# init-minio.sh — Post-startup object-store bucket initialisation.
# Creates the evidence bucket with Object Lock and a 7-year COMPLIANCE default
# retention, and the backups bucket. Idempotent: safe to re-run.
#
# The dev/CI store is SeaweedFS (ADR-0020), reached over S3. This script used
# the MinIO `mc` client before; it now uses the `minio` Python SDK that the
# project already depends on, so no extra tool is needed. Run it from an
# environment where core-graph is installed (`pip install .`).
#
# Object Lock can only be enabled when a bucket is created, so a pre-existing
# `evidence` bucket without it is reported as an error rather than altered.

set -euo pipefail

MINIO_ENDPOINT="${CG_MINIO_ENDPOINT:-localhost:9000}"
MINIO_USER="${CG_MINIO_ACCESS_KEY:-cg_admin}"
MINIO_PASS="${CG_MINIO_SECRET_KEY:-cg_dev_only_minio}"
MINIO_SECURE="${CG_MINIO_USE_SSL:-false}"
RETENTION_YEARS="${CG_EVIDENCE_RETENTION_YEARS:-7}"

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

export MINIO_ENDPOINT MINIO_USER MINIO_PASS MINIO_SECURE RETENTION_YEARS

python3 - <<'PY'
import os
import sys

from minio import Minio
from minio.commonconfig import COMPLIANCE
from minio.objectlockconfig import YEARS, ObjectLockConfig

client = Minio(
    os.environ["MINIO_ENDPOINT"],
    access_key=os.environ["MINIO_USER"],
    secret_key=os.environ["MINIO_PASS"],
    secure=os.environ["MINIO_SECURE"].lower() == "true",
)
years = int(os.environ["RETENTION_YEARS"])

print("==> Creating evidence bucket with object-lock")
if client.bucket_exists("evidence"):
    print("    Bucket evidence already exists")
else:
    client.make_bucket("evidence", object_lock=True)

print(f"==> Setting default COMPLIANCE retention ({years}y)")
try:
    client.set_object_lock_config("evidence", ObjectLockConfig(COMPLIANCE, years, YEARS))
except Exception as exc:  # noqa: BLE001 - surface any S3 error as a clear failure
    print(f"ERROR: evidence bucket has no usable Object Lock ({exc}).", file=sys.stderr)
    print("       It must be created with Object Lock; recreate it.", file=sys.stderr)
    sys.exit(1)

print("==> Creating backups bucket")
if client.bucket_exists("backups"):
    print("    Bucket backups already exists")
else:
    client.make_bucket("backups")

print("==> Bucket status")
for bucket in client.list_buckets():
    print(f"    {bucket.name}")
print("==> Object store initialisation complete")
PY
