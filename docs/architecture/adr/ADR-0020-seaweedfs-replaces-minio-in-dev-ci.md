# ADR-0020: SeaweedFS replaces MinIO as the dev/CI object store

## Status

Accepted (recorded 2026-10-04). Scope: the Docker Compose stack used for
development and CI. The production evidence store is **not** decided here (see
"Not decided here").

## Context

The compose stack needs an S3 endpoint with Object Lock, because
`scripts/init-minio.sh` creates a lock-enabled `evidence` bucket with a 7-year
COMPLIANCE default and `evidence.signing.minio.verify_locked()` reads
`GetObjectRetention`.

Upstream MinIO is no longer a viable source of that image:

* 2026-09-11 to 2026-09-12: the `minio/minio` Docker Hub repository was
  withdrawn. PR #124 moved the pull to `quay.io/minio/minio`.
* 2026-10-02: the nightly `Eval` workflow began failing at `docker compose up`
  with `unauthorized: access to the requested resource is not authorized`.
  `quay.io/minio/minio` now answers HTTP 401 to an anonymous manifest request.
  Every job that starts the stack fails (`Eval`, and `integration-test` and
  `retrieval-eval` on PR #135).
* The upstream repository was archived on 2026-04-25 and the community edition
  is source-only, so a new pinned image will not appear.

## Options

1. **Do nothing.** Dev/CI stays red. Rejected.
2. **`pgsty/minio` community fork.** Smallest diff, same S3 and `mc` behaviour.
   Rejected: it keeps a dependency on a retired project through a third-party
   publisher whose provenance and signing were not verified, and it was never
   exercised against this repository.
3. **Garage.** Light and actively maintained, but it does not implement S3
   Object Lock. The lock is the requirement, so it is excluded.
4. **RustFS.** Apache-2.0 and positioned as a MinIO successor, but its
   releases are still `1.0.0-alpha.*`. Not evaluated further.
5. **Ceph RGW.** Supports Object Lock but is far heavier than a dev stack
   warrants. Not evaluated further.
6. **SeaweedFS.** Apache-2.0, Go, self-hostable with no external control
   plane, official images updated daily with cosign signature tags, S3 Object
   Lock with GOVERNANCE and COMPLIANCE modes and bucket default retention.

## Decision

Use **SeaweedFS 4.48** (`chrislusf/seaweedfs`, pinned by digest) for the
`minio` compose service. The service name, volume, port 9000 and the
`CG_MINIO_*` variables are unchanged so the S3 client code does not move. The
MinIO console port (9001) is dropped because SeaweedFS has none.
`scripts/init-minio.sh` now uses the `minio` Python SDK instead of the `mc`
client, which belonged to the retired project.

## Evidence

The release binary (4.48, md5 matched the published checksum) was run with the
container's effective settings (`TZ=UTC`, `GODEBUG=fips140=on`,
`-dir -volume.max=0 -master.volumeSizeLimitMB=1024 -s3`) and driven with this
repository's code:

| Check | Result |
|---|---|
| `init-minio.sh` on a fresh store, and re-run on existing buckets | passes both |
| bucket default retention reads back as COMPLIANCE, 7 years | yes |
| `upload_evidence`, `list_evidence`, `presigned_url`, readiness `bucket_exists` | work |
| `verify_locked()` on a locked object | `True` |
| deleting a locked object version | `AccessDenied` |
| shortening retention, or switching COMPLIANCE to GOVERNANCE | `AccessDenied` |

Not tested: the container image itself (no Docker daemon was available), so the
compose healthcheck and the entrypoint path were read from the image config and
`entrypoint.sh` but not executed. CI is the first real run of those.

## Consequences

* **Timezone dependency.** With a non-UTC local zone SeaweedFS returns
  `RetainUntilDate` as `...+02:00`; minio-py only parses `...Z`, so
  `verify_locked()` returns `False` for a locked object. The compose service
  pins `TZ=UTC`. Any other deployment of SeaweedFS for this code must do the
  same. A worthwhile upstream report, not pursued here.
* **Open core.** `weed version` advertises an enterprise edition. The features
  used here are in the Apache-2.0 build; revisit if that changes.
* **Naming debt.** `minio` survives in the service name, `CG_MINIO_*`, the
  module `evidence/signing/minio.py` and the `minio` PyPI client. Renaming is a
  separate, larger change. The PyPI client is a generic S3 client and works
  against SeaweedFS, but it is also published by the retired project.
* **Reversibility.** One compose block, one script and docs. Rollback is
  reverting this change; the S3 surface the code uses is unchanged.

## Not decided here

The production evidence store is documented as self-hosted MinIO
(`docs/architecture/data-residency.md`, the compliance maps, break-glass and
backup runbooks). With upstream archived, production gets no security fixes
from upstream. That is a real exposure for a WORM evidence store, and it needs
its own decision covering migration of retained COMPLIANCE objects, which
cannot be rewritten before their retention expires. This ADR changes none of
those documents.
