# Backup and Restore -- pgBackRest

## Overview

pgBackRest provides enterprise PostgreSQL backup for core-graph with
compression, encryption, and parallel operations. It is the sole backup tool
for the canonical PostgreSQL store (Apache AGE + pgvector).

All backups target Hetzner Object Storage (S3-compatible, EU region) to
maintain EU data sovereignty.

## Backup strategy

| Schedule | Type        | Trigger             |
|----------|-------------|---------------------|
| Weekly   | Full        | Sunday 02:00 UTC    |
| Hourly   | Incremental | Every hour, on the hour |
| Continuous | WAL archive | Streaming           |

Retention policy: **4 full backups** (approximately 4 weeks) plus all
incremental backups between them. Expired backups are removed automatically
by pgBackRest after a successful full backup.

WAL archiving runs continuously to enable point-in-time recovery (PITR) to
any moment within the retention window.

## Encryption

- **Algorithm:** AES-256-CBC encryption at rest for all backup files and WAL
  segments stored in the S3 repository.
- **Key management:** The encryption passphrase is managed via Vault or SOPS.
  It is **never** stored in this repository or in any container image.
- **Storage:** Hetzner Object Storage (`fsn1.your-objectstorage.com`),
  S3-compatible, EU region (Falkenstein).

## Configuration

`/etc/pgbackrest/pgbackrest.conf`:

```ini
[core-graph]
pg1-path=/var/lib/postgresql/16/main

[global]
repo1-type=s3
repo1-s3-endpoint=fsn1.your-objectstorage.com
repo1-s3-bucket=cg-backups
repo1-s3-region=eu-central
repo1-cipher-type=aes-256-cbc
repo1-retention-full=4
process-max=4
compress-type=zst
compress-level=6
```

The `repo1-cipher-pass` value is injected at runtime from Vault/SOPS via
environment variable `PGBACKREST_REPO1_CIPHER_PASS`. It must not appear in
any configuration file.

## WAL archiving

Add the following to `postgresql.conf`:

```ini
archive_mode = on
archive_command = 'pgbackrest --stanza=core-graph archive-push %p'
archive_timeout = 60
```

For the evidence chain database, WAL archiving is **synchronous** to guarantee
RPO 0. Set in `postgresql.conf`:

```ini
synchronous_standby_names = ''   # if no standby, archive is the safeguard
archive_mode = on
archive_command = 'pgbackrest --stanza=core-graph archive-push %p'
```

The `archive_command` must succeed before PostgreSQL recycles a WAL segment,
ensuring no evidence records can be lost between backup snapshots.

## Monthly restore test procedure

A restore test is executed on the first Monday of each month. Results are
recorded as compliance evidence in Layer 4 (audit/compliance).

1. **Create isolated test instance.**
   Provision a temporary PostgreSQL 16 container or VM with no network access
   to production systems.

2. **Restore latest full + incrementals.**
   ```bash
   pgbackrest --stanza=core-graph --type=time \
     --target="<target-timestamp>" \
     --target-action=promote restore
   ```

3. **Verify hash chain integrity in `audit_log`.**
   Run the hash chain verification query to confirm no gaps or tampering in
   the append-only audit log.
   ```sql
   select count(*) as broken_links
   from   core.audit_log a
   where  a.prev_hash is not null
     and  a.prev_hash <> (
            select sha256(row_to_json(b)::text::bytea)
            from   core.audit_log b
            where  b.id = a.id - 1
          );
   -- Expected result: 0
   ```

4. **Run schema validation tests.**
   ```bash
   pytest tests/schema/ -v
   ```

5. **Document result as compliance evidence.**
   Record the restore date, target timestamp, hash chain result, and test
   outcome. Store the report in MinIO WORM bucket under
   `evidence/restore-tests/YYYY-MM-DD.json` and sign with cosign.

6. **Tear down test instance.**
   Destroy the temporary container/VM. No production data persists outside
   the backup repository.

## RPO / RTO targets

| Scope            | RPO          | RTO      | Mechanism                        |
|------------------|--------------|----------|----------------------------------|
| Standard data    | <= 1 hour    | <= 4 hours | Hourly incremental + WAL replay |
| Evidence chain   | 0 (zero)     | <= 4 hours | Synchronous WAL archiving        |

RPO 0 for the evidence chain means every committed transaction is archived
before PostgreSQL acknowledges the commit to the client.

## Disaster recovery scenarios

### Single table corruption

Use PITR to restore to the moment before corruption occurred.

```bash
pgbackrest --stanza=core-graph --type=time \
  --target="2026-03-28T14:30:00+00:00" \
  --target-action=promote restore
```

After restore, verify the affected table and run schema validation tests
before returning to service.

### Full database loss

Restore from the latest full backup plus all subsequent incrementals and WAL
segments.

```bash
pgbackrest --stanza=core-graph --type=default restore
```

This replays the full backup, all incrementals, and all archived WAL up to
the last available segment. Estimated RTO: <= 4 hours depending on database
size and network throughput from S3.

### Storage failure

If the local PostgreSQL data directory is lost (disk failure, node loss):

1. Provision a replacement node with PostgreSQL 16 and pgBackRest.
2. Configure `pgbackrest.conf` with the same stanza and S3 credentials.
3. Run a full restore from the S3 backup repository.
4. Verify hash chain integrity in `audit_log`.
5. Resume WAL archiving and incremental backup schedule.

The S3 backup repository is the authoritative recovery source. Local backups
are not maintained.
