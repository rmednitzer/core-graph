# Break-Glass Procedure

## Purpose

Break-glass access provides emergency database access when the normal
authorization stack (Cerbos ABAC + SpiceDB ReBAC) is insufficient to resolve
a critical incident. This procedure bypasses standard access controls and
must only be used when there is no alternative.

Every break-glass activation is irrevocable, fully audited, and triggers a
mandatory post-incident review.

## Prerequisites

- **Three key holders:** CISO plus two senior engineers, each holding one
  share of the breakglass credential.
- **Shamir's Secret Sharing:** 2-of-3 threshold scheme. Any two key holders
  can reconstruct the credential; no single holder can.
- **Pre-created role:** The `breakglass_admin` PostgreSQL role exists but is
  disabled (`NOLOGIN`) by default. It has superuser-equivalent grants scoped
  to the core-graph database.

```sql
-- Role creation (run once during initial provisioning)
create role breakglass_admin with nologin;
grant all on database "core-graph" to breakglass_admin;
```

## Activation procedure

### Step 1 -- Initiate request

Key holder A initiates the break-glass request. They must provide:

- Incident reference (e.g., `INC-2026-0042`)
- Justification for why normal access is insufficient
- Expected scope and duration of emergency access

This request is logged to the WORM audit trail before any credential is
reconstructed.

### Step 2 -- Second share

Key holder B (any of the remaining two holders) provides their Shamir share.
Both shares are combined on a secure, ephemeral workstation -- never on a
production node.

### Step 3 -- Reconstruct credential

The combined secret reveals the `breakglass_admin` password. This password
is used only for the current activation and must be rotated after the session
ends.

### Step 4 -- Enable the role with time limit

```sql
alter role breakglass_admin with login valid until '<current_timestamp + 4 hours>';
alter role breakglass_admin with password '<reconstructed_credential>';
```

The `valid until` timestamp enforces a hard 4-hour maximum. The timestamp
must be in ISO 8601 format, UTC (e.g., `2026-03-29T08:00:00+00:00`).

### Step 5 -- Set session variables

After connecting as `breakglass_admin`, set the session context so that
Row-Level Security policies grant full access:

```sql
select set_config('app.max_tlp', '4', false);
select set_config('app.breakglass', 'true', false);
select set_config('app.incident_ref', 'INC-2026-0042', false);
```

`app.max_tlp` is the only variable consumed by RLS policies; setting it to 4
(TLP:RED) grants visibility to all rows that are not compartment-restricted.
`app.breakglass` and `app.incident_ref` are not read by RLS policies — they
exist for audit trail correlation. pgAudit captures all `set_config` calls,
so post-incident review can verify when break-glass was activated and which
incident reference was associated with the session. The `false` argument to
`set_config` scopes the variable to the session (not just the current
transaction), which is required because break-glass operates across multiple
queries during the emergency.

### Step 6 -- Audit logging

All SQL commands executed during the break-glass session are captured by
pgAudit and written to:

- The `audit_log` table (append-only, hash-chained)
- MinIO WORM bucket (`evidence/breakglass/`)
- Standard PostgreSQL log (as fallback)

## Automatic safeguards

### pg_cron expiry check

A pg_cron job runs every 5 minutes to detect and disable expired break-glass
roles:

```sql
select cron.schedule(
  'breakglass-expiry-check',
  '*/5 * * * *',
  $$
    do $$
    begin
      if exists (
        select 1 from pg_roles
        where  rolname = 'breakglass_admin'
          and  rolcanlogin = true
          and  rolvaliduntil < now()
      ) then
        alter role breakglass_admin with nologin;
        raise log 'breakglass_admin role auto-disabled by expiry check';
      end if;
    end $$;
  $$
);
```

### Hard limits

- **Maximum session duration:** 4 hours. Non-extendable without a new
  activation (new Shamir reconstruction, new incident reference).
- **No role escalation:** `breakglass_admin` cannot grant privileges to
  other roles.
- **No replication access:** The role does not have `REPLICATION` privilege.

## Audit trail

| Layer              | Mechanism                        | Retention       |
|--------------------|----------------------------------|-----------------|
| SQL commands       | pgAudit (all statements logged)  | Indefinite      |
| Append-only table  | `audit_log` with hash chain       | Bitemporal, never deleted |
| Object storage     | MinIO WORM bucket                | Immutable       |
| Transparency log   | Rekor (cosign-signed entries)    | Public, append-only |

The hash chain in `audit_log` is verified after every break-glass session.
Any break in the chain triggers a critical alert.

Post-incident review is **mandatory within 24 hours** of session end.

## Return to normal

### Step 1 -- Disable the role

```sql
alter role breakglass_admin with nologin;
```

This is automatic after expiry but should be done manually as soon as the
emergency work is complete.

### Step 2 -- Rotate credentials

Rotate the `breakglass_admin` password and redistribute new Shamir shares
to all three key holders. The old credential must never be reused.

### Step 3 -- Review audit log

Query all actions taken during the break-glass session:

```sql
select *
from   audit_log
where  actor = 'breakglass_admin'
  and  t_recorded between '<activation_time>' and '<deactivation_time>'
order  by t_recorded;
```

### Step 4 -- Document in Layer 4

Create an incident record in the audit/compliance ontology layer containing:

- Incident reference
- Activation and deactivation timestamps
- Key holders involved
- Summary of actions taken
- Justification and outcome

Store the report in MinIO WORM bucket under
`evidence/breakglass/YYYY-MM-DD-INC-XXXX.json` and sign with cosign.

### Step 5 -- Verify hash chain integrity

Run the hash chain verification to confirm no audit entries were tampered
with or removed during the break-glass session:

```sql
select count(*) as broken_links
from   audit_log a
where  a.prev_hash is not null
  and  a.prev_hash <> (
         select sha256(row_to_json(b)::text::bytea)
         from   audit_log b
         where  b.id = a.id - 1
       );
-- Expected result: 0
```

## Monitoring and alerting

| Event                          | Alert level | Channel             |
|--------------------------------|-------------|---------------------|
| `breakglass_admin` role enabled  | Critical    | PagerDuty + Slack   |
| `breakglass_admin` login         | Critical    | PagerDuty + Slack   |
| `breakglass_admin` SQL statement | Warning     | Slack (real-time)   |
| Break-glass session > 3 hours  | Warning     | Slack               |
| Hash chain break detected      | Critical    | PagerDuty + Slack   |

A dashboard widget displays the current break-glass status:

- **Green:** `breakglass_admin` is `NOLOGIN` (normal operations)
- **Red:** `breakglass_admin` is `LOGIN` (active break-glass session)
- **Amber:** Break-glass session ended < 24 hours ago, pending review
