# Polaris backup runbook

Polaris persists three classes of state that operators must preserve:

| Class | Where it lives | Loss impact |
|---|---|---|
| Moderation database (subjects, incidents, observations, actions, reports, audit log, signing-key history) | Postgres | Catastrophic — every moderation decision and its provenance. |
| Audit log head hashes | Postgres + S3-object-lock target (issue #35) | High — the streamed copy is the external attestation, without which the in-DB chain is self-referential. |
| Evidence CARs | `BlobStoreKind::LocalFs` (labeler profile) or `BlobStoreKind::S3` (Bluesky profile) | Medium — replayable from upstream PDSes if their retention window has not lapsed; permanent loss if it has. |

This runbook covers backup configuration, the audit-log streaming
posture, and the quarterly restore drill that closes the loop.

---

## 1. Postgres point-in-time recovery (PITR)

**Target RPO: 15 minutes.** The Polaris audit log is append-only; a
15-minute RPO bounds the worst-case "moderator action lost on restore"
to a single triage round.

### 1a. Managed Postgres (recommended for the Bluesky profile)

| Provider | Setting | Polaris recommendation |
|---|---|---|
| AWS RDS for Postgres | "Automated backups" + "Continuous backup window" | Enable automated backups, retain ≥ 35 days, enable cross-region snapshot copy for disaster recovery. PITR window ≥ 7 days. |
| Google Cloud SQL Postgres | "Point-in-time recovery (PITR)" | Enable PITR, retain transaction logs ≥ 7 days, configure cross-region replicas for the Bluesky profile. |
| Aurora Postgres (AWS) | Continuous backup is on by default | Set `BacktrackWindow` ≥ 24h, enable cross-region cluster snapshots. |
| Azure Database for Postgres — Flexible Server | "Geo-redundant backups" + "Point-in-time recovery" | Enable both, retain ≥ 35 days. |

No Polaris configuration is required — these settings live in the
cloud console / Terraform. The DB connection URL passed to Polaris
via `DATABASE_URL` is identical pre- and post-restore.

### 1b. Self-hosted Postgres (typical labeler profile)

The labeler-profile compose stack runs Postgres in-container with no
PITR by default — that is an explicit "single-VM smallest deployment"
trade-off. Operators who care about durability should one of:

- **pgBackRest** (recommended). Continuous WAL archive + scheduled
  full + differential backups, S3-compatible target. Configuration
  template:

  ```ini
  # /etc/pgbackrest/pgbackrest.conf
  [global]
  repo1-type=s3
  repo1-s3-endpoint=s3.amazonaws.com
  repo1-s3-bucket=<your-pgbackrest-bucket>
  repo1-s3-region=us-east-1
  repo1-s3-key=<aws-access-key-id>
  repo1-s3-key-secret=<aws-secret-access-key>
  repo1-retention-full=4
  repo1-retention-archive=14

  [polaris]
  pg1-path=/var/lib/postgresql/data
  pg1-port=5432
  ```

  Schedule:
  - `pgbackrest --stanza=polaris --type=full backup` — weekly (Sunday 02:00).
  - `pgbackrest --stanza=polaris --type=diff backup` — daily.
  - WAL archive is continuous (`archive_command = 'pgbackrest --stanza=polaris archive-push %p'`).

- **wal-g** (lower-overhead alternative). Push WAL + base backups to
  S3 / GCS / Azure Blob:

  ```sh
  WALG_S3_PREFIX=s3://<your-walg-bucket>/polaris \
  AWS_REGION=us-east-1 \
  PGHOST=/var/run/postgresql \
  wal-g backup-push /var/lib/postgresql/data
  ```

  Schedule a nightly `wal-g backup-push` via cron; `archive_command`
  set to `wal-g wal-push %p` for continuous WAL streaming.

In both cases the operator restores via the tool's standard
procedure (`pgbackrest restore` / `wal-g backup-fetch` + WAL replay)
into a fresh `/var/lib/postgresql/data`, then boots Postgres pointed
at the recovered data directory. See §3 for the post-restore
verification step.

---

## 2. Audit-log streaming to immutable storage (issue #35)

The in-database audit chain is hash-linked but self-referential — if
an attacker compromises the DB, they can re-write history coherently.
The external attestation is the `AttestationWorker` (issue #35) writing
each head hash to an S3 bucket with **Object Lock in compliance mode**.

### Operator-side requirements

1. **Provision the bucket** before first Polaris start. The bucket
   MUST have Object Lock enabled at creation time — it cannot be
   toggled on later. AWS CLI:

   ```sh
   aws s3api create-bucket \
     --bucket polaris-audit-attestation \
     --region us-east-1 \
     --object-lock-enabled-for-bucket

   aws s3api put-object-lock-configuration \
     --bucket polaris-audit-attestation \
     --object-lock-configuration '{
       "ObjectLockEnabled": "Enabled",
       "Rule": {
         "DefaultRetention": {
           "Mode": "COMPLIANCE",
           "Years": 7
         }
       }
     }'
   ```

   Retention period (years above) MUST be ≥ the operator's legal-hold
   horizon. 7 years is a defensible default for moderation evidence;
   adjust to local regulatory advice.

2. **IAM**: the Polaris service identity has `s3:PutObject` only.
   `s3:DeleteObject` is forbidden by IAM in addition to being blocked
   by Object Lock; this is defence in depth.

3. **Cross-region replication** (Bluesky profile): replicate
   `polaris-audit-attestation` to a bucket in a second region, also
   with Object Lock. A regional outage that takes down the primary
   does not lose attestations.

4. **Equivalent on other clouds**:
   - GCS: bucket "Retention Policy" set to ≥ 7 years (compliance mode equivalent: lock the policy with `gsutil retention lock`).
   - Azure: Immutable storage with time-based retention policy, set retention period and lock the policy.

### Polaris-side configuration

The `AttestationWorker` reads `POLARIS_EVIDENCE_S3_BUCKET` etc. once
its issue lands; the env var names are already reserved in
`deploy/.env.example`. Until then, operators on the labeler profile
can run `cargo xtask audit-export` periodically and aws-cli the
output to the bucket manually — that path is documented in
`docs/ops/audit-export.md` when issue #35 ships.

---

## 3. Restore drill (quarterly cadence)

The drill verifies (a) the backup is actually restorable, (b) the
hash chain survives, and (c) Polaris boots cleanly against the
restored DB. Run it every calendar week 11, 24, 37, 50.

### RTO targets

- **Labeler profile**: 4 hours from "restore initiated" to "Polaris
  serving traffic on the recovered DB". Single-VM, single-Postgres,
  manual cutover.
- **Bluesky profile**: 1 hour. Cross-region replica is read-write
  promoted; DNS swing is the gating step.

### Procedure

1. **Snapshot a fresh DB from the most recent backup.** Do NOT restore
   over the production DB — restore to a sibling instance.

   - Managed: trigger a PITR restore to a separate instance from the
     cloud console (RDS: "Restore to point in time" → new DB
     identifier; Cloud SQL: "Clone" → new instance name).
   - Self-hosted: `pgbackrest --stanza=polaris --type=time --target='<timestamp>' restore` into a fresh data directory, then boot a second Postgres instance against it on a non-conflicting port.

2. **Boot Polaris against the restored DB.** Override `DATABASE_URL`
   in a fresh `.env` and `docker compose up polaris-backend` (or
   `helm install polaris-drill ... --set polaris.image.tag=<same-tag>`
   pointed at the restored DB). The backend should bind, run
   migrations as a no-op, and answer `/healthz` with `200 OK`.

3. **Verify the hash chain.** From the running drill instance:

   ```sh
   cargo xtask audit-verify --database-url postgres://<restored-dsn>
   ```

   `cargo xtask audit-verify` walks the audit-log table in primary-key
   order, recomputes each row's hash from the previous head + the
   row's content, and asserts the in-row hash matches. A clean
   verification exits 0; a mismatch is the signal that the backup
   was corrupted or tampered with — escalate to the security team
   before declaring the drill complete.

4. **Row-count delta check.** Compare row counts between source
   and restored:

   | Table | Acceptable delta |
   |---|---|
   | `subjects`, `incidents`, `observations` | ≤ 15-minute insert rate at source × elapsed restore time |
   | `actions` | Should be tightly bounded — actions are moderator-driven, not ingest-driven |
   | `audit_log` | MUST match the head reported by `audit-verify` |
   | `signing_key_history`, `revoked_keys` | MUST match exactly — these tables almost never change |

5. **Cross-check head hash against attestation bucket.** The drill
   DB's `audit_log` HEAD hash MUST be present in the S3 attestation
   bucket. If it is not, the AttestationWorker is broken (file an
   incident, do not declare the drill clean).

6. **Document the drill.** File a `docs/ops/restore-drills/YYYY-QN.md`
   entry with: backup source, restore wall-clock duration, row-count
   deltas, hash-chain verify status, any deviations.

---

## 4. Interaction with key rotation (issue #29 / #30)

Signing-key custody state (`signing_key_history`, `revoked_keys`) is
ordinary Postgres data — it rides the same backup. Post-restore:

- The `signing_key_history` row for the current active key is the
  one Polaris will look up when serving a label issued at any past
  timestamp; the historical-label verifier (REQ-12) reads this
  table by `signed_at`.
- `revoked_keys` rows preserve the audit trail of rotations.
  Restoring a snapshot from before a rotation correctly shows the
  pre-rotation active key as the issuance-time key for older labels
  while the current key remains the post-rotation one.

**Operator action after restore**: confirm the active key in
`signing_key_history` matches the key the running Polaris instance
loaded. If they diverge (e.g. you rotated the key after the backup
was taken), re-run the rotation procedure
(`polaris-backend labeler_key_rotate`) so the new key is recorded in
the restored DB.

---

## 5. Quick checklist

- [ ] Postgres PITR enabled (managed) OR pgBackRest/wal-g configured (self-hosted) with ≥ 15-minute RPO.
- [ ] S3 bucket with Object Lock in compliance mode created BEFORE first Polaris start; retention period ≥ legal-hold horizon (default 7 years).
- [ ] Cross-region replication on the attestation bucket (Bluesky profile).
- [ ] Restore drill scheduled (calendar weeks 11 / 24 / 37 / 50).
- [ ] RTO target documented and rehearsed.
- [ ] Post-restore: `cargo xtask audit-verify` clean, row-count delta within bounds, head hash present in attestation bucket.
