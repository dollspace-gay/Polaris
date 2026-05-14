# M5 design — Issue #46: Add Ozone-to-Polaris migration tooling

## Summary

Build a CLI tool `polaris-ozone-import` that lets an existing Ozone operator
migrate their database state into a Polaris deployment with minimal
disruption: data preserved, audit history intact, same signing key
continues to emit labels (so downstream consumers see no signing-key
rotation at the cutover). Half of the migration is already free: Polaris's
v1 `file-plain` SigningKey mode reads the same hex format Ozone uses
(`OZONE_SIGNING_KEY_HEX`), so the signing-key half is a config rename. This
issue covers the data half.

## v1 connection points

- `.design/polaris-proto-blue-integration.md` Out of Scope: "Migration
  tooling for operators currently running Ozone. Separate design. Note:
  Polaris's `file-plain` signing-key mode reads the same hex-encoded K-256
  secret Ozone stores as `OZONE_SIGNING_KEY_HEX`, so the signing-key half
  of a migration is a config rename, not a re-key."
- v1 §B threat model and SigningKey design — `file-plain` mode is
  explicitly Ozone-compatible (`polaris-backend/src/labeler/signer/
  file_plain.rs`).
- v1 Postgres schema (#13) is Polaris-native (subjects + incidents +
  actions + observations). Ozone's schema is different (reports + decisions
  + subject-statuses, no incidents-as-clusters). A direct DB import is not
  feasible; this issue is the mapping layer.
- v1 audit log is hash-chained per-row (`design.md` §6: "Audit log is
  append-only with per-row hash chaining"). Migrated rows must enter the
  audit chain at a clearly-marked point so the chain stays verifiable.

## Requirements

- REQ-1: A new binary crate `polaris-ozone-import` reads an Ozone Postgres
  dump (or a live Ozone Postgres) and writes the equivalent state into a
  Polaris Postgres instance.
- REQ-2: Mapping is typed: `OzoneSubjectRow -> polaris_types::Subject`,
  `OzoneReportRow -> polaris_types::Report`, `OzoneModerationEventRow ->
  polaris_types::Action`. No opaque JSON juggling. Mapping errors are
  typed and reported per-row.
- REQ-3: Migration is idempotent. Re-running on a partially-completed
  migration resumes from where it left off, not from scratch. Progress
  tracked in a `migration_state` table.
- REQ-4: Migration is resumable. SIGINT mid-run leaves the database in a
  consistent intermediate state; the next run completes the remainder.
- REQ-5: Audit-trail preservation. Migrated `Action` rows are tagged with
  a `migrated_from_ozone_at` timestamp and a reference to the source
  Ozone event ID. The Polaris audit log includes a clearly-marked
  "migration boundary" entry so chain verification spans pre-migration
  and post-migration history honestly.
- REQ-6: Same labeler signing key continues operating. The migration
  runbook walks the operator through: read `OZONE_SIGNING_KEY_HEX`,
  configure Polaris `[labeler.signing_key] mode = "file-plain"` with the
  same hex, verify with `polaris labeler-key show` that the public key
  matches Ozone's declared key.
- REQ-7: Post-migration data integrity check: row counts per source table
  match counts per target table (modulo documented many-to-one mappings),
  and a SHA-256 checksum over a deterministic sample of fields matches
  pre- and post-migration.
- REQ-8: Cutover runbook documents the shadow-mode period (both Ozone and
  Polaris ingest the firehose simultaneously) and the rollback procedure
  (snapshot taken before cutover, ability to revert to Ozone within a
  documented downtime window).

## Acceptance Criteria

- [ ] AC-1: Given a fixture Ozone Postgres dump (provided in
      `tests/fixtures/ozone-dump-v1.sql`), running `polaris-ozone-import
      --source <dump> --target <polaris-db>` populates the Polaris
      database with subjects, reports, and actions equivalent to the
      Ozone state.
- [ ] AC-2: The Polaris case view, after migration, lists the same
      subjects with the same prior-action history as the Ozone admin UI
      would have shown (verified by snapshot comparison on the fixture).
- [ ] AC-3: Resumability: a `polaris-ozone-import` run interrupted at the
      50% mark via SIGTERM, then resumed, completes without duplicate
      rows in the target database.
- [ ] AC-4: Idempotency: running `polaris-ozone-import` twice on a
      complete migration produces no schema changes and no new rows on
      the second run.
- [ ] AC-5: Row-count integrity check: `polaris-ozone-import verify`
      reports zero discrepancies on a successful migration; reports
      every discrepancy with row IDs on a tampered migration.
- [ ] AC-6: Audit log: querying the Polaris audit log around the
      migration timestamp shows one explicit "Ozone migration: $N rows
      imported at $ts" entry, hash-chained into the existing log.
- [ ] AC-7: Signing key: after the migration runbook, Polaris emits
      labels signed by the same K-256 key Ozone used. A downstream
      consumer subscribing to Polaris's `subscribeLabels` and verifying
      against the operator's `app.bsky.labeler.service` record (which
      still declares the original key) sees no verification failures.
- [ ] AC-8: Shadow-mode coexistence: with both Ozone and Polaris
      subscribed to the firehose simultaneously for a fixture period,
      Polaris's per-subject report counts converge with Ozone's
      within 1 minute (subject to firehose delivery order).

## Architecture sketch

**Source: Ozone's data shape.** Per the plan comment, the source of
truth for Ozone's schema is its repo (`packages/ozone/` in the Bluesky
monorepo). Critical Ozone tables to map:
- `moderation_subject_status` — current state per subject (DID or
  AT-URI).
- `moderation_event` — every moderator decision (label, takedown,
  comment, escalation).
- Reports come in via the `com.atproto.moderation.createReport`
  endpoint and are stored in the event log.

The mapping (informed by Ozone's actual schema, verified at
implementation time by reading
`packages/ozone/src/db/schema.ts` in the Ozone repo):
- Ozone `moderation_subject_status` → Polaris `subjects` (1:1).
- Ozone `moderation_event` of kind `report` → Polaris `reports`
  (1:1).
- Ozone `moderation_event` of kind `label`/`takedown`/etc. → Polaris
  `actions` (1:1).
- Ozone has NO direct equivalent of Polaris `incidents` — incidents
  are a Polaris concept. Migration creates one `Incident` per
  `Subject` that has any report, aggregating that subject's reports
  into the new incident. Future moderator actions on the subject
  attach to this incident.

**File layout.**
- `polaris-ozone-import/` — new binary crate.
- `polaris-ozone-import/src/main.rs` — CLI entry point.
- `polaris-ozone-import/src/source/` — Ozone DB readers, typed per
  table. Each Ozone table gets a typed `OzoneXxxRow` struct.
- `polaris-ozone-import/src/mapping/` — per-table mapping functions.
- `polaris-ozone-import/src/target/` — Polaris DB writers (using the
  same `sqlx` queries the backend uses).
- `polaris-ozone-import/src/progress.rs` — `migration_state` table
  driver.
- `polaris-ozone-import/src/verify.rs` — post-migration integrity
  check.
- `docs/operations/ozone-migration.md` — operator runbook.

**Migration tool architecture.** Three modes:
1. **Dump-and-load** (default). Operator takes an Ozone Postgres dump
   (`pg_dump`), points the tool at the dump file and the target
   Polaris database. Tool reads the dump, applies mapping, writes to
   target.
2. **Live-replication** (advanced). Tool connects to a running Ozone
   Postgres in read-only mode and continuously replicates changes to
   Polaris during the shadow period. This is the highest-fidelity
   path; it is also the most operationally complex.
3. **Verify-only.** Read-only mode that performs the integrity check
   without changing anything.

The v2 baseline ships mode 1 and mode 3. Mode 2 is a follow-up issue
if operator demand justifies the complexity.

**Idempotency mechanism.** The `migration_state` table:

```sql
CREATE TABLE migration_state (
    source_table TEXT NOT NULL,
    source_row_id TEXT NOT NULL,
    target_row_id UUID,
    migrated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (source_table, source_row_id)
);
```

Before writing each target row, the tool checks for an existing
`migration_state` row. Hit = skip. Miss = write + record in
`migration_state` in the same transaction.

**Audit chain integrity.** The v1 audit log is hash-chained. Inserting
migrated `Action` rows in-place would break the chain (or require
recomputing every hash). The migration tool inserts ONE explicit audit
entry: "Ozone migration boundary: $N actions imported at $ts, source
checksum $hash" and chains FROM that entry. The migrated `Action` rows
are then visible via a separate query path
(`actions WHERE migrated_from_ozone IS NOT NULL`) but are NOT in the
audit chain proper. This preserves the chain's verifiability for
Polaris-native actions while still making the migrated history
available for moderator context (the case timeline pulls from both
chains).

**Cutover runbook (referenced by REQ-8).**
1. Stand up Polaris alongside Ozone, configure same labeler signing
   key.
2. Run `polaris-ozone-import` in dump-and-load mode against an Ozone
   snapshot.
3. Start Polaris ingesting the firehose. Polaris is now in shadow
   mode.
4. Verify integrity with `polaris-ozone-import verify`.
5. Stop Ozone's `subscribeLabels` server. Cutover Polaris's
   `app.bsky.labeler.service` record (already declares the same
   signing key) — downstream consumers continue reading without
   noticing the swap.
6. Decommission Ozone, retain the dump for rollback.

**Rollback.** If problems surface within the rollback window
(operator-defined, e.g., 1 week post-cutover):
1. Stop Polaris.
2. Re-deploy Ozone from snapshot.
3. Repoint downstream traffic.
The rollback is documented in the runbook; the tool itself does not
automate it.

**New migrations on Polaris side.**
- `migration_state` table (above).
- `subjects.migrated_from_ozone_id` nullable column (so a subject
  knows its Ozone origin).
- `actions.migrated_from_ozone_event_id` nullable column.
- `audit_log` gets a `kind = 'migration-boundary'` variant.

**Backwards-compatibility story.** This tool runs against a v1 Polaris
deployment. If Polaris's schema evolves between v1 and the time the
tool is run, the tool may need updating; the tool ships with a Polaris
schema version range it supports and refuses to run outside it.

**Dependencies on other M5 issues.** Independent. Specifically:
unrelated to #42 (NSIDs) — migration is database-internal, not
wire-format.

## Open questions

<!-- OPEN: Q1 -->
### Q1: Source — Postgres dump or live Postgres?

- **A. Postgres dump only.** Operator runs `pg_dump`, tool reads the
  dump file. Simplest; requires downtime equal to the dump+import
  duration.
- **B. Live read-only connection.** Tool connects to Ozone's running
  Postgres as a read-only user. Lower-downtime cutover. Risk: schema
  reading concurrent with Ozone writes — needs careful transaction
  isolation.
- **C. Both.** Ship dump first, add live mode in a follow-up.

Recommend C. The dump path is shippable in weeks; live-replication is
months of careful work.

**To resolve**: confirm. Operators with large Ozone instances (>1TB)
may find the dump path's downtime unacceptable.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Incident aggregation strategy

Ozone has no incidents. Polaris does. Two strategies:

- **A. One incident per subject** (proposed). Every Ozone subject
  with any history becomes a single Polaris incident. Reports
  attach. Actions attach. Status reflects the latest Ozone action.
- **B. One incident per cluster of related actions.** Time-windowed
  clustering attempts to recreate the "logical incidents" Ozone
  never modeled. More complex; results depend on clustering
  parameters.
- **C. No incidents created at migration.** Subjects exist;
  pre-migration history is visible as a flat timeline. Incidents
  start with the first post-migration action.

A is the safest: it preserves all visible history and gives
moderators a place to attach new reports. C is the cleanest but
hides pre-migration history from the v1 incident-centric UX.

Recommend A.

**To resolve**: confirm. If A produces awkward UX (giant incidents
for subjects with many years of Ozone history), revisit.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: Operator-facing UX

- **A. Command-line tool only** (proposed). `polaris-ozone-import
  --source <dump> --target <db>`. Operator runs from a shell, reads
  the runbook.
- **B. Web UI** in the Polaris admin surface. Click "Import from
  Ozone," upload dump, watch progress bar.
- **C. Scripted runbook only** (collection of SQL scripts the
  operator runs by hand). Most transparent; most error-prone.

Recommend A. Operators running Ozone are already comfortable with
the shell. A web UI for a one-time migration is over-engineered.

**To resolve**: confirm with target operators (likely the early
adopters who file this issue).
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: Schema-version compatibility

Ozone's schema evolves. The tool needs to declare which Ozone schema
versions it supports.

- **A. Pin to a specific Ozone version range.** Tool refuses to run
  outside (e.g., supports Ozone v0.5.x through v0.6.x).
- **B. Adaptive schema reader.** Tool inspects the Ozone DB schema
  at runtime and adapts. More complex; better operator UX.
- **C. Multiple parallel schema readers.** One per supported Ozone
  version, selected by config flag.

Recommend A as the v2 baseline. The Ozone schema is not changing
fast; pinning to a known-good version range is realistic.

**To resolve**: check Ozone's release cadence and decide. If Ozone
moved fast enough to make A painful, revisit.
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: What happens to in-flight Ozone moderator sessions?

During cutover, moderators who were mid-case in Ozone need to
continue in Polaris. Options:

- **A. Documented "finish your work in Ozone, then we cutover"
  procedure.** Simple; requires moderator coordination.
- **B. Migrate session state** (lock owner, current draft).
  Complex; risk of stale state confusing moderators.
- **C. No migration; moderators see new sessions in Polaris.** Lose
  draft actions written but not committed in Ozone.

Recommend A. Moderators are humans; "finish your case before we
cut over" is a coordination problem, not a software problem.

**To resolve**: confirm with operators.
<!-- /OPEN -->

## Out of scope (within this issue)

- Migrating Ozone deployments running on databases other than
  Postgres (Ozone is Postgres-only as of writing).
- Migrating Ozone-side custom labelers or extensions. Out of scope;
  case-by-case engagement with the operator.
- Real-time bidirectional sync (Ozone ↔ Polaris running indefinitely
  side-by-side). The migration is a one-way, one-time event with a
  shadow period; ongoing dual-write is a different design.
- Importing Ozone's audit log into Polaris's hash chain. The chain
  starts at the migration boundary; Ozone history is preserved but
  not chained.
- Migrating signing key custody mode. The operator chooses on the
  Polaris side; if they want stronger custody than Ozone's
  plaintext-hex, that's a separate Polaris admin operation
  (`polaris labeler-key migrate-mode`).
- Migrating moderator identities. Polaris has its own user/role
  store; operators reassign moderators in the Polaris admin UI.

## Suggested decomposition

1. **PR 1 — Source readers.** Typed Rust structs for each Ozone
   table; integration test against a fixture dump. Read-only path;
   no Polaris writes. Establishes the source contract.
2. **PR 2 — Mapping layer.** Per-table mapping functions with typed
   errors. Tested with property tests over the fixture data. No
   target writes yet.
3. **PR 3 — Target writers + `migration_state` table.** Polaris-side
   schema additions; idempotent write path. AC-3 and AC-4 verified.
4. **PR 4 — CLI binary.** Wires source + mapping + target together.
   AC-1 verifiable end-to-end.
5. **PR 5 — Verify subcommand.** AC-5 verified.
6. **PR 6 — Audit log integration.** Migration-boundary entry, case
   timeline pulls from both legacy and native chains.
7. **PR 7 — Documentation + runbook.** The cutover runbook;
   signing-key parity instructions; rollback procedure. The
   critical PR for operator adoption.
8. **PR 8 — Fixture dataset.** A representative anonymized Ozone
   dump fixture for CI. Built once, blessed by an actual Ozone
   operator.

PRs 1-4 are the minimum viable tool. PR 5 makes it trustworthy. PRs
6-8 make it deployable.
