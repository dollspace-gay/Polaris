# Moderation Tool Design Document

**Working name:** TBD (placeholder: `Polaris`)
**Status:** Draft v0.2
**Audience:** Bluesky moderation team, independent ATProto labeler operators
**Stack:** Rust backend, Leptos frontend (WASM)
**Intent:** A gift. Take what is useful, ignore what is not, fork freely.

---

## 0. Framing

This document proposes a replacement for Ozone designed around how moderation actually feels to do, rather than how ticketing systems are conventionally built. It is offered as a gift to Bluesky and to the labeler community. Nothing here is prescriptive; the design choices are explained so that operators can disagree with them on informed grounds and adapt.

The work assumes two deployment shapes:

- **Bluesky's first-party moderation team**, operating at relay-and-AppView scale with full firehose access, in-house classifiers, and a large moderator headcount with formal training and wellness infrastructure.
- **Independent labelers**, operating against the public firehose, with smaller teams, narrower scope (a community, a topic area, a specific harm class), and limited or no in-house ML.

Both deployments share the same core architecture. The differences are in scale, ingest mode, and which optional components are turned on.

## 1. Problem Statement

Ozone is structured as a ticket queue. This is the wrong abstraction for the actual work. Moderation is not customer service; it is an adversarial intelligence problem with a wellness-critical human-in-the-loop. The cost of treating it as ticketing is paid in three places:

1. **Pattern blindness.** Coordinated abuse, sock-puppet rings, and image-hash brigades are invisible when reports are presented as isolated cards. Moderators reconstruct patterns in their heads across hundreds of clicks, badly and inconsistently.
2. **Lost institutional context.** An account's full moderation history is not surfaced at decision time. The seventh moderator to encounter a repeat offender does not know they are the seventh.
3. **Moderator burnout.** No exposure tracking, no specialty routing, no wellness instrumentation. Graphic content is delivered to whoever happens to be in the queue, with no support structure around the delivery.

This proposal treats moderation as a pattern-recognition and adversarial-intelligence task, with the human moderator as a calibrated decision-maker rather than a queue worker.

## 2. Design Principles

- **Patterns are the primary unit of work**, not individual reports. Reports aggregate to subjects; subjects cluster into incidents; incidents are observed against network and temporal context.
- **Machines do pattern detection; humans do judgment.** The tool should never ask a human to do work a computer is better at (deduping, clustering, timeline reconstruction, network walks) and should never ask a computer to do work a human is better at (final action on ambiguous content, calibration of borderline cases).
- **Every action is reversible and audited.** Free-text reasoning is required, not optional. Undo is a first-class operation for at least 24 hours.
- **The tool knows it is asking humans to look at the worst content on the network** and behaves accordingly. Exposure is tracked, breaks are enforced, routing respects training and specialty.
- **Institutional knowledge is captured in the tool, not in Slack.** Second-opinion conversations are attached to cases and searchable as training material.
- **Adversarial robustness is a v1 requirement.** The system will be probed and gamed. Authentication, rate-limiting, audit integrity, and abuse of the tool itself are designed for from the first commit.
- **Labeler-friendly by default.** A small team running a topic-specific labeler should be able to deploy and operate this with two engineers and a couple of moderators, not a SRE org.

## 3. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Leptos frontend (WASM)                                     │
│  - Pattern dashboard (default view)                         │
│  - Subject-centric case view                                │
│  - Network/graph context panel                              │
│  - Action composer with required reasoning                  │
└────────────────────────┬────────────────────────────────────┘
                         │ Axum HTTP + WebSocket
┌────────────────────────┴────────────────────────────────────┐
│  Rust backend (Axum)                                        │
│  - Auth, RBAC, session management                           │
│  - Case API, action API, query API                          │
│  - Label emission via atrium-api                            │
│  - WebSocket push for live updates and locks                │
└──┬──────────────┬──────────────┬───────────────┬────────────┘
   │              │              │               │
┌──┴───────┐  ┌───┴────────┐ ┌───┴────────┐ ┌────┴──────────┐
│ Postgres │  │ Redis      │ │ Kafka      │ │ Pattern engine│
│ Case     │  │ Hot state, │ │ (Bluesky)  │ │ SimHash,      │
│ store,   │  │ locks,     │ │ NATS       │ │ MinHash,      │
│ audit    │  │ rate limit │ │ (labelers) │ │ clustering,   │
│ log      │  │            │ │            │ │ anomaly det.  │
└──────────┘  └────────────┘ └────────────┘ └───────────────┘
                                  │                │
                            ┌─────┴─────────┐ ┌────┴──────────┐
                            │ Firehose      │ │ Optional ML   │
                            │ subscriber    │ │ classifier    │
                            │ (atrium-api)  │ │ feed (gRPC)   │
                            └───────────────┘ └───────────────┘
```

### 3.1 Two deployment profiles

**Bluesky profile.** Kafka for the event bus (matches their existing infrastructure). Pattern engine sharded by subject-id hash from day one. Optional gRPC integration with their internal classifiers. Multi-region Postgres with read replicas for the case store. Full wellness and routing stack enabled.

**Labeler profile.** NATS for the event bus (single binary, no ZooKeeper, runs on a small VM). Pattern engine single-instance. No classifier integration assumed. Single-region Postgres. Wellness and routing stack present but tuned for small teams (a 3-person labeler doesn't need specialty routing, but does need exposure tracking).

Same code, same schema, same UI. Compile-time feature flags select bus driver and a few subsystem defaults; the operator does not edit code to switch profiles.

### 3.2 Component responsibilities

**Ingest service.** Subscribes to the ATProto firehose via `atrium-api` and to inbound report events. Normalizes both into a unified event stream on the bus. Performs synchronous fast-path classification (PhotoDNA / known-hash matches if configured, known-bad-actor list) and routes critical hits straight to the priority queue.

**Pattern engine.** Stateful Rust service consuming the event stream. Maintains rolling windows for SimHash/MinHash dedup, account-creation cohorts, reply-graph fingerprints, and posting-cadence anomalies. Emits *pattern observations* (not actions) which become signals on subject and incident records.

**Case store.** Postgres. Three primary tables and a lot of indexes:
- `subjects` — accounts, posts, lists, feeds. The thing being moderated.
- `incidents` — clusters of reports + observations bound to a subject or set of subjects.
- `actions` — every moderator decision, with reasoning, reversibility window, and audit chain.

Time-partitioned report data is aged out to cold storage after 18 months; subject and action history is permanent.

**Hot state (Redis).** Current case locks (who is looking at what), session presence, rate limits on action submission, ephemeral notification fan-out.

**Frontend.** Leptos compiled to WASM. WebSocket for live pattern updates and lock state. Type-shared with the backend via a single Rust crate defining the wire protocol — no codegen, no drift.

## 4. Data Model

```rust
struct Subject {
    id: SubjectId,
    kind: SubjectKind,            // Account, Post, List, Feed
    did: Option<Did>,
    uri: Option<AtUri>,
    created_at: DateTime<Utc>,
    first_seen_by_mod: DateTime<Utc>,
    risk_signals: Vec<Signal>,    // computed, denormalized for fast load
}

struct Incident {
    id: IncidentId,
    primary_subject: SubjectId,
    related_subjects: Vec<SubjectId>,
    reports: Vec<Report>,
    pattern_observations: Vec<Observation>,
    severity: Severity,
    status: IncidentStatus,       // Open, InReview, Actioned, Closed, Escalated
    assigned_to: Option<ModeratorId>,
    locked_by: Option<ModeratorId>,
    opened_at: DateTime<Utc>,
    closed_at: Option<DateTime<Utc>>,
}

struct Action {
    id: ActionId,
    incident_id: IncidentId,
    subject_id: SubjectId,
    moderator_id: ModeratorId,
    kind: ActionKind,             // Label, Takedown, Mute, Warn, Escalate, NoAction
    label: Option<LabelValue>,
    reasoning: String,            // required, free-text, searchable
    policy_refs: Vec<PolicyId>,
    reversible_until: DateTime<Utc>,
    reversed_by: Option<ActionId>,
    created_at: DateTime<Utc>,
    emitted_to_atproto: Option<DateTime<Utc>>,  // when the label hit the wire
}

struct Observation {
    kind: ObservationKind,        // ImageHashCluster, AccountCohort, ReplyBrigade, etc.
    confidence: f32,
    evidence: serde_json::Value,
    detected_at: DateTime<Utc>,
}
```

The key design choice: **incidents, not reports, are the unit moderators act on.** A report is a signal that contributes to an incident. Twelve reports against one account become one incident with twelve attached reports, not twelve cases.

## 5. Core Features

### 5.1 Pattern dashboard (home view)

The default landing page is *not* a queue. It is a dashboard showing:

- **Report volume timeline** for the last 24h / 7d / 30d, broken down by category, with anomaly bands rendered.
- **Active incident clusters** ranked by severity × reach.
- **Coordinated-action signals** — account cohorts created within narrow windows, image-hash bursts, reply-graph anomalies — with one-click drill-down into the contributing subjects.
- **Moderator load and queue depth** by category and severity tier.

A traditional queue view is one click away, but it is the secondary surface, not the primary one.

### 5.2 Subject-centric case view

When a moderator opens an incident, the view is organized around the *subject*, not the report. The page shows:

- Account metadata: handle, DID, creation date, follower/following counts, posting cadence.
- **Full prior moderation history** rendered as a timeline, with every previous action, its reasoning, and the moderator who made it.
- **All current reports** consolidated, with reporter context (new account vs. established, prior false-report rate).
- **Pattern observations** attached by the engine.
- **Network context panel:** follow graph, reply graph, account cohort membership, shared-image clusters.
- **Action composer** with required reasoning field.

A moderator looking at this account for the first time should see what the seventh moderator would have constructed manually under Ozone, available immediately.

### 5.3 Pattern actions (bulk-on-pattern)

Beyond per-subject action, moderators can act on patterns directly:

- *"Apply label X to every account that posted this image hash in the last 48h."*
- *"Mute-from-discover every account in cohort C with fewer than 3 followers that has replied in thread T."*
- *"Escalate every incident in cluster K for senior review."*

Pattern actions are gated by role and require a senior co-sign for any action affecting more than N subjects. Every affected subject gets an individual `Action` record so reversal and audit work the same way as for single actions.

### 5.4 Triage routing

Reports are not dropped into a single queue. The router considers:

- **Category and required training.** CSAM and CSEM reports route only to trained, supported moderators with the wellness scaffolding around them. For labeler deployments without dedicated CSAM-trained mods, these reports are forwarded directly to NCMEC and to Bluesky's first-party team rather than handled in-tool — the labeler tool refuses to render them.
- **Moderator specialty and history.** Harassment reports prefer moderators who have handled similar context before.
- **Calibration mode for new moderators.** Until a calibration threshold is hit, new moderators see a curated easy-mode queue with shadow-review against senior decisions.
- **Current load and exposure budget.** A moderator who has hit their graphic-content exposure threshold for the day is not routed more of it.

### 5.5 Reasoning, reversal, and audit

- Every action requires a free-text reasoning field. The category dropdown is a tag, not the reason.
- Every action is reversible for 24 hours by the original moderator and indefinitely by senior moderators (with audit).
- Every action is appended to a hash-chained audit log; tampering is detectable.
- Reasoning text is full-text indexed and searchable so "how do we usually handle X" returns real prior decisions.

### 5.6 Second opinion workflow

One-click *flag for senior review*. The senior moderator sees the case with the original moderator's draft action and reasoning. Their conversation about the decision is attached to the incident permanently, becoming searchable training material for future moderators.

### 5.7 Wellness instrumentation

- Exposure to graphic content is tracked per moderator, surfaced to the moderator first, manager only with consent or aggregate.
- Moderators set their own daily exposure caps; the router respects them.
- Forced break prompts after exposure thresholds, with the case auto-released back to the queue.
- Personal calibration view: moderator's own reversal rate, agreement rate with senior reviewers, action distribution. Surfaced as feedback to the moderator, not as a performance metric to management.

For labelers: even a 3-person team benefits from exposure tracking. The wellness layer is not optional and not gated behind team size.

### 5.8 Appeals

Appeals open as a new incident type linked to the original action. The reviewing moderator sees the original action, original reasoning, and appellant's statement. Reversal of an appealed action surfaces in the original moderator's calibration view as feedback, not punishment.

### 5.9 Labeler interop

Labels emitted by other labelers are consumable as signals into the pattern engine — a third-party labeler flagging an account as a sock puppet contributes a signal to that account's risk profile in your instance, weighted by the trust you assign to that labeler. Conversely, every action emits a properly-formed ATProto label via `atrium-api`, signed by the deployment's labeler key.

This means:

- Bluesky's first-party deployment can ingest community-labeler signals as additional context.
- A topic-specific labeler can ingest Bluesky's labels as ground-truth context for their own narrower decisions.
- Operators configure their own trust weights per upstream labeler.

## 6. Backend Implementation Notes

- **Axum** for HTTP, with `tower` middleware for auth, tracing, and rate-limiting.
- **SQLx** against Postgres, with compile-time checked queries. Migrations via `sqlx migrate`.
- **Pattern engine in-process** with the ingest service for the labeler profile; split out and sharded for the Bluesky profile. SimHash/MinHash via `simhash` and `probminhash` crates; analytics windows via `polars`.
- **`atrium-api`** for ATProto integration — firehose subscription, label emission, repo reads.
- **Auth** via OIDC against the operator's identity provider; roles stored locally in Postgres. No password auth; everything is SSO. Hardware-key requirement is a config flag, on by default for first-party Bluesky deployment.
- **Audit log** is append-only with per-row hash chaining (each row commits the hash of the previous). Periodic external attestation of the head hash so internal tampering is detectable.
- **Tracing** via `tracing` + OpenTelemetry, logs structured, no PII in logs by policy and lint.

## 7. Frontend Implementation Notes

- **Leptos** with fine-grained reactivity. Server functions for mutations, signals for live state.
- **Shared types crate** containing all wire-protocol types, derived `Serialize`/`Deserialize`. Both backend and frontend depend on it. Type drift is structurally impossible.
- **Keyboard-first.** Every action has a shortcut. The tool is used 8 hours a day by the same people; mouse-driven UX is a tax on them.
- **Local-first case context.** When a moderator opens an incident, related context (history, network, observations) is prefetched and cached in IndexedDB so navigation within a case is instant even on bad connections.
- **Live presence** via WebSocket — moderators see when someone else is looking at the same case before they start working it.
- **Accessible by default.** Screen-reader tested, keyboard-complete, no information conveyed by color alone. Moderators are knowledge workers and a non-trivial fraction are disabled; the tool should not be one of the things working against them.

## 8. Deployment & Ops

**Bluesky profile:**
- Statically linked single binary backend, container image `FROM scratch` plus binary plus CA certs.
- Postgres on their existing managed infra. Redis managed. Kafka shared with their existing event infrastructure.
- Horizontal scale on the HTTP layer is trivial (stateless). Pattern engine sharded by subject-id hash.
- Backups: Postgres PITR, audit log additionally streamed to immutable object storage (S3 with object lock).

**Labeler profile:**
- `docker-compose up` should bring up a working instance: backend, Postgres, Redis, NATS, single ingest worker. A `helm` chart for operators who prefer Kubernetes.
- Single-binary with embedded NATS available for the smallest deployments (one VM, one binary, one Postgres).
- Backup story documented for both managed-Postgres and self-hosted-Postgres operators.

The deployment delta between profiles is config and which subsystems are enabled, not separate codebases.

## 9. Security & Threat Model

Primary threats:

1. **Compromised moderator account** abusing tool access. Mitigations: SSO + hardware key required (first-party), action rate limits, anomaly detection on moderator action patterns (a moderator suddenly labeling 1000 accounts at 3am is itself an incident), senior co-sign for high-impact pattern actions.
2. **Insider tampering with audit log.** Mitigations: hash chaining, external attestation of head hash, append-only storage with object lock for the streamed copy.
3. **Adversaries gaming the report system** to weaponize moderation against innocents. Mitigations: reporter reputation scoring, false-report tracking, weighting of reports by reporter history in pattern engine.
4. **DoS via report flooding.** Mitigations: rate limits at ingest, dedup at ingest (a thousand identical reports become one incident with a thousand reporters), graceful degradation under load (drop low-signal reports first, never drop CSAM-classifier hits).
5. **Tool itself becoming an attack surface against moderators** — malicious payloads in reported content rendered carelessly. Mitigations: all reported content rendered behind a click-to-reveal with content warnings, no auto-loading of remote resources, sandboxed iframe for any HTML preview, image rendering through a sanitizing proxy.
6. **Labeler-tool compromise leaking moderator identity** to subjects of moderation. Mitigations: moderator identity never leaves the audit log; public-facing label emission is signed by the labeler key, not the moderator.

## 10. Open Questions

- **ML classifier integration shape.** Bluesky has in-house classifiers; the right integration is probably gRPC with classifier output as another signal feeding the pattern engine, never as an autonomous actor. Worth a separate design conversation rather than locking in here.
- **Cross-labeler trust model.** How do operators express "I trust labeler X for spam signals but not for harassment signals"? Per-labeler-per-category weights are the obvious answer; a richer model may be warranted.
- **Mobile.** Moderation work is desk work, but on-call escalation may want a mobile surface. Out of scope for v1, worth revisiting.
- **Federation of moderation conversations.** Should second-opinion threads ever be visible across labeler instances (e.g., when a community labeler escalates to Bluesky)? Probably yes, with explicit handoff; needs design.

## 11. Milestones

Ordered, not timed. Each milestone is a coherent unit of work that delivers a usable increment.

**M0 — Skeleton.** Axum + Postgres + auth + basic case CRUD. Single-moderator usable for manual case entry. No pattern engine, no firehose.

**M1 — Ingest and incidents.** ATProto firehose subscription, report normalization, incident aggregation by subject. Queue view with subject-centric case page. No pattern detection yet, but the data model supports it.

**M2 — Pattern engine v1.** SimHash/MinHash dedup, account-cohort detection, basic anomaly detection on report volume. Pattern dashboard becomes the default home view. Pattern actions for a small set of operations.

**M3 — Wellness, routing, appeals.** Specialty routing, exposure tracking, appeals workflow, second-opinion conversations.

**M4 — Hardening and labeler interop.** Audit log attestation, full threat-model coverage, load testing, ops runbooks, label emission and consumption, both deployment profiles validated. Beta with a partner labeler and pilot with Bluesky's mod team if they want it.

## 12. License and Governance

This is a gift. Suggested license: MIT for everything.

MIT because the goal is maximum adoption. Bluesky needs to be able to use this without legal review friction; corporate trust-and-safety teams at other companies need to be able to deploy it without involving counsel; labeler operators need to be able to fork without worrying about copyleft obligations. The improvements that matter will come back via PRs because the project is well-run, not because a license forces them to.

Governance: project lives on a public forge, accepts PRs, has a documented decision-making process. Forks are welcome and expected; some operators will have specific needs that justify diverging.

---

*End of v0.2.*
