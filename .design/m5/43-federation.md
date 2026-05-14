# M5 design — Issue #43: Add live federation of mod conversations across labeler instances

## Summary

Make second-opinion conversations, escalations, and (optionally) richer
incident context flow between independently-operated Polaris instances over
ATProto-native federation, so that a community labeler escalating to Bluesky
(or peer-to-peer to another community labeler) hands off context and
continues a real conversation rather than dropping a one-shot report. Builds
on #42 (Polaris-owned NSIDs) for the wire format and on the v1 second-opinion
workflow (#25 under M3) for the single-instance UX it extends.

## v1 connection points

- `design.md` §5.6 ("Second opinion workflow") describes the in-tool
  conversation between the original moderator and a senior reviewer. In v1
  this is single-instance: the conversation never leaves the labeler.
- `design.md` §10 lists "Federation of moderation conversations" as an
  explicit open question. This issue answers it.
- `.design/polaris-proto-blue-integration.md` Out of Scope: "Live federation
  of mod conversations across labeler instances (`design.md` §10). Out of
  scope for this tech iteration."
- `.design/polaris-proto-blue-integration.md` §E names this issue as the
  natural place to introduce Polaris-owned lexicons (e.g.,
  `polaris.escalation`).
- Builds on v1 `proto-blue-xrpc` client (used today for upstream labeler
  subscription, §G of the v1 design) — the same client transports federation
  RPCs.
- Builds on v1 K-256 labeler signing key (REQ-11 of v1 design) — the same
  key signs federation handoffs, so signature verification across the
  federation boundary uses the same machinery as for emitted labels.

## Requirements

- REQ-1: A Polaris instance can publish a `polaris.escalation` record (from
  #42) to its own ATProto repo, referencing a `polaris.incident` and naming
  the target instance's DID.
- REQ-2: A target instance receives the escalation via firehose subscription
  or direct push (Q1) and materializes it into its local case store as a
  cross-instance incident with the originating instance's identity attached.
- REQ-3: Subsequent conversation messages (text comments, attached
  observations) on either side of the escalation are signed by the
  participating instance's labeler key and verified by the peer using the
  declared public key from the peer's `app.bsky.labeler.service` record.
- REQ-4: Federation is opt-in per peer. Operators declare trusted peers in
  `[[federation_peers]] did = "did:plc:..." direction = "bidirectional"`
  config; unknown peers' escalations land in a quarantine queue, not the
  active case stream.
- REQ-5: Privacy: moderator identity is never federated. Federated comments
  attribute to the instance, not the individual moderator. Internal audit
  chain hashes, exposure tracking, and reporter identity are not federated.
- REQ-6: Conflict policy: if two instances independently label the same
  ATProto subject differently, federation does not auto-resolve the conflict
  — each instance retains its own labels, and the conflict is surfaced to
  moderators on both sides via the existing upstream-label observation
  pipeline (v1 §G).
- REQ-7: Federation state machine is documented and explicit: states are
  `Proposed`, `Acknowledged`, `Active`, `Resolved`, `WithdrawnBySource`,
  `RejectedByTarget`. No implicit fallthrough; every state transition is
  recorded with a timestamp and the triggering record CID.
- REQ-8: Polaris ships a `polaris federation-status` admin command listing
  active federated escalations, their states, and last-message timestamps.

## Acceptance Criteria

- [ ] AC-1: On a two-instance fixture network (instance A at
      `polaris-a.test`, instance B at `polaris-b.test`), instance A publishes
      a `polaris.escalation` referencing an incident. Within 10 seconds,
      instance B has materialized the escalation in its case store.
- [ ] AC-2: A reply comment posted on instance B is signed by B's labeler
      key, verified by A using the public key from B's
      `app.bsky.labeler.service` record, and surfaced in A's case view as a
      cross-instance conversation message attributed to instance B.
- [ ] AC-3: A federated escalation from a peer not listed in
      `federation_peers` lands in `federation_quarantine`, not the active
      case stream. An admin command surfaces it for explicit accept/reject.
- [ ] AC-4: Moderator IDs from instance A do not appear in any record
      pushed to instance B. The comment attribution is always
      "instance:<did:plc:...>" not "moderator:<id>".
- [ ] AC-5: With instance A and instance B both labeling the same
      ATProto post differently (e.g., A says `harassment`, B says
      `not-harmful`), both labels persist on both sides and are surfaced as
      separate `ExternalLabel` observations on each instance's case view.
      Neither instance silently overrides the other's label.
- [ ] AC-6: A signature verification failure on a federated comment is
      surfaced in logs at WARN with the source DID and discarded; it never
      enters the case store.
- [ ] AC-7: A network partition between the two instances during an active
      escalation leaves both sides in the last-known-good state. When
      connectivity returns, in-flight messages are replayed without
      duplication (idempotent by record CID).
- [ ] AC-8: `polaris federation-status` outputs at least: peer DID, escalation
      ID, state, opened timestamp, last-message timestamp, message count.

## Architecture sketch

**Transport.** Two viable approaches, see Q1. The proposed default is
firehose-subscription-based: each Polaris instance publishes
`polaris.escalation` and `polaris.escalation-message` records to its own
ATProto repo, and peer Polaris instances subscribe to each other's repos
via `proto-blue`'s `Firehose` abstraction (already used in v1 for the
Bluesky firehose, see `polaris-backend/src/ingest/firehose.rs`). This is
"federation-by-PDS-repo" and gets us the entire ATProto sync, signature,
and replay machinery for free.

**Files / modules.**
- `polaris-backend/src/federation/mod.rs` — federation state machine.
- `polaris-backend/src/federation/peer_subscribe.rs` — one
  `proto_blue::repo::Firehose` per configured peer DID, filtered to
  Polaris-NSID records.
- `polaris-backend/src/federation/publish.rs` — wraps the existing
  repo-write path to publish escalation records to the operator's
  ATProto repo.
- `polaris-backend/src/federation/verify.rs` — labeler-key signature
  verification on incoming federated records using
  `proto-blue-crypto` (same primitives v1 uses for verifying upstream
  labels in `src/ingest/upstream_labels.rs`).
- `polaris-backend/src/federation/state.rs` — explicit state machine and
  transition log.
- `polaris-backend/src/repo/federation.rs` — case store schema for
  federated escalations.

**New migrations.**
- `federation_peers` table (config-loaded, but optionally adjustable at
  runtime).
- `federation_escalations` table — local view of federated escalations
  with the source DID, target DID, state, and original-record CID.
- `federation_messages` table — append-only log of cross-instance
  conversation messages with signing key, signature, verification
  status.
- `federation_state_transitions` table — append-only audit of state
  changes.

**Backwards-compatibility story.** Federation is opt-in. An instance with
no `federation_peers` configured is indistinguishable from a v1 deployment
that does not have this code. The new tables are empty; the new firehose
subscribers do not run; the existing single-instance second-opinion flow
(§5.6) is unchanged.

**Dependencies on other M5 issues.** Hard-blocked by #42 (the wire format
this federation flows over is defined there). Soft-related to #47 (richer
trust model) — once cross-instance labels exist, the trust model has more
work to do; that interaction is captured in #47 not here.

**Trust model.** Pairwise allowlist (option A in Q2 below). Operators
declare peer DIDs explicitly in config. No transitive trust, no
web-of-trust, no PKI in v2. Federation between two instances is a
deliberate, configured relationship; we are not building an open
federation network where unknown peers contribute automatically.

**Privacy boundary.** The mapping layer from #42 is where the privacy rule
gets enforced. Mapping from `polaris_types::EscalationMessage` to
`polaris_lexicons::EscalationMessage` strips:
- `moderator_id` → replaced with instance DID.
- Internal audit chain hash → omitted entirely.
- Reporter DIDs from referenced incidents → omitted (only the subject
  DID flows, never the reporter DID).
- Exposure tracking metadata → omitted.

This boundary is enforceable by unit test: take a sample
`polaris_types::EscalationMessage` with a moderator ID, map to wire form,
assert the wire form has no field containing the moderator ID.

## Open questions

<!-- OPEN: Q1 -->
### Q1: Federation transport — firehose-subscription, direct push, or hybrid?

- **A. Firehose-subscription (proposed).** Each instance writes Polaris
  records to its own PDS-hosted repo; peers subscribe to each other's
  repos. Reuses all of ATProto's sync infrastructure. Latency is
  PDS-determined (seconds to tens-of-seconds). No new transport to
  operate.
- **B. Direct instance-to-instance HTTP push** (e.g.,
  `POST /xrpc/polaris.federation.deliver` from sender to receiver).
  Lower latency (single HTTP round-trip). Requires bidirectional
  reachability and a new transport with its own auth, retry, and
  back-pressure story.
- **C. Hybrid** — direct push for "live" conversation messages with
  firehose-subscription as durable fallback. Most code; combines both
  failure modes.

Recommend A. The latency penalty (seconds) is acceptable for a
moderator-to-moderator conversation, and reusing the ATProto sync stack
avoids inventing a parallel federation transport with its own bugs.

**To resolve**: confirm that the latency budget for moderator
conversation is "seconds, not subsecond." If sub-second is required,
revisit.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Trust model — pairwise allowlist, web-of-trust, or PKI?

- **A. Pairwise allowlist (proposed).** Each operator declares each
  trusted peer explicitly. Simple, auditable, doesn't scale beyond
  hundreds of peers per instance.
- **B. Web-of-trust.** Peers vouch for peers; trust is transitive with
  configurable depth. Scales further; harder to reason about.
- **C. PKI.** A federation CA issues certificates to participating
  instances; the CA is the trust root. Operationally heavy; requires a
  CA operator.

Recommend A for v2. Federation networks at the scale Polaris targets
(community labelers + Bluesky first-party + a few peers) fit fine in a
pairwise model. If the federation network ever has thousands of peers,
revisit.

**To resolve**: this is mostly a forward-compatibility question. As long
as the v2 schema allows adding richer trust later (which it does — the
peer table is just config), shipping A is safe.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: Conflict resolution — auto-resolve, surface-only, or escalate?

REQ-6 above proposes surface-only (each instance keeps its own labels,
the disagreement is shown). Alternatives:

- **A. Surface-only (proposed).** Federation does not change the
  per-instance labeling decision. Disagreements are visible to
  moderators and the existing v1 upstream-label observation pipeline
  handles surfacing.
- **B. Auto-resolve by trust weight.** Apply the v1 trust weight (or the
  v2 richer model from #47) at federation time: a higher-trusted peer's
  label wins. Risk: silently overriding a local decision is a moderation
  hazard.
- **C. Escalate to senior moderator.** Any cross-instance disagreement
  automatically opens a senior-review case. Heaviest; doesn't scale to
  many low-priority disagreements.

Recommend A. Moderation is high-stakes; silent override is wrong.

**To resolve**: confirm in design review. If operators want B for
specific categories (e.g., "always defer to NCMEC-trained peer for
CSAM"), that can be a future per-category override.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: What level of incident context federates?

When instance A escalates incident #1234 to instance B, what does B see?

- **A. Just the escalation record + subject DID + free-text reasoning.**
  Minimal data crosses the boundary. B does its own investigation from
  the subject DID forward.
- **B. The above plus a snapshot of the incident's public observations**
  (pattern-engine signals on the subject — these are derived from public
  ATProto data anyway).
- **C. The above plus the incident's report metadata** (counts,
  categories — not reporter identities).
- **D. The above plus the original moderator's reasoning text.**

Each step crosses more privacy boundaries. Recommend B as the v2 default
(public-derived observations are not a privacy leak; report metadata
without reporter identity might be; reasoning text is sometimes
sensitive).

**To resolve**: human decision. The trade-off is between context
(helpful for the receiving moderator) and information leak (some report
metadata could deanonymize a reporter in a small community).
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: Withdrawal and rejection semantics

If instance A escalates to instance B and then withdraws (e.g., the
local moderator decided to handle it themselves), what does B see?

Options: A. B's view of the escalation is marked Withdrawn and locked.
B. B's view is deleted entirely. C. B can still continue if it wants
(promoting it to a B-originated incident).

Symmetric question for B rejecting an escalation from A.

**To resolve**: A is the safest default (no destructive operations
across instance boundaries). Confirm.
<!-- /OPEN -->

## Out of scope (within this issue)

- Open federation (any-instance-can-federate-with-any-instance). v2 is
  pairwise-allowlist only.
- Cross-instance synchronization of full incident history. Federation
  carries the escalation and the conversation, not the entire incident
  graph.
- Federating non-ATProto-shaped subjects (lists, feeds, internal
  aggregates). Federation only references DID/AT-URI subjects.
- Per-moderator federation (moderator A on instance X talks directly to
  moderator B on instance Y). v2 federates at the instance level only,
  per the privacy requirement REQ-5.
- Federation of appeals (the v1 appeals workflow stays single-instance
  for v2; cross-instance appeals are a separate future design).
- Trust-weighted automatic label adoption (deferred to #47, which has
  its own design doc).

## Suggested decomposition

1. **PR 1 — Wire-up firehose subscription to peer repos.** Read-only
   path: subscribe to a peer's PDS-hosted repo, filter to Polaris NSIDs,
   verify signatures, materialize into a quarantine table. No active
   integration with the case store yet. Operationally usable for
   one-way "show me what peer X is publishing."
2. **PR 2 — Federation state machine + tables.** Add the schema and the
   state-transition log. Wire incoming records to allocate escalation
   IDs and walk the state machine.
3. **PR 3 — Outbound publishing.** Implement
   `polaris-backend/src/federation/publish.rs`. The mapping-layer
   privacy boundary (REQ-5) is enforced here. Adds the `polaris
   federation-escalate` admin command.
4. **PR 4 — Conversation messages.** Bidirectional
   `polaris.escalation-message` records flowing between peers; case
   view shows the cross-instance thread.
5. **PR 5 — Admin tooling + observability.** `polaris federation-status`
   command, federation health metrics, signature-failure alerting.
6. **PR 6 — Integration tests on a fixture two-instance network.** AC-1
   through AC-8 verified end-to-end.

PRs 1-2 are infrastructure; PR 3 is the first user-visible
functionality; PRs 4-6 fill out the UX and operational surface. Each PR
is independently reviewable and deployable.
