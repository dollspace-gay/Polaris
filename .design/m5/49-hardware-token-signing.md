# M5 design — Issue #49: Add hardware-token (PKCS#11 / FIDO2 HSM) SigningKey impl with attended-signing UX

## Summary

Add a sixth `SigningKey` trait implementation: hardware tokens (YubiKey,
FIDO2 PRF, PKCS#11 HSM) with touch-to-sign UX. The hard part is the UX —
labelers run unattended, so this mode requires either batched offline
signing (operator periodically signs a queue) or a separate attended-
signer service that holds the token and accepts signing RPCs. The signing
private key never leaves the hardware token; signing operations require
physical presence (touch).

## v1 connection points

- v1 `SigningKey` trait (REQ-11 / AC-13 of
  `.design/polaris-proto-blue-integration.md`). Lives at
  `polaris-backend/src/labeler/signer/`. This is the sixth impl
  alongside the four v1 modes and the TPM mode from #48.
- v1 Out of Scope: "Hardware-token signing keys (YubiKey / FIDO2 /
  PKCS#11 HSM). Post-v1; not viable for unattended labeler deployment
  without a separate attended-signing UX." This issue answers "what's
  the attended-signing UX."
- v1 §B threat-coverage table: hardware-token mode defends T1-T4 (key
  material never leaves the device; signing requires physical touch).
  It is the strongest at-rest custody mode, at the cost of attendance.
- v1 `polaris labeler-key rotate` (REQ-12 / AC-15) — rotation in
  hardware-token mode generates a new key on the token. Requires
  physical access to the token (or the token's standby).
- v1 label emission pipeline (case → action → label → sign → emit). In
  hardware-token mode, the sign step is asynchronous; labels enter a
  `pending_signature` state until signed.

## Requirements

- REQ-1: A new `SigningKey` implementation at
  `polaris-backend/src/labeler/signer/hwtoken.rs` supporting both
  PKCS#11 tokens (`cryptoki` crate) and FIDO2-PRF-based signing
  (`ctap-hid-fido2` or successor crate).
- REQ-2: Two operational modes, config-selected per deployment:
  - **Attended-batch**: Polaris queues labels for signing in a
    `pending_signature` state. An operator periodically runs `polaris
    labeler-sign-pending` at the host where the token is inserted,
    touches the token, signs a batch. Labels are emitted only after
    signing — latency is operator-driven.
  - **Attended-realtime**: A separate `polaris-signer` daemon runs on
    a continuously-attended host (e.g., a moderator's desk) and
    accepts signing RPCs from the Polaris backend. Touch-per-signature
    or batched-with-PIN (Q4 below).
- REQ-3: `WouldBlock` semantics in the trait: when no signer is
  reachable (batch mode without queued processing, realtime mode with
  daemon disconnected), `sign()` returns `SigningError::WouldBlock`.
  Callers handle this by setting the label's status to
  `pending_signature` and waiting for an async signing event.
- REQ-4: Label rows gain a `signature_status` column:
  `Signed | PendingSignature | SigningFailed { reason }`. The emit
  pipeline streams only `Signed` labels.
- REQ-5: PIN / touch UX:
  - For PKCS#11: per-operation PIN prompt if the token requires it
    (PINs cached in-memory for the daemon's lifetime, never on disk).
  - For FIDO2: per-operation physical touch on the token.
  - For PKCS#11 HSMs that support N-of-M quorum: signing requires the
    quorum (Q5).
- REQ-6: The signing key is generated INSIDE the token. The private
  key never exists in software memory. Signing operations require
  physical presence (touch / PIN entry).
- REQ-7: Token disconnect handling: the realtime signer daemon
  detects token removal and signals the backend; subsequent labels
  enter `pending_signature` until the token returns.
- REQ-8: Conforms to the v1 `SigningKey` trait. The `WouldBlock`
  return path is the only behavioral difference visible to the trait
  caller.

## Acceptance Criteria

- [ ] AC-1: Fixture-token (`softhsm2`) integration test: sign a payload
      via the new impl; signature verifies against the public key
      returned by `public_key()`.
- [ ] AC-2: Batched mode latency: with `[labeler.signing_key] mode =
      "hwtoken-batch"`, labels enter `pending_signature` and stay
      pending until `polaris labeler-sign-pending` is run. After the
      command completes, all queued labels are `Signed` and emitted.
- [ ] AC-3: Realtime mode disconnect: with the `polaris-signer` daemon
      running and connected, labels sign immediately. Stopping the
      daemon: subsequent labels enter `pending_signature`. Restarting
      the daemon: pending labels flush and emit within 60 seconds.
- [ ] AC-4: `WouldBlock`: a `SigningKey::sign()` call against an
      unreachable signer returns `SigningError::WouldBlock` (not a
      timeout-then-error; the variant is explicit).
- [ ] AC-5: No-exfiltration: under softhsm2 + audit, no system call
      from `polaris-backend` reads the private key bytes from the
      token's memory. Signing happens via the PKCS#11 `C_Sign` call
      which returns only the signature.
- [ ] AC-6: Touch-required: with a FIDO2 token, an attempt to sign
      without touching the token within the timeout window returns
      `SigningError::PhysicalPresenceTimeout`.
- [ ] AC-7: PIN security: the realtime daemon's PIN is held in
      `secrecy::SecretString`, never written to disk, never logged.
      A `ps`-equivalent inspection of the daemon's memory does not
      surface the PIN as plaintext (within best-effort limits).
- [ ] AC-8: Rotation in hardware-token mode: `polaris labeler-key
      rotate` generates a new keypair on the token (or a designated
      successor token), publishes the new public key, retains the old
      key in `revoked_keys`. The token's old key is removed from the
      token (CKA_DESTROY or equivalent).

## Architecture sketch

**Hardware support matrix.**

| Device class            | Crate          | Mode support              | Notes                                               |
|-------------------------|----------------|---------------------------|-----------------------------------------------------|
| PKCS#11 HSM (e.g., YubiHSM, AWS CloudHSM client) | `cryptoki` | Both modes | Industry-standard. Most flexible.                   |
| YubiKey (PIV applet)    | `cryptoki` via Yubico's pkcs11 module | Both modes | PIV applet exposes PKCS#11; well-supported.        |
| YubiKey (FIDO2 PRF)     | `ctap-hid-fido2` | Touch-per-sign only       | FIDO2 doesn't support per-token PIN caching as PKCS#11 does. |
| Software fixture (softhsm2) | `cryptoki` | Both modes, CI only       | Test harness, not for production.                   |

**Mode 1: Attended-batch.** Polaris backend keeps the labels in a
`pending_signature` state. Operator runs:

```
$ polaris labeler-sign-pending
Found 27 pending labels.
Insert token and touch when prompted.
[touch] [touch] [touch] ...
Signed 27 labels in 41 seconds.
```

The operator interacts via the CLI tool, which holds the token
session. Each `C_Sign` call may require a touch (FIDO2) or a PIN
(PKCS#11 first-time). Labels emit only after the command completes.

**Mode 2: Attended-realtime.** A separate `polaris-signer` daemon
runs on a continuously-attended host (e.g., the operator's desk
machine, with the token physically plugged in and a human present).
The daemon:
1. Opens a session with the token at startup (PIN entered once by the
   operator on the desk, into `secrecy::SecretString`).
2. Listens on a TLS-mutual-authenticated channel for signing RPCs
   from the Polaris backend.
3. For each RPC: optionally prompts touch (FIDO2) or invokes
   `C_Sign` (PKCS#11). Returns the signature.
4. On disconnect / token removal: closes the session, alerts the
   backend.

Backend connects to the daemon via TLS-mutual-auth. The daemon's
public key is in the backend's config; the backend's client cert is
in the daemon's config. Mutual auth prevents unauthorized signing.

**File layout.**
- `polaris-backend/src/labeler/signer/hwtoken.rs` — the
  `SigningKey` impl.
- `polaris-backend/src/labeler/signer/hwtoken/batch.rs` — batch
  mode driver.
- `polaris-backend/src/labeler/signer/hwtoken/realtime.rs` —
  realtime mode RPC client.
- `polaris-backend/src/labeler/signer/hwtoken/pending.rs` — pending
  label queue management.
- `polaris-signer/` — new binary crate for the realtime daemon.
- `polaris-signer/src/main.rs` — daemon entry.
- `polaris-signer/src/pkcs11.rs` — PKCS#11 token interaction.
- `polaris-signer/src/fido2.rs` — FIDO2 PRF token interaction.
- `polaris-signer/src/rpc.rs` — TLS-mutual-auth RPC server.
- `polaris-backend/src/bin/polaris.rs` — adds `labeler-sign-pending`
  subcommand.
- `docs/operations/hardware-token-signing.md` — operator runbook.

**Label state machine.** Extends the v1 label emission flow:

```
Action created  →  Label constructed  →  sign() called
                                              │
                                              ├─ Ok(sig)            →  Signed → emit to subscribeLabels
                                              ├─ WouldBlock         →  PendingSignature (queued)
                                              └─ Err(_)             →  SigningFailed (alert)
```

A background worker (`pending_label_signer`) polls the
`PendingSignature` queue. In batch mode, it does nothing (waits for
operator command). In realtime mode, it retries `sign()` periodically
or on daemon-reconnect event.

**`WouldBlock` semantics.** This is the key abstraction. The trait
becomes:

```rust
enum SigningError {
    WouldBlock,
    PhysicalPresenceTimeout,
    TokenDisconnected,
    Other(anyhow::Error),
}
```

`WouldBlock` is the explicit "no signer reachable right now" variant;
callers must handle it by queueing, not retrying immediately. This
mirrors `std::io::ErrorKind::WouldBlock` semantics.

**Trait extension impact.** The v1 `SigningKey` trait does NOT
currently return `WouldBlock`. Adding it requires either:
- Changing the trait (breaking change to v1, affects all four v1
  impls), or
- Adding a parallel trait `AsyncSigningKey` and converting at the
  call site.

Recommend the former — extending v1 `SigningError` with a new variant
is additive (existing variants unchanged) and the only impl that
returns `WouldBlock` is this issue's. Other impls always succeed or
fail with other variants.

**Two-person rule (Q5).** PKCS#11 HSMs (e.g., YubiHSM, AWS CloudHSM)
support N-of-M quorum: an operation requires N of M designated keys
to authorize. This maps naturally onto Polaris's "senior co-sign for
high-impact actions" (`design.md` §5.3). Open question whether v2
ships this or defers it.

**New migrations.**
- `labels.signature_status` column (existing `labels` table from v1).
- `labels.signed_at` nullable column.
- `pending_label_queue` view or materialized index over
  `labels WHERE signature_status = 'PendingSignature'`.

**Backwards-compatibility story.** Additive. Existing v1 modes
unchanged. The `SigningError::WouldBlock` variant is new; the v1
modes never return it; existing call sites are not affected.

**Dependencies on other M5 issues.** Independent of #42, #43, #44,
#45, #46, #47, #48. The realtime signer's TLS-mutual-auth machinery
could plausibly share code with #43's federation transport but the
v2 baseline keeps them separate.

## Open questions

<!-- OPEN: Q1 -->
### Q1: Batch vs. realtime as the v2 baseline

Both are described above. Options:

- **A. Ship batch first.** Simpler; no daemon to operate. Latency
  is operator-attendance-bound (could be hours).
- **B. Ship realtime first.** More features; daemon to manage.
  Latency is touch-per-signature plus network round-trip.
- **C. Ship both in v2.** Maximum operator choice; maximum surface
  area.

Recommend A as the first PR sequence, with B as a follow-on. The
batch mode is shippable in weeks and serves the "labeler with
occasional emission" use case. Realtime is for active labelers and
needs more infrastructure (daemon, TLS pinning, monitoring).

**To resolve**: confirm. Some operators may have a strong
preference and the decision affects what ships first.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: FIDO2 PRF vs. PKCS#11 as the primary path

Two technically-different paths to "hardware key signs the label."

- **A. PKCS#11 (proposed primary).** Industry standard. PIV
  applet on YubiKey, native on HSMs. Mature `cryptoki` crate.
- **B. FIDO2 PRF.** Newer; uses the WebAuthn PRF extension to
  derive a signing key from a FIDO2 credential. Limited tool
  support. Touch-per-sign mandatory.
- **C. Both, config-selectable.**

Recommend C, with PKCS#11 as the default. PKCS#11 hits more
existing operator hardware; FIDO2 PRF is the future direction but
ecosystem is thin.

**To resolve**: implementation-time decision based on the actual
hardware target operators have on hand.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: Per-operation PIN prompt UX in realtime mode

Realtime daemon. PIN entry options:

- **A. PIN entered once at daemon startup, cached for daemon
  lifetime.** Operationally easiest. Daemon is a persistent
  in-memory hot target.
- **B. PIN entered per-signature** via OS-native PIN prompt. Maximum
  security; unusable for any non-trivial volume.
- **C. PIN cached for a time window** (e.g., 1 hour). Compromise.
- **D. Touch instead of PIN, where the token supports it (FIDO2).**
  Each signature requires a touch but no typed PIN.

Recommend A for PKCS#11 (with secrecy crate, no disk write, careful
memory hygiene) and D for FIDO2. Both balance UX against the threat
model honestly.

**To resolve**: confirm with operators. The trade-off varies by
deployment.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: Touch-per-sign for PKCS#11 batched signing

PKCS#11 tokens can be configured to require touch per `C_Sign` call
(e.g., YubiKey "always require touch" mode). In batch mode, the
operator would touch the token 100 times for 100 labels. Options:

- **A. Touch-per-sign required.** Strongest; tedious.
- **B. One touch authorizes a batch up to N labels.** Looser; not
  all tokens support this.
- **C. PIN-only, no touch.** Weakest of the hardware-token modes.

Recommend A for the v2 baseline. If operator feedback indicates
"100 touches per batch is unworkable," revisit. The touch
requirement is what distinguishes hardware-token mode from
software modes; weakening it defeats the purpose.

**To resolve**: confirm with actual operators.
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: N-of-M quorum signing

PKCS#11 HSMs (YubiHSM, AWS CloudHSM) support N-of-M quorum: signing
requires N of M designated keys. This is the "two-person rule" the
plan comment mentions.

- **A. v2 ships single-token signing.** Quorum is a follow-up
  issue.
- **B. v2 ships single-token + 2-of-2 quorum.** Most common
  two-person rule.
- **C. v2 ships full N-of-M.** Generality.

Recommend A. Quorum signing has its own design (key ceremony,
quorum-member management, lost-key recovery) that deserves a
dedicated issue.

**To resolve**: confirm. Operators with regulatory requirements
(some financial-services trust-and-safety teams) may need quorum
day 1, in which case B is the minimum.
<!-- /OPEN -->

<!-- OPEN: Q6 -->
### Q6: Realtime daemon transport

The realtime daemon needs a wire protocol with the Polaris
backend.

- **A. gRPC over TLS-mutual-auth.** Polaris already gets `tonic`
  via #45 (classifier). Reuse.
- **B. Plain TCP with a Polaris-defined binary protocol.** Lighter.
  Hand-rolled.
- **C. SSH tunnel from backend to daemon, with a tiny RPC over
  stdin/stdout on the daemon side.** Operationally simple (SSH is
  ubiquitous); auth via SSH keys.

Recommend A. The gRPC dependency lands anyway via #45; reuse rather
than invent.

**To resolve**: confirm in implementation.
<!-- /OPEN -->

## Out of scope (within this issue)

- N-of-M quorum signing. Reserved for a future issue (Q5).
- Multiple parallel hardware tokens for HA (one primary, one hot
  spare). Future issue; involves token-to-token key duplication
  which is platform-specific.
- TPM mode (#48 covers that; they are complementary).
- Hardware-token-as-moderator-auth (the v1 hardware-key
  requirement). Different concern.
- Migrating an existing software key INTO a hardware token. Not
  supported; operators rotate to a new hardware-generated key.
- Cloud-HSM as a `cloud-kms-oracle` alternative. The v1
  `cloud-kms-oracle` mode covers cloud HSMs via network KMS.
- WebAuthn PRF from a browser (different attestation flow). v2
  focuses on server-side PKCS#11 / FIDO2 via the daemon.

## Suggested decomposition

1. **PR 1 — `SigningError::WouldBlock` variant.** Extends the v1
   enum; no behavioral change for existing impls. Foundation.
2. **PR 2 — `HwTokenSigningKey` impl, batch mode, PKCS#11 backend.**
   With softhsm2 fixture. AC-1 verifiable.
3. **PR 3 — `signature_status` schema + pending label queue.**
   Polaris-side label state machine. AC-2 verifiable.
4. **PR 4 — `polaris labeler-sign-pending` CLI.** End-to-end batch
   flow; operator-runnable. AC-2 end-to-end.
5. **PR 5 — `polaris-signer` daemon.** Realtime mode. gRPC over
   TLS-mutual-auth.
6. **PR 6 — Backend realtime client.** Connects to the daemon;
   handles disconnect / reconnect; AC-3 verifiable.
7. **PR 7 — FIDO2 PRF backend.** Adds touch-per-sign path. AC-6
   verifiable.
8. **PR 8 — Rotation in hardware-token mode.** Extends `polaris
   labeler-key rotate`. AC-8 verifiable.
9. **PR 9 — Documentation + runbook.** Hardware requirements,
   token initialization, PIN management, recovery from token
   loss. Critical for operator adoption.
10. **PR 10 — Audit + miri.** AC-5 and AC-7 verified.

PRs 1-4 deliver batch mode (the minimum viable). PRs 5-7 deliver
realtime. PRs 8-10 round out.
