# M5 design — Issue #48: Add TPM-sealed signing key SigningKey impl

## Summary

Add a fifth `SigningKey` trait implementation: PCR-bound TPM 2.0 sealing.
Restart is zero-touch but unseal only succeeds on the original hardware in
the original boot state, defending threats T1-T3 (at-rest, stolen-disk,
stolen-backup) and partially T4 (code-execution as the Polaris user can
call the TPM signing API but cannot exfiltrate key material to another
machine).

## v1 connection points

- v1 `SigningKey` trait (REQ-11 / AC-13 of
  `.design/polaris-proto-blue-integration.md`):
  ```rust
  trait SigningKey: Send + Sync {
      fn sign(&self, payload: &[u8]) -> Result<Signature, SigningError>;
      fn public_key(&self) -> &PublicKey;
  }
  ```
  Lives at `polaris-backend/src/labeler/signer/`. v1 ships four impls
  (`file_plain.rs`, `passphrase_sealed.rs`, `os_keychain.rs`,
  `cloud_kms.rs`). This issue adds a fifth.
- v1 §B threat-coverage table (`.design/polaris-proto-blue-integration.md`)
  is the framework: TPM mode sits between `os-keychain` and
  `cloud-kms-oracle` in the threat-defense spectrum. TPM defends T1-T3 like
  `os-keychain` but additionally defends key exfiltration under T4 (the
  TPM signs on behalf of the process; the private key never leaves the
  TPM).
- v1 Out of Scope: "TPM-sealed signing keys (PCR-bound at-rest). Post-v1;
  depends on operator demand and on `tpm2-tss` Rust bindings stabilizing."
  This issue is the post-v1 activation.
- v1 `polaris labeler-key rotate` (REQ-12 / AC-15) is the rotation path
  that must remain compatible. TPM mode requires re-sealing on rotation.

## Requirements

- REQ-1: A new `SigningKey` implementation
  `polaris-backend/src/labeler/signer/tpm.rs` that:
  - Generates a K-256 keypair INSIDE the TPM (the private key never
    exists outside the TPM).
  - Seals the keypair's TPM handle under a PCR policy.
  - Performs each `sign()` call via the TPM (no key material in process
    memory).
  - Exposes the public key extracted from the TPM at the same K-256
    curve Polaris uses for all signing.
- REQ-2: Selected via `[labeler.signing_key] mode = "tpm"` config key,
  consistent with the v1 selection pattern.
- REQ-3: Sealing policy bound to a configurable PCR set, default
  `PCR0, PCR4, PCR7` (firmware, bootloader, Secure Boot state). PCR set
  is operator-configurable; the default is auditable in the startup log.
- REQ-4: PCR-mismatch recovery is documented and supported. A
  `polaris labeler-key reseal-after-update` admin command, gated by an
  offline sealing-authorization token (Q3 below), re-seals the key to a
  new PCR state when the operator has performed a legitimate firmware /
  bootloader / Secure Boot update.
- REQ-5: All TPM error paths are typed. At minimum: `TpmError::Unavailable`
  (no TPM device), `TpmError::SealPolicyMismatch` (PCR state changed),
  `TpmError::PcrUpdateRequired` (sealing policy refers to PCRs that
  changed), `TpmError::HandleNotFound`, `TpmError::SigningFailed`.
- REQ-6: Conforms exactly to the v1 `SigningKey` trait. Callers (label
  emission, key rotation, public-key declaration) are unchanged.
- REQ-7: `unsafe` policy: any FFI to the TPM library is contained inside
  the chosen binding crate. Hand-written `unsafe` in `tpm.rs` is
  forbidden; if a workaround in `tpm.rs` requires `unsafe`, it gets a
  `// SAFETY:` block AND a miri test that exercises the invariant.
- REQ-8: Key rotation (`polaris labeler-key rotate`) works with TPM
  mode: generates a new keypair inside the TPM, seals it under the same
  PCR policy, writes the new `app.bsky.labeler.service` record, retains
  the old public key in `revoked_keys` (per v1 REQ-12), switches active
  signing to the new key. The old keypair's TPM handle is unsealed and
  destroyed.

## Acceptance Criteria

- [ ] AC-1: Soft-TPM (`swtpm`) fixture integration test signs a payload
      via the new impl; signature verifies against the public key
      returned by `public_key()`.
- [ ] AC-2: PCR-mismatch test: deliberately change a fixture PCR value
      between seal and unseal; `unseal` returns
      `TpmError::SealPolicyMismatch`. No process memory contains the
      private key after a failed unseal.
- [ ] AC-3: Polaris with `[labeler.signing_key] mode = "tpm"` starts on
      a host with the TPM populated, unseal completes within 5 seconds,
      and the labeler endpoint signs subsequent labels via the TPM.
- [ ] AC-4: Per-signature latency: under a soft-TPM fixture, p50 sign
      latency is <50ms; p99 is <200ms. Documented; real-hardware
      numbers expected to differ.
- [ ] AC-5: `polaris labeler-key reseal-after-update` performs the
      re-sealing flow without exposing key material to disk; verified by
      strace / equivalent confirmation that no `write()` to a non-TPM
      file descriptor carries the key bytes.
- [ ] AC-6: Key rotation flow works end-to-end in TPM mode: new keypair
      generated, sealed, declared, old key retained in `revoked_keys`,
      labels emitted post-rotation verify under the new key.
- [ ] AC-7: Exfiltration test: take a snapshot of the Polaris VM's
      disk + memory at runtime; copy it to a different machine; attempt
      to start Polaris in TPM mode from the snapshot. Unseal fails with
      `TpmError::SealPolicyMismatch` (because PCR values on the new
      machine differ).
- [ ] AC-8: `unsafe` audit: `cargo +nightly miri test -p polaris-backend
      --test tpm_signing` passes (any `unsafe` blocks in `tpm.rs` are
      exercised under miri).

## Architecture sketch

**Rust crate landscape.** Two real candidates, with current status to
verify at implementation time:

- `tss-esapi` (crates.io) — high-level Rust bindings to the
  `tpm2-tss` C library. Mature relative to alternatives. Requires
  `libtss2-esys` system library and `libtss2-tcti` for the
  transmission interface. Active maintenance as of writing.
- `cryptoki` — PKCS#11 bindings. Some TPM modules expose PKCS#11
  interfaces; this gives a TPM-via-PKCS#11 path. Less direct;
  better suited to hardware tokens (#49) than TPMs.

Recommend `tss-esapi` for #48; `cryptoki` is the right path for #49.
The split is intentional: TPM and PKCS#11 hardware tokens have
different operational profiles (TPM is unattended local; tokens are
attended portable).

**File layout.**
- `polaris-backend/src/labeler/signer/tpm.rs` — the impl.
- `polaris-backend/src/labeler/signer/tpm/seal.rs` — sealing logic.
- `polaris-backend/src/labeler/signer/tpm/pcr.rs` — PCR policy
  construction.
- `polaris-backend/src/labeler/signer/tpm/error.rs` — `TpmError`
  enum.
- `polaris-backend/src/labeler/signer/tpm/reseal.rs` — recovery
  command.
- `polaris-backend/src/bin/polaris.rs` (existing CLI) gets a new
  subcommand `labeler-key reseal-after-update`.
- `docs/operations/tpm-signing.md` — operator runbook.

**TPM operations sequence (sign path).**
1. At startup, Polaris reads `[labeler.signing_key.tpm] handle = "..."`
   pointing at a persisted TPM handle.
2. Polaris loads the sealed keypair from the handle. Loading requires
   policy authorization: the PCR state must match the seal-time
   policy.
3. The loaded keypair is held as an authorized TPM object reference
   (not key material in process memory).
4. Each `SigningKey::sign(payload)` call performs `Esys_Sign` against
   the TPM handle. The TPM returns a signature; the private key never
   leaves the TPM.
5. The public key, extracted once at startup via `Esys_ReadPublic`, is
   cached in process memory for `SigningKey::public_key()` calls.

**TPM operations sequence (key generation, one-time at first start).**
1. Operator runs `polaris labeler-key init --mode tpm --pcrs
   0,4,7`.
2. Tool starts a TPM session, builds a sealing policy
   (`Esys_PolicyPCR` against the selected PCRs).
3. Tool calls `Esys_Create` with the K-256 curve and the policy.
4. The resulting keypair's public part is extracted and written to
   the `app.bsky.labeler.service` record (via the existing
   `polaris-publish-labeler-record` tool).
5. The keypair's TPM handle is persisted at a stable NV index.

**PCR set choice.** The default `PCR0, PCR4, PCR7` is conservative:
- PCR0: firmware (UEFI). Changes on firmware update.
- PCR4: bootloader. Changes on bootloader update.
- PCR7: Secure Boot policy. Changes when Secure Boot keys change.

Operators with kernel-update-resilience requirements may want to
include PCR8 (kernel image). The trade-off is: more PCRs = stronger
binding, but more PCR-update events that require re-sealing.

**Recovery flow.** When a legitimate update changes the PCR state,
unseal fails on next start. The recovery command,
`polaris labeler-key reseal-after-update`, accepts an offline
sealing-authorization token (Q3) and re-seals the key under the new
PCR state. The offline token is the operator's "yes, this PCR change
is legitimate" signal; without it, an attacker who controls the boot
chain cannot transparently re-seal.

**`unsafe` discipline.** `tss-esapi` uses `unsafe` internally for FFI.
Polaris's `tpm.rs` does NOT introduce additional `unsafe`. If a path
requires `unsafe` (e.g., a missing safe wrapper in `tss-esapi`), the
right action is to upstream the safe wrapper, not to write `unsafe`
in Polaris.

**OS support.** Linux first (Linux 5.x+ kernel TPM driver, tpm2-tss
on most distros). macOS lacks a discrete TPM; Apple's Secure Enclave
is a different design and is a separate future issue. Windows TPM
support via `tss-esapi` is theoretically possible but untested in
the Polaris stack; v2 ships Linux-only.

**New migrations.** None on the Polaris DB side. The TPM-side state
(persistent handles, sealing policy) lives in the TPM hardware; it
is not Polaris DB state.

**Backwards-compatibility story.** Additive. Existing v1 modes are
unchanged. Operators choose TPM mode at fresh-deploy or via the
key-rotation flow (rotate to a new TPM-backed key, retain the old key
in `revoked_keys` so historical labels still verify).

**Dependencies on other M5 issues.** Independent. Specifically not
related to #49 hardware-token signing — TPM is locked to one machine
and unattended; hardware-token is portable and attended. The two are
complementary, not alternatives.

## Open questions

<!-- OPEN: Q1 -->
### Q1: `tss-esapi` maturity in 2026

The plan comment notes: "verify Rust binding maturity before
commitment." This is a real risk. As of v1 design time the bindings
were noted as immature. Action items at implementation time:

- Verify the current `tss-esapi` release version on crates.io.
- Check the maintainer's responsiveness in the last 6 months.
- Run the soft-TPM fixture test on Linux 6.x kernels.
- Confirm the K-256 curve is supported by mainstream TPMs in the
  field (P-256 is more universal; K-256 may be less broadly
  supported).

**To resolve**: implementer-driven, during PR 1. If `tss-esapi`
proves unworkable, the alternative is `cryptoki` + a software-TPM
PKCS#11 module (less idiomatic but functional).
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: K-256 vs. P-256 curve in TPM

ATProto labels use K-256 (secp256k1). Most TPMs more reliably support
P-256 (NIST). Options:

- **A. K-256 only.** Refuse TPM mode on TPMs that don't support
  K-256. May exclude common TPM hardware.
- **B. Allow P-256 + sign-converted-output.** TPM generates and
  signs with P-256; Polaris bridges the output to K-256-shaped
  signatures. Risk: signature shape mismatch with ATProto
  consumers.
- **C. Support both curves; Polaris's label format declares which
  curve the signing key uses.** ATProto's
  `app.bsky.labeler.service` allows declaring the public key as a
  `did:key`, which encodes the curve. Downstream consumers must
  honor the declared curve.

Recommend C. ATProto's spec actually allows multiple curves for
labeler signing keys via the `did:key` declaration. Confirm against
the current Bluesky verifier implementation; if Bluesky's verifier
hard-codes K-256, A is the only safe choice.

**To resolve**: implementer must verify Bluesky's current label
verifier curve support before committing to C.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: Recovery-after-PCR-change authorization mechanism

When PCR state changes (legitimate update), unseal fails. Options
for the recovery authorization:

- **A. Offline sealing-authorization token** (proposed). Generated
  at TPM-key-init time, stored offline (paper, hardware token,
  separate machine). Required to re-seal. Strongest; operationally
  heavy.
- **B. Owner-authorization at the TPM level.** TPM owner-auth
  password unlocks re-sealing. Less strong (a host compromise that
  recovers owner-auth can re-seal arbitrarily).
- **C. Sealing-policy update via senior-moderator co-sign.**
  Re-sealing requires a second Polaris moderator's hardware-key
  approval through a Polaris admin endpoint. Polaris-native;
  doesn't depend on offline material.

Recommend A. The whole point of TPM sealing is offline-immutable
custody; the recovery path must match the strength of the seal.

**To resolve**: confirm. Some operators may push back on the
operational complexity of A; C is the fallback for those.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: How does TPM mode interact with high availability?

A TPM-bound key is locked to one machine. Polaris HA typically
requires hot-standby instances; if the primary fails, the standby
takes over. Options:

- **A. Single-host-TPM only.** No HA support in TPM mode. Operators
  needing HA use `cloud-kms-oracle` or accept downtime on
  primary failure.
- **B. Per-host TPM keys, key-rotation on failover.** Each host has
  its own TPM-sealed key; failover rotates to the standby's key.
  Requires the `app.bsky.labeler.service` record to be re-published
  on failover.
- **C. TPM key replication via TPM key duplication / migration.**
  Some TPMs support exporting a key to another TPM under specific
  policies. Highly platform-dependent; risk of being mis-implemented.

Recommend A. TPM mode is for operators who chose unattended-strong-
custody over HA. Operators who need HA pick `cloud-kms-oracle`.

**To resolve**: confirm. Bluesky's first-party deployment uses
`cloud-kms-oracle` so this isn't their concern. Labeler operators
with HA needs are a small segment.
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: TPM owner authorization on shared / multi-tenant hosts

If Polaris is one of several services on a host, TPM owner-
authorization conflicts may arise. Polaris's TPM operations should
happen under a TPM application-level handle that doesn't require
owner-auth.

This is mostly an operational question (operator must allocate a
TPM hierarchy for Polaris) but the documentation must call it out.

**To resolve**: documentation in
`docs/operations/tpm-signing.md` covers the multi-tenant case. Not
a design-time blocker.
<!-- /OPEN -->

## Out of scope (within this issue)

- macOS Secure Enclave support. Different architecture; a separate
  future issue.
- Windows TPM via `tss-esapi` — theoretically possible but not
  tested in v2. Linux-only.
- TPM-bound moderator authentication (using TPM as the user's
  hardware factor). v1 hardware-key requirement (`design.md` §9) is
  separate.
- TPM remote attestation (proving to a third party that Polaris is
  running on a specific PCR state). Useful but a much larger design.
- Migrating an existing `file-plain` or `passphrase-sealed` key
  INTO a TPM. Not supported; operators must rotate to a new
  TPM-generated key (which is the correct way: the existing key was
  exposed to disk / memory and has a different threat history).
- TPM-bound database encryption keys. Polaris's database is
  Postgres; database encryption is operator-managed.
- HSM-backed mode for organizations that want shared HSM-stored
  keys (vs. per-host TPM). HSMs are covered by `cloud-kms-oracle`
  via PKCS#11 over a network or by #49 hardware-token mode.

## Suggested decomposition

1. **PR 1 — Spike: verify `tss-esapi` viability.** Throwaway branch
   running a basic soft-TPM seal + sign test. Resolves Q1 and the
   curve question Q2 against the current Bluesky verifier.
2. **PR 2 — `TpmSigningKey` impl skeleton.** Implements the
   `SigningKey` trait, with `TpmError` enum and the soft-TPM
   fixture test. AC-1 verifiable.
3. **PR 3 — PCR-policy sealing.** Adds the PCR binding; AC-2 and
   AC-7 verified.
4. **PR 4 — Key-init command.**
   `polaris labeler-key init --mode tpm`. AC-3 end-to-end.
5. **PR 5 — Key rotation.** Extends `polaris labeler-key rotate`
   to TPM mode. AC-6 verified.
6. **PR 6 — Reseal-after-update command.** Implements
   `polaris labeler-key reseal-after-update` with offline-token
   authorization. AC-5 verified.
7. **PR 7 — Documentation + runbook.** Operator guide for TPM
   mode: hardware requirements, PCR choices, recovery procedure.
8. **PR 8 — miri + `unsafe` audit.** Confirms AC-8 and the
   no-hand-`unsafe` policy.

PRs 1-4 are the minimum viable; PRs 5-8 fill out the operational
surface.
