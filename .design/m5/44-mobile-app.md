# M5 design — Issue #44: Add mobile / on-call surface for escalation response

## Summary

Ship a constrained mobile client that lets an on-call moderator respond to
P1 escalations from a phone — receive a push notification, view the case
read-only, take ownership, and call a senior reviewer. Full moderation
workflows stay on the desktop tool. The explicit non-goal is "moderation
from a phone"; the explicit goal is "P1 incident response from a phone."

## v1 connection points

- `design.md` §10: "Mobile. Moderation work is desk work, but on-call
  escalation may want a mobile surface. Out of scope for v1, worth
  revisiting." This issue is the revisit.
- `.design/polaris-proto-blue-integration.md` Out of Scope: "Mobile /
  on-call surface (`design.md` §10). Out of scope." Confirming the v1
  deferral was intentional.
- Builds on the existing `polaris-backend` HTTP API and `polaris-frontend`
  surface — the mobile client is another consumer of the same backend, not
  a parallel implementation.
- Builds on the moderator auth surface defined in v1
  (`polaris-backend/src/auth/{oidc,atproto}.rs`). The mobile client uses
  the same auth backends; no mobile-specific auth path.
- Uses the same hardware-key requirement (v1 §9 threat 1: "SSO + hardware
  key required"). Mobile must support hardware-key auth or it does not
  satisfy the security model.

## Requirements

- REQ-1: A push notification path delivers a P1 escalation alert to the
  on-call moderator's device within 30 seconds of the escalation event.
- REQ-2: A read-only mobile UI surfaces: subject identity, severity,
  reporting summary (counts + categories, no reporter identity), pattern
  observations, and the v1 case timeline.
- REQ-3: Two write operations are available from mobile:
  `take_ownership` (mark the incident as actively held by this moderator,
  bumping the v1 case lock) and `release_ownership` (return to queue). No
  Label / Takedown / Mute / Warn from mobile in v2.
- REQ-4: A `call senior` button initiates a phone call (using OS dialer
  intent / `tel:` URL) to the senior moderator on duty, with the case ID
  pasted into the call's note context if the platform supports it.
- REQ-5: Mobile uses the existing moderator auth backends (OIDC or ATProto
  OAuth) via OS browser + custom-scheme deep-link callback. No password
  auth, no client-side credentials.
- REQ-6: Hardware-key support: at minimum WebAuthn via the OS biometric
  prompt (iOS Face/Touch ID, Android biometric) on devices that have it.
  When hardware-key is required by config, devices without it cannot
  complete auth.
- REQ-7: Offline-first is explicitly NOT a goal. P1 escalation response
  requires network; the app should fail loudly when offline, not pretend
  to work.
- REQ-8: The mobile app's network surface is a strict subset of the v1
  HTTP API. No new endpoints invented for mobile; if mobile needs
  something the desktop tool doesn't, the desktop tool gets it too.

## Acceptance Criteria

- [ ] AC-1: On a real device (iOS ≥16, Android ≥12), a P1 escalation fired
      on the backend causes a push notification to appear within 30 seconds.
      Measured on a controlled test network.
- [ ] AC-2: Tapping the notification opens the app to the relevant
      incident case view. Cold start (app killed) is acceptable up to 5
      seconds total time.
- [ ] AC-3: A moderator can complete `take_ownership` from the case view
      and the v1 case lock visible in the desktop UI reflects the
      ownership within 2 seconds.
- [ ] AC-4: A moderator can complete `call senior` and the OS dialer
      opens with the senior moderator's number prefilled.
- [ ] AC-5: Auth flow works end-to-end with both OIDC and ATProto OAuth
      backends, using the OS browser for the consent step.
- [ ] AC-6: Hardware-key requirement: with `[security] require_hardware_key
      = true`, an attempt to authenticate on a device without WebAuthn
      biometric capability fails at the OS step with a clear error
      message.
- [ ] AC-7: Network-down state: with airplane mode on, the app shows a
      clear "no connectivity, cannot respond to P1 — switch network"
      banner and disables `take_ownership` / `release_ownership` /
      `call senior` controls.
- [ ] AC-8: Push notification has no PII in the payload (no moderator
      name, no subject content) — only a generic "Polaris: P1 incident
      requires response" plus the incident ID for deep-link.

## Architecture sketch

**Platform choice — see Q1.** The plan comment names Tauri Mobile, PWA,
and React Native as candidates. The proposed default is Tauri Mobile,
because it lets the entire stack stay Rust (the desktop frontend is
Leptos+WASM in `polaris-frontend/`; Tauri Mobile would host the same
Leptos code in a native shell on iOS/Android). The fallback is PWA —
extending `polaris-frontend` with a mobile route subset and shipping it
as an installable PWA.

**Crate / module layout (assuming Tauri Mobile).**
- `polaris-mobile/` — new workspace crate. Tauri Mobile app shell.
- `polaris-mobile/src-tauri/` — Rust shell with iOS/Android-specific
  bridges for push notification registration and biometric prompt.
- `polaris-mobile/src/` — Leptos UI subset, reuses
  `polaris-frontend/src/api_client.rs` (the `PolarisApiClient` from v1)
  and a small subset of `polaris-frontend/src/components/`.
- `polaris-backend/src/notifications/push.rs` — new module that fans
  out P1 escalations to APNs (iOS) and FCM (Android).
- `polaris-backend/src/notifications/registration.rs` — endpoint where
  the mobile app registers its device token.

**Push notification path.** The backend already emits P1 escalation
events on the internal bus (Kafka/NATS per v1 §3.1). A new subscriber in
`polaris-backend/src/notifications/push.rs` consumes those events,
looks up the on-call moderator's device tokens from a new
`mobile_devices` table, and pushes via APNs/FCM. The push payload has
NO PII (REQ-8) — just `{ "type": "p1", "incident_id": "..." }` —
respecting v1's "no PII in logs by policy" principle.

**Auth flow.** Mobile cannot embed a webview-based login (it defeats the
"OS browser is the trust boundary" property hardware keys depend on).
Flow: app sends user to OS browser via
`ASWebAuthenticationSession` (iOS) / Custom Tabs (Android). Browser
hits Polaris's OIDC or ATProto OAuth endpoint, completes login,
redirects to `polaris://callback?session=...`. Mobile app receives the
session token via custom-scheme deep-link.

**Hardware-key on mobile.** WebAuthn on iOS Safari ≥16 and Android
Chrome supports biometric (Face/Touch ID, Android Biometric) as a
platform authenticator. External keys (YubiKey) over USB/NFC are
supported on both platforms but with caveats. v2 baseline:
platform-authenticator only (biometric). External hardware-key support
is a future issue.

**New migrations.**
- `mobile_devices` table — moderator ID, platform (iOS/Android), push
  token, last-active timestamp.
- `oncall_schedule` table — who is on-call when (could also be
  pulled from PagerDuty / Opsgenie via integration, but the v2 baseline
  is a Polaris-internal schedule).

**Backwards-compatibility story.** Additive. v1 deployments work
unchanged; the mobile app is a new client. Backends without the
notifications worker can be deployed and the mobile app simply never
gets P1 push.

**Dependencies on other M5 issues.** Independent of #42, #43, #45,
#46, #47. Soft-dependent on #48/#49 — if those hardware-key flows are
required by config, the mobile app must integrate compatibly (WebAuthn
on mobile is platform-authenticator; external hardware-keys via mobile
are out of scope for this v2 baseline).

## Open questions

<!-- OPEN: Q1 -->
### Q1: Tauri Mobile vs. PWA vs. React Native vs. native

- **A. Tauri Mobile (proposed).** Reuses the existing Leptos codebase
  with a Rust-end-to-end story. Risks: Tauri Mobile is newer and less
  mature than its desktop sibling; iOS App Store review of WKWebView-
  based apps has historical quirks; performance on Android can be
  variable.
- **B. PWA.** No native shell. Extend `polaris-frontend` with a
  `viewport=mobile` route subset; ship as an installable PWA. Risks:
  push notification support is unreliable on iOS Safari (it works in
  iOS 16.4+ for installed PWAs but is constrained); no OS-level
  background; App Store distribution unavailable.
- **C. React Native / Flutter.** Cross-platform native UI. Risks: new
  toolchain in the Polaris stack; not Rust; type-sharing with the
  backend is now an additional layer.
- **D. Native (Swift + Kotlin).** Best per-platform UX. Cost: two
  codebases, two skill sets, longest path to ship.

Recommend A as the default, with B as the planned fallback if Tauri
Mobile maturity blocks shipping.

**To resolve**: human decision after a 1-week prototype spike against
both A and B. The right answer depends on (a) whether iOS PWA push
notification latency meets REQ-1, and (b) whether the Leptos+Tauri
Mobile combination builds and runs on a real device with the existing
codebase. Measure both; pick on evidence.
<!-- /OPEN -->

<!-- OPEN: Q2 -->
### Q2: Push notification infrastructure

Direct integration with APNs (Apple) and FCM (Google) requires:
- An Apple Developer account ($99/year) and provisioning certs.
- A Firebase project (free tier covers low volumes).
- Token rotation, certificate renewal, error handling for stale tokens.

Alternative: use a push aggregator (Pushover, OneSignal, ntfy.sh,
etc.). Pro: less ops burden. Con: another vendor in the data path,
and self-hosted labelers may not want a third party in their alert
chain.

**To resolve**: for the Bluesky profile, direct APNs+FCM is the
right answer (they have the org for it). For the labeler profile,
ntfy.sh or self-hosted ntfy is a better fit (a 3-person labeler does
not want to manage Apple certs). Recommend supporting both with a
config switch.
<!-- /OPEN -->

<!-- OPEN: Q3 -->
### Q3: External hardware keys on mobile (YubiKey via USB-C / NFC)

iOS supports YubiKey via Lightning, USB-C (5Ci, 5C NFC), and NFC
through the WebAuthn API in Safari ≥16 and via the YubiKit SDK.
Android supports USB and NFC YubiKeys. But: each integration has
quirks (NFC tap-to-auth UX, USB-C cable juggling).

Options:
- A. Platform authenticator only in v2. External hardware-keys are a
  future issue.
- B. Support NFC YubiKeys in v2 (iOS and Android both support
  this).
- C. Full external-hardware-key matrix in v2.

Recommend A. The on-call use case is "respond from anywhere"; if the
moderator's phone has biometric set up, that's the path of least
friction. Hauling a YubiKey around for P1 response is unrealistic.

**To resolve**: human decision. Tied to the v1 hardware-key policy
in `design.md` §9 — if the policy is "hardware key REQUIRED for all
operations," option A fails for the operations the mobile app
supports. If the policy is "hardware key required for high-impact
operations" (which the mobile app does NOT expose: only
take/release/call), option A is fine.
<!-- /OPEN -->

<!-- OPEN: Q4 -->
### Q4: Schedule and on-call rotation source

The push fan-out (REQ-1) needs to know who is on-call. Options:

- A. Polaris-internal schedule (new `oncall_schedule` table, admin
  UI to manage).
- B. External integration (PagerDuty, Opsgenie webhook). Polaris asks
  the external service "who is on call right now" before pushing.
- C. All-on-call (push goes to every registered device of every
  authorized moderator). Simplest; ignores rotation.

Recommend A as the v2 baseline (most operators don't want a
PagerDuty dependency just to know who is on call) with B as a
follow-up issue.

**To resolve**: human decision. C might actually be fine for
labelers with a 3-person team where everyone is always notionally
on-call.
<!-- /OPEN -->

<!-- OPEN: Q5 -->
### Q5: How does the desktop tool know about the mobile-registered ownership take?

When a moderator on mobile takes ownership of an incident, the
desktop tool needs to reflect this in real time. v1 already uses
WebSocket push for live updates (per `design.md` §3 architecture
diagram, "WebSocket push for live updates and locks"). The mobile
action should fan out through the same channel.

This is mostly straightforward but it does mean the mobile
write-path must commit through the same v1 case-lock infrastructure
as the desktop write-path. No mobile-specific shortcut.

**To resolve**: confirm during implementation. Likely no design-time
work needed; this is a "be careful in code review" item.
<!-- /OPEN -->

## Out of scope (within this issue)

- Full moderation workflows from mobile (Label, Takedown, Mute, Warn,
  Escalate). These remain desktop-only in v2.
- Writing free-text reasoning on mobile (the v1 `Action.reasoning`
  field requires careful, considered text; mobile soft keyboards are
  not the right input device).
- Mobile pattern dashboard (the dashboard is dense and needs a large
  screen).
- Offline support / IndexedDB / local case cache. P1 response requires
  network; we fail loudly when offline.
- Tablets as a separate form factor. Tablets get the desktop UX
  (`polaris-frontend`) in their browser.
- Mobile-side ML classifier (#45) integration. The mobile app consumes
  classifier signals via the same backend API; it does not invoke
  classifiers directly.

## Suggested decomposition

1. **PR 1 — Prototype spike (Tauri Mobile vs. PWA).** 1 week, two
   throwaway branches. Measure REQ-1 push latency on iOS for both,
   measure build + install path on Android for both. Pick the
   platform on evidence and document the decision.
2. **PR 2 — Backend push notification subsystem.** APNs + FCM
   integration in `polaris-backend/src/notifications/push.rs`,
   `mobile_devices` table, the `/api/devices/register` endpoint. No
   mobile app yet; verifiable from a manual `curl + APNs sandbox`
   test.
3. **PR 3 — Mobile app shell + auth.** App boots, can complete
   OIDC and ATProto OAuth login via OS browser, receives session
   cookie via deep-link. No case view yet.
4. **PR 4 — Read-only case view.** Mobile receives a deep-link to an
   incident, fetches case data from `PolarisApiClient`, renders the
   read-only subset.
5. **PR 5 — Take/release ownership.** Two mutating endpoints, with
   the existing v1 case-lock plumbing. Desktop reflects the change
   via WebSocket.
6. **PR 6 — Call senior.** OS dialer intent, on-call schedule
   lookup. The most important PR for the actual P1 use case.
7. **PR 7 — Hardware-key (platform authenticator) enforcement.**
   WebAuthn via biometric, enforced by the existing v1 hardware-key
   config flag.
8. **PR 8 — Documentation + ops runbook.** How to register a device,
   how to test the push path, how to revoke a device. Critical for
   operator adoption.

Each PR is small and shippable. The product is usable after PR 6;
PR 7 hardens it; PR 8 makes it operable.
