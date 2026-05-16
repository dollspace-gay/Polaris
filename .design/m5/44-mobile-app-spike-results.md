# Mobile platform spike — results & recommendation

**Issue:** #115 / M5 #44 PR 1
**Status:** ARCHITECTURAL DECISION (spike-not-run-on-hardware)
**Decision:** Tauri Mobile as the primary path, PWA as the planned fallback

---

## Scope

Decide whether the M5 #44 mobile on-call surface ships as a Tauri
Mobile app or as a Progressive Web App (PWA). The decision binds the
remaining mobile-epic PRs (#116–#122).

## Why this isn't a hardware-tested spike report

The issue body specifies a 1-week prototype with on-device
measurements (iOS push latency, Android build path, Tauri Mobile
maturity check). That requires:

- An Apple Developer account ($99/year)
- iOS hardware with a configured provisioning profile
- Android hardware with USB debugging enabled
- A real APNs test certificate

None of these are available in the current session's substrate. The
spike's hardware-measurement deliverable is necessarily a follow-up
operator activity, not session-scope code.

What the session **can** ship is the architectural decision the
spike would inform, derived from the documented constraints and the
shape of the rest of the M5 #44 epic. Operators with hardware-access
can validate the recommendation; the binding goes to the recommendation
unless operator measurement contradicts it.

## Recommendation

**Tauri Mobile is the primary path.** PWA is the planned fallback if
Tauri Mobile maturity proves blocking when on-device validation runs.

### Why Tauri Mobile

1. **Rust end-to-end.** The desktop frontend is Leptos compiled to
   wasm. Tauri Mobile hosts the same Leptos bundle in a native shell on
   iOS and Android. The shared codebase materially reduces drift between
   the desktop and mobile surfaces — every fix to `PolarisApiClient`,
   `case_view`, action handling, etc. lands once.

2. **APNs / FCM integration is uniform.** The native shell exposes
   platform push tokens through Tauri's command bridge; the mobile-shell
   Rust code feeds them to the backend's `/api/devices/register`
   endpoint (#116 PR 2 surface). The PWA path requires a parallel
   service-worker-driven push registration that doesn't compose with
   the desktop's existing OAuth state.

3. **Hardware-key (REQ-6 / AC-6) works uniformly.** Tauri Mobile's
   webview hosts WebAuthn the same way Safari and Chrome do; the
   biometric platform-authenticator path works identically across
   desktop + mobile-Tauri without per-platform shims.

4. **App Store distribution available.** Critical for the on-call
   moderator workflow — operators need a one-tap install path their
   mod team can use without bypass-warning friction. PWAs on iOS
   require manual "Add to Home Screen" + permission grants for push.

5. **Native back-press / OS lifecycle hooks.** The native shell
   gets foreground / background / kill events the PWA can't observe;
   matters for the P1 escalation push-handler that needs to wake the
   app cold-started.

### Why PWA as the fallback (not the primary)

PWA wins on **shipping speed** (no app-store review cycle, no
Apple Developer account, no provisioning profiles) and **immediate
update propagation** (no version-mismatch tail). Both matter for
operators who have to ship a mobile surface yesterday with no
existing infrastructure.

But PWA loses on:

- **iOS push notification reliability.** Safari's web-push support
  arrived in iOS 16.4 (2023); coverage and latency are still uneven
  across versions and lock-screen states. The P1 escalation surface
  (REQ-1: 30s push latency) lives or dies on this property.
- **OAuth-flow ergonomics.** PWA on iOS Safari + OAuth redirect +
  in-app-browser context handoff has known quirks; Tauri Mobile's
  `ASWebAuthenticationSession` path is the documented OS-supported
  flow.
- **Update isolation.** PWA updates ship to everyone simultaneously;
  Tauri Mobile lets operators stage rollouts via TestFlight + Google
  Play internal tracks.

### Concrete blockers that would flip the decision to PWA

If on-device measurement shows ANY of:

1. Tauri Mobile + Leptos combination produces a >2s cold-start on
   mid-tier Android (e.g. Pixel 5a). The P1 escalation path AC-2
   targets <5s end-to-end (tap-to-render); >2s cold-start eats most
   of that budget.
2. Tauri Mobile's APNs/FCM token plumbing requires per-app-instance
   manual configuration that doesn't compose with the operator's
   existing backend secrets management. (PWA's service-worker push
   path is more uniform across operators.)
3. iOS App Store reviewers reject the WKWebView-based shell for
   reasons the Tauri community can't quickly route around.

If any of those land during on-device validation, the planned fallback
is documented above and the M5 #44 epic's PR 2-7 can be re-cut against
the PWA architecture without re-doing the design.

## Measurement protocol (for the operator-driven spike)

Once hardware-access is available, the documented validation steps:

### iOS push latency

1. Build Tauri Mobile shell against the polaris-backend's current
   `main` HEAD, sign with a TestFlight provisioning profile.
2. Configure backend with the APNs sandbox endpoint
   (`api.sandbox.push.apple.com`).
3. Fire 50 synthetic P1 escalation events via the `polaris federation-escalate`
   CLI (or a dedicated test endpoint), each with a unique payload that
   logs receipt-timestamp on the device.
4. Report median + p95 latency. REQ-1 target: <30s; concerning if
   p95 > 10s.

### Android build path

1. Time from `git clone polaris` to `cargo tauri android build` →
   APK on a Pixel 5a (or equivalent mid-tier).
2. Report wall-clock + step count.
3. Concerning if > 30 minutes from clean clone OR > 10 explicit
   manual steps.

### Tauri Mobile + Leptos integration

1. Verify `polaris-frontend` compiles against the wasm target Tauri
   Mobile expects (likely `wasm32-unknown-unknown` per the desktop
   path).
2. Confirm `web-sys` window/document APIs work inside the WKWebView
   / Android WebView the shell hosts.
3. Concerning if any v1 frontend feature (case-view, action composer,
   dashboard) breaks under the Tauri Mobile shell.

### Bundle size

1. Compare PWA service-worker shell (built via `trunk build --release`)
   vs Tauri Mobile shell (APK + IPA) raw + gzipped sizes.
2. Reference: keep mobile shell < 25 MB raw (matches the M5 #44
   on-call use case — operators install on personal devices, not
   org-managed fleets).

## Next steps

PR 2-7 of the mobile epic (#116-#121) proceed against the Tauri
Mobile decision. If the operator-driven validation flips the
decision to PWA, the relevant sub-issues get a re-author pass
against the PWA architecture before merging.

The platform-validation work doesn't block PR 2 (#116 — backend
push subsystem); the backend's APNs+FCM+ntfy dispatcher is
mobile-shell-agnostic. PRs 3-7 (the mobile shell + the case view,
OAuth, take-ownership, call-senior wiring) depend on the platform
choice.
