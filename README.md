# Polaris

A gift-quality replacement for Ozone built around moderation-as-pattern-recognition with a calibrated human-in-the-loop, not a ticket queue. Polaris is an ATProto labeler and moderation tool for Bluesky and independent labeler operators — MIT-licensed, designed for both Bluesky's multi-region deployment and single-VM community labelers sharing one codebase.

## Quick start

There are two paths through Polaris depending on what you're trying to
do. Operators ship it; developers extend it.

### Path A — Operator (deploy Polaris)

One command from a fresh Linux host:

```sh
curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash
```

Or, from a checked-out repo:

```sh
./scripts/install.sh
```

The script verifies Docker + Compose v2, locates (or builds) the
`polaris-setup` binary, generates `deploy/.env` (mode 0600) and
`client-metadata.json` with freshly-rolled secrets, and prints the
exact `docker compose up -d` command for you to run. It never
auto-starts the stack.

Set `POLARIS_HOSTNAME` in the environment before piping when there's
no tty (i.e. the `curl … | bash` path):

```sh
POLARIS_HOSTNAME=mod.example.com bash -c \
  'curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash'
```

The full 15-minute walkthrough — including the in-browser setup wizard
(signing key, labeler service record, DID document) and the
multi-hour third-party-labels cold-start — is in
[`docs/ops/quick-start.md`](docs/ops/quick-start.md). Upgrading an
existing install is covered in [`docs/ops/upgrade.md`](docs/ops/upgrade.md).

### Path B — Developer (work on Polaris)

```sh
# Build all workspace crates
cargo build --workspace

# Run the backend (development mode)
cargo run --package polaris-backend

# Run workspace tasks
cargo xtask --help
```

Requires Rust 1.85 or later (pinned in `rust-toolchain.toml`).

Operators do not need to build from source — the `ghcr.io/dollspace-gay/polaris-backend`
image (multi-arch: linux/amd64 + linux/arm64) is the supported
production artefact, and `scripts/install.sh` is the supported entry
point.

## AI moderation

Polaris ships an LLM moderation-assist substrate that lets a model
recommend (or, with operator opt-in, autonomously apply) moderation
actions. The feature is **off by default** and gated end-to-end by a
versioned policy workbook plus eight server-side safety floors — the
LLM never decides on its own which policy applies, what action verb is
legal, or whether autonomy is even allowed for the case in front of it.

Three operator-selectable modes, configured **per policy** in
`mod_policies`:

| Mode | What happens to a recommendation |
|---|---|
| `manual` *(default)* | Shows in the case-view advisory panel; a human moderator decides. |
| `assisted` | Lands in `pending_auto_actions` as a draft; a moderator clicks approve / reject. |
| `autonomous` | When confidence + safety floors clear, the action emits to atproto without human review. Reversible within 24 hours. |

What's shipped today:

- gRPC `Recommend` RPC on `polaris.classifier.v1.Classifier`
  ([`proto/polaris-classifier-v1.proto`](proto/polaris-classifier-v1.proto)).
- [Fixture adapter](examples/llm-fixture-adapter/) for end-to-end
  wire-up validation without a real model.
- [Live-LLM reference implementation](examples/llm-prompt-reference/)
  against Qwen 2.5 32B Instruct (Q3_K_M GGUF, ~16 GB VRAM) via
  `llama-cpp-python` — including a quality-gate smoke test on an
  ambiguous criticism-vs-harassment case.
- Dispatcher with three-mode routing (manual / assisted / autonomous)
  and the eight server-side safety floors (CSAM hard block, global
  kill switch, reversal-rate breaker, per-policy rate limit, subject
  cooldown, account-takedown gate, action-kind gate, confidence floor).
- Admin pages: `/admin/llm/audit` (filterable autonomous-action audit
  with full LLM envelope), kill-switch toggle, dry-run calibration
  replay (`POST /api/admin/llm/dry-run`).
- Feedback loop: every reversal and rejection fires a structured
  `Feedback` RPC back to the LLM substrate; daily confirmation batch
  emits positive-signal feedback when an autonomous action survives
  its 24-hour reversal window.

**Enabling it is a single env-var**:

```sh
# Point Polaris at your gRPC adapter; restart polaris-backend.
POLARIS_LLM_ENDPOINT=http://llm-adapter:50052
```

`polaris-backend` reads the variable at boot, connects a
`TonicClassifierClient` to that endpoint, seeds the
`autonomous-agent` moderator row that's the FK target for every
autonomous-emitted action, constructs the `RecommendDispatcher` with
the live label emitter attached, and installs it onto `ApiState`.
Connect failures abort startup — the substrate is opt-in, so silent
fallback to manual moderation is the wrong default. When the
variable is unset the dispatcher slot stays `None` and every LLM API
route returns the "no dispatcher configured" branch.

The remaining tunables (`POLARIS_LLM_RECOMMEND_TIMEOUT_MS`,
`POLARIS_LLM_EXTERNAL`, `POLARIS_LLM_NAME`,
`POLARIS_LLM_SEND_FEEDBACK`) are documented in
[`deploy/.env.example`](deploy/.env.example).

Full runbooks:

- [`docs/ops/llm-moderation.md`](docs/ops/llm-moderation.md) — the
  operator runbook: fixture wire-up, per-policy autonomy enablement,
  safety floors in plain English, kill-switch usage, audit page,
  common adapters (vLLM / Claude / OpenAI / Bedrock).
- [`docs/ops/policy-autonomy.md`](docs/ops/policy-autonomy.md) —
  the safety-invariant catalogue, `human_required_always` semantics,
  and the three independent enforcement layers (workbook API,
  action-create API, dispatcher).
- [`.design/llm-moderation-assist.md`](.design/llm-moderation-assist.md)
  — full design doc with every REQ-* traced through to a test.

## Workspace layout

| Crate | Role |
|---|---|
| `polaris-types` | Plain Rust domain types shared by backend and frontend. No ATProto dependency. |
| `polaris-backend` | Axum HTTP server, labeler XRPC endpoint, ingest workers, label signing. |
| `polaris-frontend` | Leptos WASM moderation dashboard. |
| `xtask` | Workspace automation (`cargo xtask <subcommand>`). |

## Deployment

Operator artefacts live under [`deploy/`](deploy/) and the runbooks
under [`docs/ops/`](docs/ops/):

| Path | Purpose |
|---|---|
| `scripts/install.sh` | One-shot operator bootstrapper. Checks prerequisites, runs `polaris-setup`, prints the `docker compose` command. |
| `polaris-backend/src/bin/polaris_setup.rs` | `polaris-setup` config-templating CLI: writes `.env` (mode 0600) + `client-metadata.json` with freshly-rolled secrets. Built as `cargo build -p polaris-backend --bin polaris-setup`; usable as an IaC escape hatch when you don't want the install script. |
| `ghcr.io/dollspace-gay/polaris-backend:latest` | Multi-arch (amd64 + arm64) published image. Compose pulls this by default; pin `POLARIS_IMAGE_TAG=vX.Y.Z` for reproducible upgrades. |
| `deploy/docker-compose.yaml` | Labeler-profile single-host stack (backend + Postgres + Redis + NATS + Caddy). |
| `deploy/Caddyfile.example` | TLS termination + reverse proxy template for the compose stack. |
| `deploy/.env.example` | Every env var `AppConfig` reads, documented inline. |
| `deploy/Dockerfile.labeler-profile` | Alpine-glibc-runtime image for self-hosted operators (source of the published image). |
| `deploy/Dockerfile.bluesky-profile` | `FROM scratch` musl-static image (≤ 50 MB budget) for first-party fleets. |
| `deploy/helm/` | Helm chart (Postgres + Redis + NATS sub-charts, Ingress, securityContext). See [`deploy/helm/README.md`](deploy/helm/README.md). |
| `deploy/systemd/polaris.service` | Bare-VM systemd unit with hardening directives. See [`deploy/systemd/README.md`](deploy/systemd/README.md). |
| `docs/ops/quick-start.md` | 15-minute install-to-running runbook for the compose stack. |
| `docs/ops/upgrade.md` | Standard upgrade flow, migration handling, and rollback. |
| `docs/ops/backup.md` | Postgres PITR + S3-object-lock attestation + quarterly restore drill. |
| `docs/ops/llm-moderation.md` | Wire-up tutorial, per-policy autonomy enablement, safety floors, kill switch, common LLM adapters. |
| `docs/ops/policy-autonomy.md` | `human_required_always` invariant, the three enforcement layers, pause / resume workflow. |
| `docs/ops/policy-management.md` | Versioned workbook (`mod_policies`), seed YAML, `polaris-setup seed-policies`. |
| `docs/ops/classifier-integration.md` | Sibling guide for the non-LLM `Classify` / `ClassifyStream` / `Feedback` / `HealthCheck` RPCs. |
| `examples/llm-fixture-adapter/` | Rust gRPC fixture returning canned `RecommendResponse`s for end-to-end plumbing checks. |
| `examples/llm-prompt-reference/` | Python reference impl against Qwen 2.5 32B Instruct (GGUF + llama-cpp-python) including a quality-gate smoke test. |

## License

MIT — see [`LICENSE`](LICENSE).
