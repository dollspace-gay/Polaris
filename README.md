# Polaris

A gift-quality replacement for Ozone built around moderation-as-pattern-recognition with a calibrated human-in-the-loop, not a ticket queue. Polaris is an ATProto labeler and moderation tool for Bluesky and independent labeler operators — MIT-licensed, designed for both Bluesky's multi-region deployment and single-VM community labelers sharing one codebase.

## Quick start

```sh
# Build all workspace crates
cargo build --workspace

# Run the backend (development mode)
cargo run --package polaris-backend

# Run workspace tasks
cargo xtask --help
```

Requires Rust 1.85 or later (pinned in `rust-toolchain.toml`).

## Workspace layout

| Crate | Role |
|---|---|
| `polaris-types` | Plain Rust domain types shared by backend and frontend. No ATProto dependency. |
| `polaris-backend` | Axum HTTP server, labeler XRPC endpoint, ingest workers, label signing. |
| `polaris-frontend` | Leptos WASM moderation dashboard. |
| `xtask` | Workspace automation (`cargo xtask <subcommand>`). |

## License

MIT — see [`LICENSE`](LICENSE).
