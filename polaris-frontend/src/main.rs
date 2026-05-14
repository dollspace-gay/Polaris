//! Polaris frontend wasm entry point.
//!
//! Trunk compiles this binary as the wasm bundle for the browser. The
//! same binary builds for native targets too (as a no-op stub) so
//! `cargo build --workspace` works without a wasm toolchain.

#[cfg(target_arch = "wasm32")]
use polaris_frontend::App;

/// Browser entry point.
///
/// Installs `console_error_panic_hook` so any panic from Rust code
/// surfaces in the browser console with a useful stack trace, then
/// mounts the root [`App`] component onto `<body>`.
#[cfg(target_arch = "wasm32")]
fn main() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(App);
}

/// Native stub.
///
/// The real entry point is the wasm bundle served by Trunk. Native
/// builds of this binary exist so workspace tooling (`cargo build`,
/// `cargo check`, IDE rust-analyzer) compiles the whole tree on the
/// host toolchain without requiring `wasm32-unknown-unknown`. Exiting
/// non-zero on accidental invocation surfaces the misuse loudly
/// instead of silently hanging.
#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    eprintln!("polaris-frontend is a WASM-only binary; build with `trunk serve` or `trunk build`.");
    std::process::ExitCode::from(2)
}
