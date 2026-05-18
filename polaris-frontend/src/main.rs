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
    web_sys::console::log_1(&"polaris-frontend: main() running".into());
    leptos::mount::mount_to_body(App);
    web_sys::console::log_1(&"polaris-frontend: mount_to_body returned".into());

    // Diagnostic: dump what Leptos actually appended to <body>. mount_to_body
    // is synchronous wrt initial render in Leptos 0.8, so reading
    // document.body.innerHTML immediately after it returns should reflect the
    // mounted tree. If it shows "", Leptos kept ownership of the view but
    // never rendered it. If it shows markup, the markup is just invisible
    // (CSS, dimensions, off-screen).
    if let Some(doc) = web_sys::window().and_then(|w| w.document()) {
        if let Some(body) = doc.body() {
            let html = body.inner_html();
            let child_count = body.child_element_count();
            web_sys::console::log_1(
                &format!(
                    "polaris-frontend: body children={child_count} html_len={}",
                    html.len()
                )
                .into(),
            );
            web_sys::console::log_1(&format!("polaris-frontend: body.innerHTML={html}").into());
        } else {
            web_sys::console::log_1(&"polaris-frontend: document.body is None".into());
        }
    }
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
