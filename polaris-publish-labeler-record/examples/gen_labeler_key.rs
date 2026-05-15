//! Generate a fresh K-256 labeler signing keypair.
//!
//! Operator helper: run once to produce the secret + did:key pair for a
//! new Polaris labeler. Output shape:
//!
//! - line 1 stderr: the public `did:key:z...` (paste into
//!   `polaris-publish-labeler-record --signing-pubkey` and
//!   `polaris-publish-did-service --signing-key`).
//! - line 1 stdout: the 32-byte private key, hex-encoded. Redirect to a
//!   file and `chmod 600` immediately. This is the file path you point
//!   `[labeler.signing_key] mode = "file-plain"` at.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example gen_labeler_key -p polaris-publish-labeler-record \
//!     > /path/to/labeler.key
//! chmod 600 /path/to/labeler.key
//! ```
//!
//! The public did:key prints to stderr so a stdout-redirect captures only
//! the secret bytes without operator-instruction noise.

use std::fmt::Write as _;

use proto_blue::crypto::{ExportableKeypair as _, K256Keypair, Keypair as _};

fn main() {
    let kp = K256Keypair::generate();
    let secret_bytes = kp.export_private_key();
    // `write!` into a pre-sized `String` avoids the per-byte allocation that
    // `.map(|b| format!(...)).collect()` would produce (clippy::format_collect).
    let mut secret_hex = String::with_capacity(secret_bytes.len() * 2);
    for byte in &secret_bytes {
        // Writing into `String` is infallible; the expect documents the invariant.
        write!(&mut secret_hex, "{byte:02x}").expect("writing to a String never fails");
    }

    eprintln!("# public did:key (use as --signing-pubkey / --signing-key)");
    eprintln!("{}", kp.did());
    eprintln!();
    eprintln!("# secret (hex) follows on stdout — redirect to a 0o600 file");

    println!("{secret_hex}");
}
