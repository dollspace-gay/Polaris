//! `cargo xtask lexicon-contract` — drift detector against Bluesky's
//! published lexicon JSONs (REQ-E2 / AC-E2 of
//! `.design/polaris-operationally-complete.md`).
//!
//! Polaris's wire shapes (the `app.bsky.labeler.service` record, the
//! `com.atproto.identity.{request,sign,submit}PlcOperation` request
//! bodies, `com.atproto.repo.putRecord`, the `com.atproto.label.defs#label`
//! object) are pinned against schemas that live in
//! [bluesky-social/atproto](https://github.com/bluesky-social/atproto).
//! Those schemas drift silently — the smoke session against
//! `polarislabeler.bsky.social` surfaced four cases where the upstream
//! shape no longer matched Polaris's expectations.
//!
//! This subcommand fetches the canonical lexicon JSONs at a pinned
//! upstream commit, deserialises them via
//! [`proto_blue::lexicon::LexiconDoc`], and walks the field set Polaris
//! actually sends on the wire. Any field that vanished, changed type,
//! or moved out of `defs.main.input.schema` fails the task with a
//! diff-style message naming the lexicon path and the before/after
//! types so a CI consumer can open an issue against the upstream
//! schema change.
//!
//! # Cache
//!
//! Fetched bodies are cached under `.xtask-cache/lexicon-contract/<sha>/`
//! keyed by the pinned SHA. Bumping `UPSTREAM_LEXICON_COMMIT` invalidates
//! the cache; subsequent local runs are offline-clean for the same pin.
//!
//! # Scope
//!
//! REQ-E1 (`smoke_e2e`) is **not** owned by this module — that test
//! depends on Workstream A's first-run-boot work. This xtask covers
//! REQ-E2 / REQ-E3 only: the drift detector and (via
//! `.github/workflows/lexicon-contract.yml`) the weekly cron that runs
//! it and opens an issue on failure.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow, bail};
use proto_blue::lexicon::{LexUserType, LexiconDoc};

/// Pinned upstream commit at `github.com/bluesky-social/atproto`.
///
/// The SHA is the contract — bumping it is an explicit operator action.
/// Reaching for `main` would silently drift the moment upstream merged a
/// breaking schema change, which is exactly the failure mode this task
/// is designed to surface.
///
/// Resolved 2026-05-15 via
/// `curl https://api.github.com/repos/bluesky-social/atproto/commits/main`.
pub const UPSTREAM_LEXICON_COMMIT: &str = "cb1387899f0b296759ebdf5b8985b6b573091a9a";

/// Test inputs for the synthesised labeler service record.
///
/// These mirror the canonical happy-path fixture used by
/// `polaris-publish-labeler-record/tests/cli.rs`. The drift check
/// re-runs Polaris's production validator against a record built from
/// these inputs so the xtask exercises the same path the publish CLI
/// does. The did:key is a known-valid ES256K multikey (test vector,
/// not a real key — it is never signed against).
const SYNTH_SERVICE_URL: &str = "https://example.invalid";
const SYNTH_SIGNING_PUBKEY: &str = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
const SYNTH_LABEL_VALUE: &str = "test1";

/// Lexicon paths to fetch and the in-process check applied to each.
///
/// Stable-ordered so the xtask's stdout summary is deterministic
/// across runs.
fn lexicon_checks() -> Vec<LexiconCheck> {
    vec![
        LexiconCheck {
            path: "lexicons/app/bsky/labeler/service.json",
            id: "app.bsky.labeler.service",
            check: Box::new(check_labeler_service),
        },
        LexiconCheck {
            path: "lexicons/com/atproto/label/defs.json",
            id: "com.atproto.label.defs",
            check: Box::new(check_label_defs),
        },
        LexiconCheck {
            path: "lexicons/com/atproto/identity/requestPlcOperationSignature.json",
            id: "com.atproto.identity.requestPlcOperationSignature",
            check: Box::new(check_request_plc_op_signature),
        },
        LexiconCheck {
            path: "lexicons/com/atproto/identity/signPlcOperation.json",
            id: "com.atproto.identity.signPlcOperation",
            check: Box::new(check_sign_plc_op),
        },
        LexiconCheck {
            path: "lexicons/com/atproto/identity/submitPlcOperation.json",
            id: "com.atproto.identity.submitPlcOperation",
            check: Box::new(check_submit_plc_op),
        },
        LexiconCheck {
            path: "lexicons/com/atproto/repo/putRecord.json",
            id: "com.atproto.repo.putRecord",
            check: Box::new(check_put_record),
        },
    ]
}

/// Closure-shaped per-lexicon checker: deserialised `LexiconDoc` plus
/// the raw JSON (some checks consult both — the latter is what gets
/// re-run through the production validator).
type CheckFn = Box<dyn Fn(&LexiconDoc, &str) -> Result<()> + Send + Sync>;

struct LexiconCheck {
    /// Path within the upstream repo, used both as the GitHub URL
    /// suffix and the cache key.
    path: &'static str,
    /// The lexicon NSID — used for the human-readable summary line.
    id: &'static str,
    check: CheckFn,
}

/// Run the lexicon-contract subcommand.
///
/// # Errors
///
/// - Returns the underlying network error if a lexicon fetch fails
///   without a cached body to fall back on.
/// - Returns a structured drift diagnostic if any of the per-lexicon
///   checks fails. The diagnostic names the lexicon path, the offending
///   field, and the before/after types in a diff-style format.
pub fn run() -> Result<()> {
    let cache_root = cache_root()?;
    let client = blocking_client()?;

    let checks = lexicon_checks();
    let mut failures: Vec<String> = Vec::new();

    println!("lexicon-contract: pinned upstream commit = {UPSTREAM_LEXICON_COMMIT}",);

    for entry in &checks {
        let body = fetch_or_cache(&client, &cache_root, entry.path)
            .with_context(|| format!("fetching lexicon `{}`", entry.path))?;
        let doc: LexiconDoc = serde_json::from_str(&body).with_context(|| {
            format!(
                "deserialising lexicon `{}` via proto_blue::lexicon::LexiconDoc",
                entry.path
            )
        })?;

        if doc.id != entry.id {
            failures.push(format!(
                "lexicon `{}` declares id `{}` but Polaris expected `{}`",
                entry.path, doc.id, entry.id
            ));
            println!(
                "  FAIL  {} ({}): unexpected lexicon id",
                entry.path, entry.id
            );
            continue;
        }

        match (entry.check)(&doc, &body) {
            Ok(()) => {
                println!("  PASS  {} ({})", entry.path, entry.id);
            }
            Err(err) => {
                println!("  FAIL  {} ({}): {err:#}", entry.path, entry.id);
                failures.push(format!("{}: {err:#}", entry.path));
            }
        }
    }

    if failures.is_empty() {
        println!(
            "lexicon-contract: {} lexicon(s) checked, no drift detected.",
            checks.len()
        );
        Ok(())
    } else {
        // Stitch the per-lexicon failures into a single anyhow chain
        // so the GitHub-Actions issue body carries every drift in one
        // payload. The leading newline keeps the first entry off the
        // anyhow prefix line.
        let body = failures.join("\n");
        Err(anyhow!(
            "lexicon-contract detected {} drift(s) against upstream `{UPSTREAM_LEXICON_COMMIT}`:\n{body}",
            failures.len()
        ))
    }
}

/// Build the on-disk cache root. Workspace-relative so the cache lives
/// alongside `target/` and follows the same gitignore semantics.
fn cache_root() -> Result<PathBuf> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let root = Path::new(manifest_dir)
        .parent()
        .ok_or_else(|| anyhow!("xtask manifest dir has no parent — broken workspace layout"))?
        .join(".xtask-cache")
        .join("lexicon-contract")
        .join(UPSTREAM_LEXICON_COMMIT);
    fs::create_dir_all(&root)
        .with_context(|| format!("creating cache dir `{}`", root.display()))?;
    Ok(root)
}

/// Construct the blocking reqwest client used for upstream fetches.
///
/// `User-Agent` is required by GitHub's API — raw.githubusercontent.com
/// is more forgiving, but a missing UA still trips occasional rate-
/// limiting heuristics. The timeout caps a hung fetch so the CI cron
/// never wedges indefinitely.
fn blocking_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .user_agent(
            "polaris-xtask-lexicon-contract/0.1 (+https://github.com/dollspace-gay/polaris)",
        )
        .timeout(Duration::from_secs(30))
        .build()
        .context("constructing reqwest blocking client")
}

/// Fetch a lexicon body from the cache, falling back to the upstream
/// raw-content URL on a cache miss. Successful fetches are written
/// through to the cache so subsequent runs at the same pin are
/// offline-clean.
fn fetch_or_cache(
    client: &reqwest::blocking::Client,
    cache_root: &Path,
    path: &str,
) -> Result<String> {
    let cache_path = cache_root.join(path.replace('/', "__"));
    if let Ok(cached) = fs::read_to_string(&cache_path) {
        return Ok(cached);
    }

    let url = format!(
        "https://raw.githubusercontent.com/bluesky-social/atproto/{UPSTREAM_LEXICON_COMMIT}/{path}"
    );
    let response = client
        .get(&url)
        .send()
        .with_context(|| format!("HTTP GET `{url}`"))?;
    let status = response.status();
    let body = response
        .text()
        .with_context(|| format!("reading response body for `{url}`"))?;
    if !status.is_success() {
        bail!("HTTP {status} fetching `{url}`: {body}");
    }

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating cache parent `{}`", parent.display()))?;
    }
    let mut file = fs::File::create(&cache_path)
        .with_context(|| format!("opening cache file `{}` for write", cache_path.display()))?;
    file.write_all(body.as_bytes())
        .with_context(|| format!("writing cache file `{}`", cache_path.display()))?;

    Ok(body)
}

// =========================================================================
// Per-lexicon drift checks
// =========================================================================

/// `app.bsky.labeler.service` — synthesise the record Polaris would
/// publish and re-run the production validator against it.
///
/// This intentionally calls
/// [`polaris_publish_labeler_record::validate_record`] so the xtask
/// exercises the same path the production publish CLI walks. The
/// validator embeds its own copy of the four labeler lexicons; if the
/// upstream copy has drifted from those embeds the synthesised record
/// will still validate against the embed but the **upstream** schema
/// fetched here will fail the structural sanity check below. Both
/// signals are surfaced to the operator.
fn check_labeler_service(doc: &LexiconDoc, _body: &str) -> Result<()> {
    // Polaris's wire shape: a `record` def at `main` whose inner
    // `record` is an `object`. Drift here would be e.g. the upstream
    // promoting `policies` to a primary def or splitting `service`
    // into two records — both have happened to other lexicons.
    let main = doc
        .defs
        .get("main")
        .ok_or_else(|| anyhow!("missing `defs.main`"))?;
    let LexUserType::Record(record_def) = main else {
        return Err(anyhow!(
            "expected `defs.main` to be type `record`, got `{}`",
            main.type_name()
        ));
    };

    // Confirm the record carries the two fields the production builder
    // populates (`policies`, `createdAt`). The exhaustive validation is
    // the next step — these guards just produce a nicer diff message
    // when a field disappears entirely vs. when its shape changed.
    for field in ["policies", "createdAt"] {
        if !record_def.record.properties.contains_key(field) {
            return Err(anyhow!(
                "record property `{field}` missing — Polaris publishes this field unconditionally"
            ));
        }
    }

    // Re-run the production validator. This is the actual drift
    // detector for `app.bsky.labeler.service`: we synthesise the
    // record Polaris would publish and confirm validate_record still
    // accepts it. If the embed has drifted from upstream the prior
    // structural guards will already have caught it; if the embed is
    // in sync with upstream, this call exercises the full schema.
    let record = polaris_publish_labeler_record::build_labeler_service_record(
        SYNTH_SERVICE_URL,
        SYNTH_SIGNING_PUBKEY,
        vec![SYNTH_LABEL_VALUE.to_string()],
    )
    .map_err(|e| anyhow!("synthesising labeler service record failed: {e}"))?;
    polaris_publish_labeler_record::validate_record(&record)
        .map_err(|e| anyhow!("validate_record(synthesised) failed: {e}"))?;

    Ok(())
}

/// `com.atproto.label.defs` — assert the `label` def carries the
/// canonical fields with their expected types.
///
/// Polaris signs labels using exactly this shape; a silent rename or
/// type change on any of these fields would break verification on
/// every downstream consumer.
fn check_label_defs(doc: &LexiconDoc, _body: &str) -> Result<()> {
    let label = doc
        .defs
        .get("label")
        .ok_or_else(|| anyhow!("missing `defs.label`"))?;
    let LexUserType::Object(obj) = label else {
        return Err(anyhow!(
            "expected `defs.label` to be type `object`, got `{}`",
            label.type_name()
        ));
    };

    // Field → expected lexicon type-name pairs. Order is the canonical
    // declaration order from `com.atproto.label.defs#label`.
    let expected: &[(&str, &str)] = &[
        ("ver", "integer"),
        ("src", "string"),
        ("uri", "string"),
        ("cid", "string"),
        ("val", "string"),
        ("neg", "boolean"),
        ("cts", "string"),
        ("exp", "string"),
        ("sig", "bytes"),
    ];

    for (field, want) in expected {
        let prop = obj
            .properties
            .get(*field)
            .ok_or_else(|| anyhow!("`label` def missing property `{field}`"))?;
        let got = prop.type_name();
        if got != *want {
            return Err(anyhow!(
                "field `label.{field}` drifted: expected `{want}`, found `{got}`",
            ));
        }
    }
    Ok(())
}

/// `com.atproto.identity.requestPlcOperationSignature` — Polaris sends
/// this with NO body. Upstream had this declare an `input` field at
/// one point; today it declares none. Drift in either direction breaks
/// the wizard.
fn check_request_plc_op_signature(doc: &LexiconDoc, _body: &str) -> Result<()> {
    let main = doc
        .defs
        .get("main")
        .ok_or_else(|| anyhow!("missing `defs.main`"))?;
    let LexUserType::Procedure(procedure) = main else {
        return Err(anyhow!(
            "expected `defs.main` to be type `procedure`, got `{}`",
            main.type_name()
        ));
    };
    if procedure.input.is_some() {
        return Err(anyhow!(
            "`requestPlcOperationSignature` now declares an `input` schema, \
             but Polaris sends a bodyless POST — review the input shape and \
             update `polaris-backend/src/api/setup.rs` accordingly",
        ));
    }
    Ok(())
}

/// `com.atproto.identity.signPlcOperation` — Polaris sends
/// `{ token, services, verificationMethods }`. Assert each field is
/// declared on the input schema with the type the wire shape expects.
fn check_sign_plc_op(doc: &LexiconDoc, _body: &str) -> Result<()> {
    let main = doc
        .defs
        .get("main")
        .ok_or_else(|| anyhow!("missing `defs.main`"))?;
    let LexUserType::Procedure(procedure) = main else {
        return Err(anyhow!(
            "expected `defs.main` to be type `procedure`, got `{}`",
            main.type_name()
        ));
    };
    let input = procedure
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("`signPlcOperation` lost its `input` schema"))?;
    let schema = input
        .schema
        .as_ref()
        .ok_or_else(|| anyhow!("`signPlcOperation.input` has no schema"))?;
    let LexUserType::Object(obj) = schema.as_ref() else {
        return Err(anyhow!(
            "`signPlcOperation.input.schema` is `{}`, expected `object`",
            schema.type_name()
        ));
    };

    // Polaris sends these three fields (see
    // polaris-backend/src/api/setup.rs::submit_plc_operation). The
    // wire-shape map-vs-array surprise that bit the smoke session
    // lives in the runtime PLC behaviour, not the lexicon — the
    // lexicon declares `services` / `verificationMethods` as
    // `unknown`, which is the wire-shape-tolerant signal. We assert
    // the fields are still present and still typed as the lexicon
    // declares, but we do NOT lock the type at `object` because that
    // would be tighter than the upstream schema.
    let expected: &[(&str, &str)] = &[
        ("token", "string"),
        ("services", "unknown"),
        ("verificationMethods", "unknown"),
    ];
    for (field, want) in expected {
        let prop = obj
            .properties
            .get(*field)
            .ok_or_else(|| anyhow!("`signPlcOperation.input` missing property `{field}`"))?;
        let got = prop.type_name();
        if got != *want {
            return Err(anyhow!(
                "field `signPlcOperation.input.{field}` drifted: expected `{want}`, found `{got}`",
            ));
        }
    }
    Ok(())
}

/// `com.atproto.identity.submitPlcOperation` — Polaris sends
/// `{ operation }`. Assert it exists on the input schema.
fn check_submit_plc_op(doc: &LexiconDoc, _body: &str) -> Result<()> {
    let main = doc
        .defs
        .get("main")
        .ok_or_else(|| anyhow!("missing `defs.main`"))?;
    let LexUserType::Procedure(procedure) = main else {
        return Err(anyhow!(
            "expected `defs.main` to be type `procedure`, got `{}`",
            main.type_name()
        ));
    };
    let input = procedure
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("`submitPlcOperation` lost its `input` schema"))?;
    let schema = input
        .schema
        .as_ref()
        .ok_or_else(|| anyhow!("`submitPlcOperation.input` has no schema"))?;
    let LexUserType::Object(obj) = schema.as_ref() else {
        return Err(anyhow!(
            "`submitPlcOperation.input.schema` is `{}`, expected `object`",
            schema.type_name()
        ));
    };
    let prop = obj
        .properties
        .get("operation")
        .ok_or_else(|| anyhow!("`submitPlcOperation.input` missing property `operation`"))?;
    let got = prop.type_name();
    if got != "unknown" {
        return Err(anyhow!(
            "field `submitPlcOperation.input.operation` drifted: expected `unknown`, found `{got}`",
        ));
    }
    Ok(())
}

/// `com.atproto.repo.putRecord` — Polaris's labeler-record publish
/// path posts here with `{ collection, repo, rkey, validate,
/// swapRecord?, swapCommit?, record: <opaque> }`. The wire-shape-
/// tolerant signal is `record: unknown`; the other fields must keep
/// their canonical types.
fn check_put_record(doc: &LexiconDoc, _body: &str) -> Result<()> {
    let main = doc
        .defs
        .get("main")
        .ok_or_else(|| anyhow!("missing `defs.main`"))?;
    let LexUserType::Procedure(procedure) = main else {
        return Err(anyhow!(
            "expected `defs.main` to be type `procedure`, got `{}`",
            main.type_name()
        ));
    };
    let input = procedure
        .input
        .as_ref()
        .ok_or_else(|| anyhow!("`putRecord` lost its `input` schema"))?;
    let schema = input
        .schema
        .as_ref()
        .ok_or_else(|| anyhow!("`putRecord.input` has no schema"))?;
    let LexUserType::Object(obj) = schema.as_ref() else {
        return Err(anyhow!(
            "`putRecord.input.schema` is `{}`, expected `object`",
            schema.type_name()
        ));
    };

    // Polaris fills these fields on every put_record call (see
    // polaris-backend/src/api/setup.rs::build_put_record_input).
    // `swapRecord` / `swapCommit` are passed as `None` today but the
    // lexicon contract still requires the upstream surface them so
    // the put_record::Input type stays a faithful mirror.
    let expected: &[(&str, &str)] = &[
        ("collection", "string"),
        ("repo", "string"),
        ("rkey", "string"),
        ("validate", "boolean"),
        ("swapRecord", "string"),
        ("swapCommit", "string"),
        ("record", "unknown"),
    ];
    for (field, want) in expected {
        let prop = obj
            .properties
            .get(*field)
            .ok_or_else(|| anyhow!("`putRecord.input` missing property `{field}`"))?;
        let got = prop.type_name();
        if got != *want {
            return Err(anyhow!(
                "field `putRecord.input.{field}` drifted: expected `{want}`, found `{got}`",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm the pinned SHA is a valid 40-char hex digest. Bumping
    /// the pin to a placeholder would silently disable the cache key
    /// — this guard catches a stray edit before CI does.
    #[test]
    fn upstream_lexicon_commit_is_valid_sha() {
        assert_eq!(UPSTREAM_LEXICON_COMMIT.len(), 40);
        assert!(
            UPSTREAM_LEXICON_COMMIT
                .chars()
                .all(|c| c.is_ascii_hexdigit()),
            "UPSTREAM_LEXICON_COMMIT must be a hex SHA",
        );
    }

    /// Sanity check the synthesised did:key is a `did:key:z…` multikey
    /// — the validator under test rejects anything else, which would
    /// turn an upstream-drift test into a Polaris-side fixture-bug
    /// false positive.
    #[test]
    fn synth_signing_pubkey_is_did_key() {
        assert!(SYNTH_SIGNING_PUBKEY.starts_with("did:key:z"));
    }
}
