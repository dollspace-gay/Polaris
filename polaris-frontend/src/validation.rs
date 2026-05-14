//! Client-side validation against ATProto lexicons (REQ-13 / AC-16).
//!
//! Builds a minimal [`Lexicons`] registry from the four lexicon JSON
//! documents embedded at build time and exposes two typed entry points
//! the action composer (and any future moderator-authoring surface) can
//! call:
//!
//! - [`validate_label_def`] — validate a `com.atproto.label.defs#label`
//!   record value.
//! - [`validate_labeler_service`] — validate an
//!   `app.bsky.labeler.service` record value (`$type = "main"`).
//!
//! The registry is built once at app start via [`build_registry`] and
//! shared through Leptos context (`StoredValue<Arc<Lexicons>>`). The
//! composer's debounced effect calls one of the `validate_*` entry
//! points with the in-progress record as JSON; errors render inline.
//!
//! # Why this exists
//!
//! `.design/polaris-proto-blue-integration.md` REQ-13 / AC-16: every
//! moderator-authored record must be lexicon-validated client-side
//! before submission, with zero HTTP round-trips for the validation
//! itself. The validation engine is `proto-blue-lexicon`, reached
//! through the `proto-blue` umbrella crate's re-exports
//! ([`proto_blue::lexicon`]) so we don't pull a second copy of the
//! same dependency into the wasm bundle.
//!
//! # Cargo / bundle hygiene
//!
//! The frontend depends on `proto-blue` (the umbrella) directly; the
//! lexicon engine is reached through `proto_blue::lexicon` so a single
//! lockfile version of `proto-blue-lexicon` ends up in the wasm bundle.
//! See `xtask/src/check_wasm_symbols.rs` for the bundle-time assertion
//! that the engine actually survived dead-code elimination.

use std::collections::BTreeMap;
use std::sync::Arc;

use proto_blue::lex_data::LexValue;
use proto_blue::lex_json::json_to_lex;
use proto_blue::lexicon::{LexUserType, Lexicons};

/// `$type` of an `app.bsky.labeler.service` record (always `main`).
pub const LABELER_SERVICE_NSID: &str = "app.bsky.labeler.service";

/// `$type` of a `com.atproto.label.defs#label` record value.
///
/// The label-defs document declares `label` as an object definition
/// (not a top-level record), so the URI carries the `#label` fragment.
/// Lookups against the registry resolve relative refs to absolute URIs
/// when the document is loaded, so this string is the form
/// [`Lexicons::get_def`] expects.
pub const LABEL_DEF_URI: &str = "com.atproto.label.defs#label";

/// JSON sources of the four lexicon documents the v1 composer surface
/// can author records against.
///
/// Embedded at compile time via `include_str!` so the validator is
/// offline-clean — no runtime file IO and no HTTP fetch. The files are
/// vendored from `proto-blue`'s `lexicons/` tree (same set as
/// `polaris-publish-labeler-record/lexicons/`); refreshing them is a
/// manual drop-in alongside a `proto-blue` major-version bump.
const EMBEDDED_LEXICONS: &[(&str, &str)] = &[
    (
        "com.atproto.moderation.defs",
        include_str!("../lexicons/com/atproto/moderation/defs.json"),
    ),
    (
        "com.atproto.label.defs",
        include_str!("../lexicons/com/atproto/label/defs.json"),
    ),
    (
        "app.bsky.labeler.defs",
        include_str!("../lexicons/app/bsky/labeler/defs.json"),
    ),
    (
        LABELER_SERVICE_NSID,
        include_str!("../lexicons/app/bsky/labeler/service.json"),
    ),
];

/// Errors that [`build_registry`] can return.
///
/// All variants are programmer-visible: a failure here would mean the
/// embedded JSON was corrupted at build time. We surface the cause
/// (rather than panicking) so a downstream operator running the
/// validator in an unexpected environment can see exactly which lexicon
/// failed to parse.
#[derive(Debug, thiserror::Error)]
pub enum ValidationInitError {
    /// One of the embedded lexicon JSON documents failed to parse or
    /// register against the [`Lexicons`] engine.
    #[error("failed to load embedded lexicon `{nsid}`: {source}")]
    Parse {
        /// NSID of the lexicon document being loaded when the failure
        /// fired.
        nsid: &'static str,
        /// Underlying error from the lexicon registry.
        #[source]
        source: proto_blue::lexicon::LexiconError,
    },
}

/// Errors that the per-record validators ([`validate_label_def`],
/// [`validate_labeler_service`]) can return.
///
/// `Schema` wraps the typed [`proto_blue::lexicon::ValidationError`] so
/// the composer can match on the discriminator (currently
/// `InvalidValue { path, message }` for property-level failures vs.
/// `LexiconNotFound` / `DefNotFound` for programmer-visible setup
/// errors). The `Display` impl forwards to the inner error so simple
/// inline rendering works without a custom formatter.
#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    /// The composer's JSON failed to round-trip into a [`LexValue`].
    ///
    /// In practice this is unreachable from the composer because the
    /// composer always builds a `serde_json::Value` from typed signal
    /// state, but the conversion routine returns `Result`; surfacing
    /// the variant keeps the boundary explicit.
    #[error("failed to convert JSON to LexValue: {0}")]
    JsonConversion(String),

    /// The expected lexicon definition was not registered in the
    /// engine. This is a programmer invariant — it should never fire
    /// against a `Lexicons` built by [`build_registry`].
    #[error("lexicon definition `{0}` missing from registry")]
    DefinitionMissing(&'static str),

    /// The lexicon definition is registered, but is not the expected
    /// shape (e.g. we asked for a record def and got an object def).
    /// Programmer invariant; would indicate the embedded JSON drifted
    /// from the validators expect.
    #[error("lexicon definition `{0}` is not of the expected kind")]
    DefinitionWrongKind(&'static str),

    /// The record did not validate against its schema. The path string
    /// inside the typed variant points at the offending field, e.g.
    /// `record/val` for a missing required `val` property on a label
    /// record.
    #[error("schema validation failed: {0}")]
    Schema(#[from] proto_blue::lexicon::ValidationError),
}

/// Build a fresh [`Lexicons`] registry containing the four schemas the
/// v1 composer surface requires.
///
/// Call once at app start (see `app.rs`) and share the result through
/// a `StoredValue<Arc<Lexicons>>` Leptos context entry. Re-constructing
/// the registry on every composer mount is wasteful and would break the
/// AC-16 100ms validation budget on lower-end devices.
///
/// # Errors
///
/// Returns [`ValidationInitError`] if any of the embedded lexicon
/// documents fails to parse. In practice this is unreachable for the
/// vendored documents; the variant exists so corruption of the build
/// artifact is surfaced loudly rather than panicked on.
pub fn build_registry() -> Result<Lexicons, ValidationInitError> {
    let mut registry = Lexicons::new();
    for (nsid, body) in EMBEDDED_LEXICONS {
        registry
            .add_from_json(body)
            .map_err(|source| ValidationInitError::Parse { nsid, source })?;
    }
    Ok(registry)
}

/// Convenience: [`build_registry`] wrapped in an [`Arc`] for sharing
/// through Leptos context without further allocation at consumer sites.
///
/// # Errors
///
/// Forwards [`ValidationInitError`] from [`build_registry`].
pub fn build_shared_registry() -> Result<Arc<Lexicons>, ValidationInitError> {
    build_registry().map(Arc::new)
}

/// Validate a `com.atproto.label.defs#label` value against its schema.
///
/// The composer constructs an in-progress label as a `serde_json::Value`
/// (typed signal state -> `serde_json::json!`), passes it here, and
/// renders any returned error inline.
///
/// # Errors
///
/// - [`ValidationError::DefinitionMissing`] if the registry was not
///   built via [`build_registry`] (programmer invariant).
/// - [`ValidationError::DefinitionWrongKind`] if the registered
///   definition is not an object (programmer invariant; vendored JSON
///   would have to have drifted).
/// - [`ValidationError::Schema`] if the value does not match the
///   `label` object schema — this is the variant the composer surfaces
///   inline to the moderator.
pub fn validate_label_def(
    registry: &Lexicons,
    json: &serde_json::Value,
) -> Result<(), ValidationError> {
    let def = registry
        .get_def(LABEL_DEF_URI)
        .ok_or(ValidationError::DefinitionMissing(LABEL_DEF_URI))?;
    let LexUserType::Object(obj) = def else {
        return Err(ValidationError::DefinitionWrongKind(LABEL_DEF_URI));
    };

    let lex = json_to_lex(json);
    let map = lex_as_map(&lex).ok_or_else(|| {
        ValidationError::JsonConversion("label value must be a JSON object".to_owned())
    })?;

    proto_blue::lexicon::validate_object(registry, "record", obj, map).map_err(Into::into)
}

/// Validate an `app.bsky.labeler.service` record value against its
/// `record` schema.
///
/// # Errors
///
/// Same variant set as [`validate_label_def`]; see that function's
/// docs for the per-variant semantics.
pub fn validate_labeler_service(
    registry: &Lexicons,
    json: &serde_json::Value,
) -> Result<(), ValidationError> {
    let def = registry
        .get_def(LABELER_SERVICE_NSID)
        .ok_or(ValidationError::DefinitionMissing(LABELER_SERVICE_NSID))?;
    let LexUserType::Record(record_def) = def else {
        return Err(ValidationError::DefinitionWrongKind(LABELER_SERVICE_NSID));
    };

    let lex = json_to_lex(json);
    proto_blue::lexicon::validate_record(registry, record_def, &lex).map_err(Into::into)
}

/// Borrow the inner map of a [`LexValue::Map`] without leaking
/// `proto_blue_lex_data` from the public surface of this module. The
/// proto-blue 0.3 line uses `LexValue::Map(BTreeMap<String, LexValue>)`;
/// pulling the borrow into one place means a future API change in
/// `proto-blue` is a one-line edit here.
fn lex_as_map(value: &LexValue) -> Option<&BTreeMap<String, LexValue>> {
    match value {
        LexValue::Map(m) => Some(m),
        _ => None,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code is allowed to panic — rust-quality §7 convention"
)]
mod tests {
    use super::*;
    use serde_json::json;

    fn registry() -> Lexicons {
        build_registry().expect("embedded lexicons must parse")
    }

    #[test]
    fn build_registry_loads_all_four_documents() {
        let r = registry();
        // Each NSID registers its own doc plus one `lex:<nsid>` alias
        // when a `main` def is present. We only assert on doc count
        // because the def-count surface is the engine's internal
        // accounting, not part of our contract.
        assert_eq!(r.doc_count(), 4);
        assert!(r.get("com.atproto.label.defs").is_some());
        assert!(r.get("com.atproto.moderation.defs").is_some());
        assert!(r.get("app.bsky.labeler.defs").is_some());
        assert!(r.get(LABELER_SERVICE_NSID).is_some());
    }

    #[test]
    fn label_def_uri_resolvable() {
        // The composer's hot path looks up the label-object definition
        // every keystroke (per debounce window); the lookup must not
        // be string-mangling — assert directly that the URI we use
        // resolves to a non-empty definition of the expected kind.
        let r = registry();
        let def = r
            .get_def(LABEL_DEF_URI)
            .expect("label def URI must resolve");
        assert!(matches!(def, LexUserType::Object(_)));
    }

    #[test]
    fn valid_label_passes() {
        let r = registry();
        let value = json!({
            "src": "did:plc:example",
            "uri": "at://did:plc:example/app.bsky.feed.post/abc123",
            "val": "spam",
            "cts": "2026-05-14T00:00:00.000Z",
        });
        validate_label_def(&r, &value).expect("valid label must validate clean");
    }

    #[test]
    fn label_missing_required_val_rejected() {
        let r = registry();
        let value = json!({
            "src": "did:plc:example",
            "uri": "at://did:plc:example/app.bsky.feed.post/abc123",
            "cts": "2026-05-14T00:00:00.000Z",
            // `val` deliberately missing — it is required by the lexicon.
        });
        let err = validate_label_def(&r, &value).expect_err("must reject missing `val`");
        match err {
            ValidationError::Schema(proto_blue::lexicon::ValidationError::InvalidValue {
                path,
                message,
            }) => {
                assert!(
                    path.contains("val"),
                    "error path should name `val`, got `{path}`",
                );
                assert!(
                    message.to_lowercase().contains("required") || message.contains("val"),
                    "error message should explain the missing field, got `{message}`",
                );
            }
            other => panic!("expected Schema(InvalidValue), got {other:?}"),
        }
    }

    #[test]
    fn label_wrong_type_on_val_rejected() {
        let r = registry();
        let value = json!({
            "src": "did:plc:example",
            "uri": "at://did:plc:example/app.bsky.feed.post/abc123",
            "val": 42,
            "cts": "2026-05-14T00:00:00.000Z",
        });
        let err = validate_label_def(&r, &value).expect_err("non-string `val` must reject");
        // Path should pin the offending property; we don't pin the
        // exact message since it's the lexicon engine's text, but the
        // discriminator must be `InvalidValue`.
        assert!(matches!(
            err,
            ValidationError::Schema(proto_blue::lexicon::ValidationError::InvalidValue { .. })
        ));
    }

    #[test]
    fn labeler_service_valid_record() {
        let r = registry();
        let value = json!({
            "$type": LABELER_SERVICE_NSID,
            "policies": {
                "labelValues": ["spam", "!hide"],
            },
            "createdAt": "2026-05-14T00:00:00.000Z",
        });
        validate_labeler_service(&r, &value)
            .expect("minimum valid labeler-service record must validate clean");
    }

    #[test]
    fn labeler_service_missing_policies_rejected() {
        let r = registry();
        let value = json!({
            "$type": LABELER_SERVICE_NSID,
            "createdAt": "2026-05-14T00:00:00.000Z",
            // `policies` deliberately missing — required by the lexicon.
        });
        let err = validate_labeler_service(&r, &value).expect_err("missing `policies` must reject");
        match err {
            ValidationError::Schema(proto_blue::lexicon::ValidationError::InvalidValue {
                path,
                ..
            }) => {
                assert!(
                    path.contains("policies"),
                    "error path should name `policies`, got `{path}`",
                );
            }
            other => panic!("expected Schema(InvalidValue), got {other:?}"),
        }
    }

    #[test]
    fn shared_registry_arcable() {
        // The composer wires the registry through a
        // `StoredValue<Arc<Lexicons>>`; assert that the builder hands
        // back an Arc-wrapped registry with the same shape.
        let a = build_shared_registry().expect("shared registry must build");
        assert_eq!(a.doc_count(), 4);
    }
}

/// Source-only headless wasm test scaffolding (#34g).
///
/// AC-16 names "headless-browser `wasm-bindgen-test`" as the verification
/// mechanism. The sandbox running this dispatch does not necessarily have
/// chromedriver/geckodriver, so the execution is gated behind the
/// crate-level `wasm-tests` cargo feature — CI runs the suite as a
/// separate job (see `.github/workflows/ci.yml`). The source ships so
/// the contract is auditable from `cargo doc` and so a developer running
/// `wasm-pack test --headless --chrome` locally exercises the same path
/// the CI job does.
#[cfg(all(target_arch = "wasm32", feature = "wasm-tests"))]
mod wasm_tests {
    use super::*;
    use serde_json::json;
    use wasm_bindgen_test::wasm_bindgen_test;

    wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn registry_builds_in_browser() {
        let r = build_registry().expect("registry must build in wasm");
        assert!(r.get_def(LABEL_DEF_URI).is_some());
    }

    #[wasm_bindgen_test]
    fn label_validation_runs_in_browser() {
        let r = build_registry().expect("registry must build in wasm");
        let bad = json!({
            "src": "did:plc:example",
            "uri": "at://did:plc:example/app.bsky.feed.post/abc123",
            "cts": "2026-05-14T00:00:00.000Z",
        });
        let err = validate_label_def(&r, &bad).expect_err("missing val rejected");
        // Discriminator check is enough — string content is asserted in
        // the native suite which runs as part of every `cargo test`.
        assert!(matches!(
            err,
            ValidationError::Schema(proto_blue::lexicon::ValidationError::InvalidValue { .. })
        ));
    }
}
