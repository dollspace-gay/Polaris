//! Library half of `polaris-publish-labeler-record` (issue #27).
//!
//! Pure, testable functions for constructing and validating an
//! `app.bsky.labeler.service` record. The CLI / authentication / network
//! glue lives in `main.rs`; this module is deliberately I/O-free so the
//! happy path is unit-testable without a PDS or a Bluesky account.
//!
//! # Design notes
//!
//! - **Generated lexicon type, not hand-rolled JSON.** The record is built
//!   via [`proto_blue_api::generated::app::bsky::labeler::service::Main`],
//!   matching REQ-2 / AC-2 of `.design/polaris-proto-blue-integration.md`.
//! - **Lexicon-level validation.** Before submission the record is
//!   serialized to JSON, converted into a `LexValue`, and validated against
//!   a [`Lexicons`] registry seeded with the four schemas the record
//!   transitively references: `app.bsky.labeler.service`,
//!   `app.bsky.labeler.defs`, `com.atproto.label.defs`,
//!   `com.atproto.moderation.defs`.
//! - **Service URL + did:key are call-site inputs, not record fields.**
//!   The `app.bsky.labeler.service` lexicon does NOT carry the labeler's
//!   public hostname or signing key directly — those are declared on the
//!   operator's DID document as a `#atproto_labeler` service entry. The
//!   record itself describes the labeler's policies (the set of label
//!   values it emits). [`build_labeler_service_record`] still parses and
//!   validates the URL + did:key inputs so the caller can surface bad
//!   flags early; the values are echoed back to the operator in the
//!   dry-run output for cross-checking against the DID document.
//!
//! [`Lexicons`]: proto_blue::lexicon::Lexicons

use proto_blue::api::app::bsky::labeler::service as labeler_service;
use proto_blue::lex_json::json_to_lex;
use proto_blue::lexicon::{LexUserType, Lexicons};
use proto_blue::syntax::Datetime;
use thiserror::Error;

/// `$type` discriminator for the labeler service record.
pub const RECORD_TYPE: &str = "app.bsky.labeler.service";

/// Record key the labeler service record is always written at
/// (`literal:self` per the lexicon).
pub const RECORD_RKEY: &str = "self";

/// NSID collection the labeler service record lives in.
pub const RECORD_COLLECTION: &str = "app.bsky.labeler.service";

/// JSON sources of the lexicon documents required to validate an
/// `app.bsky.labeler.service` record.
///
/// Embedded at build time so the validator is offline-clean — no
/// runtime file IO. The four files are copied verbatim from
/// `proto-blue`'s `lexicons/` directory; refreshing them is a manual
/// drop-in alongside a `proto-blue` major-version bump.
const LEXICON_LABELER_SERVICE: &str = include_str!("../lexicons/app/bsky/labeler/service.json");
const LEXICON_LABELER_DEFS: &str = include_str!("../lexicons/app/bsky/labeler/defs.json");
const LEXICON_LABEL_DEFS: &str = include_str!("../lexicons/com/atproto/label/defs.json");
const LEXICON_MODERATION_DEFS: &str = include_str!("../lexicons/com/atproto/moderation/defs.json");

/// A constructed (but not-yet-signed-or-submitted)
/// `app.bsky.labeler.service` record.
///
/// Newtype wrapper around the generated lexicon type so the public
/// surface of this crate does not leak `proto_blue_api`'s internal
/// module path into downstream call sites and so the constructor's
/// invariants (validated inputs, RFC-3339 timestamp) stay enforced.
#[derive(Debug, Clone)]
pub struct RecordValue {
    inner: labeler_service::Main,
}

impl RecordValue {
    /// Borrow the underlying generated record.
    #[must_use]
    pub const fn as_main(&self) -> &labeler_service::Main {
        &self.inner
    }

    /// Consume this wrapper and return the generated record.
    #[must_use]
    pub fn into_main(self) -> labeler_service::Main {
        self.inner
    }

    /// Serialize the record to `serde_json::Value`.
    ///
    /// This is the wire shape used by `com.atproto.repo.putRecord`'s
    /// `record` field.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`serde_json::Error`] when the generated
    /// record's `Serialize` impl unexpectedly fails. In practice this is
    /// impossible because every field of `Main` is itself plain JSON, but
    /// the error is surfaced rather than panicked on for the same reason
    /// every other library-side fallible op is — to keep `unwrap_used`
    /// off the implementation.
    pub fn to_json(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(&self.inner)
    }
}

/// Errors that [`build_labeler_service_record`] can return.
///
/// Failures are exclusively driven by the caller's CLI input — there is
/// no IO in `build_*`, so every variant maps onto exit code 1
/// (user error) in `main.rs`.
#[derive(Debug, Error)]
pub enum BuildError {
    /// `--signing-pubkey` was not a parseable `did:key:z…` multikey.
    #[error("invalid did:key for --signing-pubkey: {0}")]
    InvalidDidKey(String),

    /// `--signing-pubkey` parsed but did not name a K-256 / P-256 curve.
    ///
    /// Polaris signs labels with K-256 (REQ-3); declaring any other curve
    /// in the service record would create a verifier mismatch on the
    /// downstream consumer side. We accept either P-256 or K-256 because
    /// the broader ATProto ecosystem accepts both, but reject anything
    /// else loudly here rather than at signature-verification time on a
    /// consumer.
    #[error("unsupported did:key curve: {0}")]
    UnsupportedDidKeyCurve(String),

    /// `--service-url` failed URL parsing.
    #[error("invalid --service-url: {0}")]
    InvalidServiceUrl(String),

    /// `--service-url` parsed but was not an HTTPS URL.
    ///
    /// Downstream consumers connect over WebSocket Secure to the labeler
    /// endpoint; a plaintext URL here would silently degrade to a
    /// no-TLS connection at deploy time.
    #[error("--service-url must use https:// scheme, got: {0}")]
    NonHttpsServiceUrl(String),

    /// `label_values` was empty.
    ///
    /// A labeler service that declares no label values is meaningless —
    /// the lexicon does not require this, but Polaris does, because a
    /// downstream AppView matches consumer settings against the
    /// declared value set.
    #[error("label_values must be non-empty")]
    EmptyLabelValues,

    /// `labelValueDefinitions` is not 1:1 with `label_values`. Either
    /// some values have no matching definition (`missing`) or some
    /// definitions reference a value the labeler doesn't claim
    /// (`extra`). Surfaced eagerly to keep bsky.app's profile-page
    /// rendering deterministic: a partial offering produces a
    /// half-blank UI which is worse than a clear build error.
    #[error(
        "labelValueDefinitions must be 1:1 with label_values \
         (missing: {missing:?}, extra: {extra:?})"
    )]
    DefinitionMismatch {
        /// Label values for which no definition was supplied.
        missing: Vec<String>,
        /// Definitions whose `identifier` is not in `label_values`.
        extra: Vec<String>,
    },
}

/// Errors that [`validate_record`] (the wrapper, not the proto-blue
/// re-export) can return.
///
/// `LexiconLoad` covers the unlikely scenario where the embedded JSON
/// files fail to parse; `Schema` covers an actual record-vs-schema
/// mismatch; `Serialize` and `LexConversion` cover the
/// JSON ↔ `LexValue` plumbing.
#[derive(Debug, Error)]
pub enum ValidationError {
    /// One of the embedded lexicon JSON documents failed to load.
    #[error("failed to load embedded lexicon `{nsid}`: {source}")]
    LexiconLoad {
        /// The NSID we were loading when the error fired.
        nsid: &'static str,
        /// The underlying error returned by the lexicon registry.
        #[source]
        source: proto_blue::lexicon::LexiconError,
    },

    /// The record failed to round-trip through `serde_json::to_value`.
    #[error("failed to serialize record to JSON: {0}")]
    Serialize(#[from] serde_json::Error),

    /// The record did not validate against the labeler service lexicon.
    #[error("lexicon validation failed: {0}")]
    Schema(proto_blue::lexicon::ValidationError),

    /// The lexicon registry is internally inconsistent — the labeler
    /// service definition was not registered as expected. This is a
    /// programming invariant, not a user input error.
    #[error("internal: labeler service definition missing from registry")]
    DefinitionMissing,

    /// The labeler service definition is registered, but is not of kind
    /// `record`. This is a programming invariant.
    #[error("internal: labeler service definition is not a record type")]
    DefinitionNotRecord,
}

/// Construct the `app.bsky.labeler.service` record value.
///
/// All inputs are validated up-front; the returned [`RecordValue`] is
/// guaranteed parseable but has not yet been schema-validated against
/// the lexicon — call [`validate_record`] for that.
///
/// The returned record carries **both** `policies.labelValues` (the
/// declared set of values this labeler may emit) **and**
/// `policies.labelValueDefinitions` (per-value UI metadata: severity,
/// blur behavior, default subscriber setting, English locale strings).
/// bsky.app's profile UI renders the labeler's offering from
/// `labelValueDefinitions`; a record with only raw values (no
/// definitions) is accepted by the AppView but produces a blank
/// "Labels" surface on the profile page — operators see no evidence
/// the labeler advertises anything. Polaris emits sensible defaults
/// when the caller does not supply explicit definitions (see
/// [`default_definitions_for`]) so an operator's first-run wizard
/// flow yields a profile page that immediately surfaces the labels.
///
/// # Errors
///
/// Returns a [`BuildError`] if `signing_pubkey` is not a parseable
/// did:key, `service_url` is not a valid HTTPS URL, `label_values`
/// is empty, or any provided definition's `identifier` is not in
/// `label_values`.
pub fn build_labeler_service_record(
    service_url: &str,
    signing_pubkey: &str,
    label_values: Vec<String>,
) -> Result<RecordValue, BuildError> {
    let definitions = default_definitions_for(&label_values);
    build_labeler_service_record_with_definitions(
        service_url,
        signing_pubkey,
        label_values,
        definitions,
    )
}

/// Same as [`build_labeler_service_record`] but allows the caller to
/// supply explicit `labelValueDefinitions`. Use this when the
/// operator has configured per-label metadata (severity, blur
/// behavior, locales) and you want to honor it verbatim instead of
/// the default-fill path.
///
/// `definitions` must contain exactly one entry per `label_value`:
/// extras (a definition whose identifier isn't in `label_values`)
/// and gaps (a value without a matching definition) both yield a
/// [`BuildError::DefinitionMismatch`]. The 1:1 contract surfaces
/// operator config drift loudly rather than letting bsky.app render
/// a partial offering.
///
/// # Errors
///
/// In addition to the [`build_labeler_service_record`] error set,
/// returns [`BuildError::DefinitionMismatch`] when the definition
/// set is not exactly 1:1 with `label_values`.
pub fn build_labeler_service_record_with_definitions(
    service_url: &str,
    signing_pubkey: &str,
    label_values: Vec<String>,
    definitions: Vec<proto_blue::api::com::atproto::label::defs::LabelValueDefinition>,
) -> Result<RecordValue, BuildError> {
    // Validate the service URL eagerly so a typo is caught at flag-
    // parse time rather than at publish time.
    let parsed_url = url::Url::parse(service_url)
        .map_err(|e| BuildError::InvalidServiceUrl(format!("{service_url}: {e}")))?;
    if parsed_url.scheme() != "https" {
        return Err(BuildError::NonHttpsServiceUrl(service_url.to_string()));
    }

    // Validate the did:key. We don't keep the parsed bytes — the record
    // does not embed the key — but a malformed value here would silently
    // skip past every downstream check, so we reject early.
    let parsed = proto_blue::crypto::parse_did_key(signing_pubkey)
        .map_err(|e| BuildError::InvalidDidKey(format!("{signing_pubkey}: {e}")))?;
    if parsed.jwt_alg != "ES256K" && parsed.jwt_alg != "ES256" {
        return Err(BuildError::UnsupportedDidKeyCurve(parsed.jwt_alg));
    }

    if label_values.is_empty() {
        return Err(BuildError::EmptyLabelValues);
    }

    // 1:1 cross-check: every value has a definition; no extras.
    let value_set: std::collections::BTreeSet<&str> =
        label_values.iter().map(String::as_str).collect();
    let def_set: std::collections::BTreeSet<&str> =
        definitions.iter().map(|d| d.identifier.as_str()).collect();
    if value_set != def_set {
        let missing: Vec<String> = value_set
            .difference(&def_set)
            .map(|s| (*s).to_owned())
            .collect();
        let extra: Vec<String> = def_set
            .difference(&value_set)
            .map(|s| (*s).to_owned())
            .collect();
        return Err(BuildError::DefinitionMismatch { missing, extra });
    }

    let policies = proto_blue::api::app::bsky::labeler::defs::LabelerPolicies {
        label_value_definitions: Some(definitions),
        label_values,
    };

    let main = labeler_service::Main {
        r#type: labeler_service::TYPE.to_string(),
        created_at: Datetime::now(),
        labels: None,
        policies,
        reason_types: None,
        subject_collections: None,
        subject_types: None,
    };

    Ok(RecordValue { inner: main })
}

/// Auto-generate one [`LabelValueDefinition`] per label value with
/// neutral, operator-overridable defaults: `severity = "inform"`
/// (least intrusive), `blurs = "none"` (don't hide content),
/// `defaultSetting = "warn"` (subscribers see a notice), and one
/// English locale where the display name equals the identifier and
/// the description names the labeler. Returned in the same order as
/// `label_values` so a 1:1 zip is deterministic.
///
/// Operators who want richer per-label metadata (per-locale strings,
/// severity escalation, blur-on-media for image labels, etc.) should
/// pass their own definitions to
/// [`build_labeler_service_record_with_definitions`]. The defaults
/// here exist so the first-run wizard produces a profile page that
/// already renders the labeler's offering — see the doc on
/// [`build_labeler_service_record`] for the bsky.app rendering
/// rationale.
///
/// [`LabelValueDefinition`]: proto_blue::api::com::atproto::label::defs::LabelValueDefinition
#[must_use]
pub fn default_definitions_for(
    label_values: &[String],
) -> Vec<proto_blue::api::com::atproto::label::defs::LabelValueDefinition> {
    use proto_blue::api::com::atproto::label::defs::{
        LabelValueDefinition, LabelValueDefinitionStrings,
    };
    label_values
        .iter()
        .map(|identifier| LabelValueDefinition {
            adult_only: Some(false),
            blurs: "none".to_owned(),
            default_setting: Some("warn".to_owned()),
            identifier: identifier.clone(),
            locales: vec![LabelValueDefinitionStrings {
                description: format!(
                    "Label '{identifier}' as advertised by this labeler. The operator has \
                     not yet supplied a custom description for this value.",
                ),
                lang: "en".to_owned(),
                name: identifier.clone(),
            }],
            severity: "inform".to_owned(),
        })
        .collect()
}

/// Validate a [`RecordValue`] against the embedded
/// `app.bsky.labeler.service` lexicon plus its three transitive
/// schema dependencies.
///
/// # Errors
///
/// Returns a [`ValidationError`] if the embedded lexicons fail to load
/// (this would indicate a corrupt build artifact), if the record fails
/// to serialize to JSON, or if the record does not match the schema.
pub fn validate_record(record: &RecordValue) -> Result<(), ValidationError> {
    let lexicons = load_lexicons()?;

    let def = lexicons
        .get_def(RECORD_TYPE)
        .ok_or(ValidationError::DefinitionMissing)?;
    let LexUserType::Record(record_def) = def else {
        return Err(ValidationError::DefinitionNotRecord);
    };

    let json = record.to_json()?;
    let lex = json_to_lex(&json);

    proto_blue::lexicon::validate_record(&lexicons, record_def, &lex)
        .map_err(ValidationError::Schema)
}

/// Construct a [`Lexicons`] registry seeded with the four schemas the
/// labeler service record transitively references.
fn load_lexicons() -> Result<Lexicons, ValidationError> {
    let mut lexicons = Lexicons::new();
    for (nsid, json) in [
        ("com.atproto.moderation.defs", LEXICON_MODERATION_DEFS),
        ("com.atproto.label.defs", LEXICON_LABEL_DEFS),
        ("app.bsky.labeler.defs", LEXICON_LABELER_DEFS),
        (RECORD_TYPE, LEXICON_LABELER_SERVICE),
    ] {
        lexicons
            .add_from_json(json)
            .map_err(|source| ValidationError::LexiconLoad { nsid, source })?;
    }
    Ok(lexicons)
}

/// Build a put-record AT-URI for a given operator handle/DID.
///
/// The labeler service record is always at `rkey = self` per the
/// lexicon's `key: literal:self` constraint. Exposed publicly because
/// tests and the dry-run path both surface the AT-URI in their output.
#[must_use]
pub fn record_at_uri(repo: &str) -> String {
    format!("at://{repo}/{RECORD_COLLECTION}/{RECORD_RKEY}")
}

// Re-export, under a stable name, the four label-value sentinels every
// labeler is likely to declare. Saves call sites from reaching into a
// deeply-namespaced module of the generated crate.
pub use proto_blue::api::com::atproto::label::defs::{
    LABEL_VALUE_DMCA_VIOLATION, LABEL_VALUE_DOXXING, LABEL_VALUE_GORE, LABEL_VALUE_HIDE,
    LABEL_VALUE_NO_PROMOTE, LABEL_VALUE_NO_UNAUTHENTICATED, LABEL_VALUE_NSFL, LABEL_VALUE_NUDITY,
    LABEL_VALUE_PORN, LABEL_VALUE_SEXUAL, LABEL_VALUE_WARN,
};

// Re-export the proto-blue API types unit tests need to reason about
// the constructed record without re-importing the generated module
// path everywhere.
pub use proto_blue::api::app::bsky::labeler::defs::LabelerPolicies;
pub use proto_blue::api::app::bsky::labeler::service::Main as LabelerServiceMain;
