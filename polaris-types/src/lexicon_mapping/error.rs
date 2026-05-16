//! [`MappingError`] — typed errors from the lexicon mapping boundary.
//!
//! Every public function in [`crate::lexicon_mapping`] that can fail returns
//! `Result<_, MappingError>`. Structured variants carry diagnostic context so
//! callers can log and surface meaningful error messages without parsing
//! `Display` strings.

/// Errors produced by the `polaris-types` ↔ `polaris-lexicons` mapping
/// functions.
///
/// All variants are produced by hand-written mapping logic; no `#[from]`
/// impls on `serde_json::Error` or other library errors — we want structured
/// diagnostics, not free-form strings.
#[derive(Debug, thiserror::Error)]
pub enum MappingError {
    /// A numeric field (typically a scaled-integer confidence or score) is
    /// outside its valid range.
    ///
    /// The `field` name identifies which field, and `value` is the
    /// out-of-range value as a `String` for human readability.
    #[error("field `{field}` out of range: {value}")]
    FieldOutOfRange {
        /// Name of the field that was out of range.
        field: &'static str,
        /// The offending value, stringified.
        value: String,
    },

    /// A union discriminator value is not in the safe-to-federate set.
    ///
    /// The `discriminator` is the string tag that was seen (e.g.
    /// `"report_volume_anomaly"` or `"moderator_behavior_anomaly"`). These
    /// variants are internal-only and must not cross instance boundaries.
    #[error("unsupported variant for discriminator `{discriminator}`")]
    UnsupportedVariant {
        /// The discriminator string that was rejected.
        discriminator: &'static str,
    },

    /// A required field was absent in the wire form.
    ///
    /// Produced when a field that the lexicon marks optional is `None` but
    /// the internal type requires it (e.g. after a `SubjectRefs::Other`
    /// catch-all arm catches an unrecognised discriminator).
    #[error("missing required field `{field}`")]
    MissingRequired {
        /// Name of the required field that was absent.
        field: &'static str,
    },

    /// A DID string was syntactically malformed.
    ///
    /// Polaris accepts any `did:…` string without deep validation at this
    /// layer; this error fires only when the value is clearly not a DID
    /// (e.g. empty string, no `:` separator).
    #[error("malformed DID: {value:?}")]
    MalformedDid {
        /// The offending string.
        value: String,
    },

    /// An AT-URI string was syntactically malformed.
    ///
    /// Fires when a value claimed to be an AT-URI does not start with
    /// `at://`.
    #[error("malformed AT-URI: {value:?}")]
    MalformedAtUri {
        /// The offending string.
        value: String,
    },

    /// An RFC 3339 datetime string failed to parse.
    ///
    /// Fires when a value claimed to be a `format: datetime` Lexicon string
    /// cannot be parsed by `chrono::DateTime::parse_from_rfc3339`. Added in
    /// issue #110 for the `escalationMessage.signedAt` round-trip.
    #[error("invalid RFC 3339 datetime: {value:?}: {source}")]
    InvalidDatetime {
        /// The offending string.
        value: String,
        /// The chrono parser's structured error for diagnostic chaining.
        #[source]
        source: chrono::ParseError,
    },
}
