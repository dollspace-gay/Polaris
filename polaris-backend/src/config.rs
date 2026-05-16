//! Typed configuration for the Polaris backend.
//!
//! All configuration access in the binary and library MUST go through
//! [`AppConfig`]. Calling `std::env::var` directly elsewhere is a process
//! discipline violation — scattered env reads make the surface impossible to
//! audit, and the architect's pre-flight for #8 calls this out explicitly.
//!
//! # Sources, in precedence order
//!
//! 1. Environment variables (`DATABASE_URL`, `POLARIS_HTTP_BIND`).
//! 2. Hard-coded defaults documented on each field.
//!
//! A future issue will layer a TOML file under `polaris.toml` between these
//! two layers; the shape of [`AppConfig`] is designed so `serde` can drive
//! that without an API break.

use std::env;
use std::num::ParseIntError;
use std::path::PathBuf;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

/// Top-level application configuration.
///
/// Constructed via [`AppConfig::from_env`] at process start and threaded
/// through the binary; never mutated after startup.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// Database connection + pool settings.
    pub db: DbConfig,
    /// HTTP listener settings.
    pub http: HttpConfig,
    /// Moderator-authentication settings (#9).
    #[serde(default)]
    pub auth: AuthConfig,
    /// Security settings (cookie key, etc.) (#9).
    #[serde(default)]
    pub security: SecurityConfig,
    /// Pattern-action settings (#21).
    #[serde(default)]
    pub pattern_actions: PatternActionsConfig,
    /// Labeler subsystem settings (#29: signing-key custody).
    #[serde(default)]
    pub labeler: LabelerConfig,
    /// Deployment profile (#29 / AC-14). Drives the binding profile-
    /// vs-mode safety check on the labeler signing-key custody
    /// selection.
    #[serde(default)]
    pub profile: Profile,
    /// Evidence-preservation worker settings (#33 / REQ-10 / AC-11).
    #[serde(default)]
    pub evidence: EvidenceConfig,
    /// Reporter-reputation tunables (#37, design.md §9.3).
    #[serde(default)]
    pub reputation: ReputationConfig,
    /// Moderator-behavior-anomaly detector tunables (#73, design.md
    /// §9 #1 / threat-model T1).
    #[serde(default)]
    pub moderator_anomaly: ModeratorAnomalyEnvConfig,
    /// Report-aggregation worker tunables (#75, design.md §9 #4 /
    /// threat-model T4).
    #[serde(default)]
    pub aggregator: AggregatorEnvConfig,
    /// Cross-instance federation settings (issue #107 / M5 PR 1).
    ///
    /// When `federation.enabled = true` (env: `POLARIS_FEDERATION_ENABLED`)
    /// the binary spawns one Firehose subscriber per configured peer.
    /// Defaults to disabled so existing deployments are unaffected.
    #[serde(default)]
    pub federation: FederationConfig,
}

/// Postgres connection and pool configuration.
///
/// All fields are `serde(default)`-able with the documented fallbacks so
/// operators can override individual values via TOML in the future without
/// being forced to specify every field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbConfig {
    /// Postgres connection URL. From `DATABASE_URL` env or the
    /// dev-friendly default `postgres://polaris:polaris@localhost:5432/polaris`.
    #[serde(default = "default_database_url")]
    pub url: String,
    /// Hard cap on connections in the pool. Default 16.
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// Number of connections to keep warm. Default 1.
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
    /// Timeout (seconds) for `pool.acquire()`. Default 5.
    #[serde(default = "default_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
}

/// HTTP listener configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Bind address. From `POLARIS_HTTP_BIND` env or default `127.0.0.1:8080`.
    #[serde(default = "default_http_bind")]
    pub bind: String,
}

fn default_database_url() -> String {
    "postgres://polaris:polaris@localhost:5432/polaris".to_owned()
}

fn default_max_connections() -> u32 {
    16
}

fn default_min_connections() -> u32 {
    1
}

fn default_acquire_timeout_secs() -> u64 {
    5
}

fn default_http_bind() -> String {
    "127.0.0.1:8080".to_owned()
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: default_database_url(),
            max_connections: default_max_connections(),
            min_connections: default_min_connections(),
            acquire_timeout_secs: default_acquire_timeout_secs(),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind: default_http_bind(),
        }
    }
}

impl AppConfig {
    /// Build an [`AppConfig`] from environment variables, falling back to
    /// documented defaults for any unset variable.
    ///
    /// Recognised variables:
    ///
    /// | Variable             | Field             | Default                                                    |
    /// |----------------------|-------------------|------------------------------------------------------------|
    /// | `DATABASE_URL`       | `db.url`          | `postgres://polaris:polaris@localhost:5432/polaris`        |
    /// | `POLARIS_HTTP_BIND`  | `http.bind`       | `127.0.0.1:8080`                                           |
    ///
    /// Numeric pool parameters are not (yet) overridable via env because they
    /// rarely vary across deployments — operators who need to tune them
    /// should wait for the TOML config layer (#TBD) or override the
    /// [`DbConfig`] struct in code.
    pub fn from_env() -> Result<Self, ConfigError> {
        let db = DbConfig {
            url: env::var("DATABASE_URL").unwrap_or_else(|_| default_database_url()),
            max_connections: default_max_connections(),
            min_connections: default_min_connections(),
            acquire_timeout_secs: default_acquire_timeout_secs(),
        };

        let http = HttpConfig {
            bind: env::var("POLARIS_HTTP_BIND").unwrap_or_else(|_| default_http_bind()),
        };

        let auth = AuthConfig::from_env()?;
        let security = SecurityConfig::from_env()?;
        let pattern_actions = PatternActionsConfig::from_env()?;
        let labeler = LabelerConfig::from_env()?;
        let profile = Profile::from_env()?;
        let evidence = EvidenceConfig::from_env()?;
        let reputation = ReputationConfig::from_env()?;
        let moderator_anomaly = ModeratorAnomalyEnvConfig::from_env()?;
        let aggregator = AggregatorEnvConfig::from_env()?;
        let federation = FederationConfig::from_env()?;

        Ok(Self {
            db,
            http,
            auth,
            security,
            pattern_actions,
            labeler,
            profile,
            evidence,
            reputation,
            moderator_anomaly,
            aggregator,
            federation,
        })
    }
}

/// Pattern-action settings (issue #21).
///
/// Drives the senior-co-sign gating on bulk-on-pattern actions per
/// `design.md` §5.3. The threshold is the maximum *auto-approved* affected-
/// subject count: a proposal that affects `> cosign_threshold` subjects
/// requires a senior signature before its per-subject [`crate::repo::action::NewAction`]
/// rows are inserted. The proposer's own signature is implicit in
/// `pattern_actions.requested_by`; the cosign row is a second moderator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PatternActionsConfig {
    /// Auto-approve pattern actions affecting at most this many subjects.
    /// Anything above this requires senior co-sign. Default 100; aligns
    /// with the `[pattern.cosign] required_above_n` example in the #21
    /// design comment.
    #[serde(default = "default_cosign_threshold")]
    pub cosign_threshold: usize,
}

const fn default_cosign_threshold() -> usize {
    100
}

impl Default for PatternActionsConfig {
    fn default() -> Self {
        Self {
            cosign_threshold: default_cosign_threshold(),
        }
    }
}

impl PatternActionsConfig {
    /// Build from environment variables.
    ///
    /// Recognises `POLARIS_PATTERN_ACTIONS_COSIGN_THRESHOLD`. Falls back
    /// to [`default_cosign_threshold`] when unset.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInt`] when the env value cannot be
    /// parsed as a `usize`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let cosign_threshold = match env::var("POLARIS_PATTERN_ACTIONS_COSIGN_THRESHOLD").ok() {
            Some(raw) => raw
                .parse::<usize>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_PATTERN_ACTIONS_COSIGN_THRESHOLD",
                    source,
                })?,
            None => default_cosign_threshold(),
        };
        Ok(Self { cosign_threshold })
    }
}

/// Moderator-authentication configuration.
///
/// The selected `backend` drives which [`crate::auth::ModeratorAuth`]
/// implementation is constructed at startup. Both [`OidcConfig`] and
/// [`AtprotoAuthConfig`] are deserialised regardless of which backend is
/// active so an operator can swap `backend` without restart-time
/// validation surprises.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Which authentication backend to use.
    #[serde(default)]
    pub backend: AuthBackend,
    /// OIDC backend settings — populated even when `backend = Atproto` so
    /// a future operator can swap by config without restart-time
    /// validation surprises.
    #[serde(default)]
    pub oidc: OidcConfig,
    /// ATProto OAuth backend settings — populated even when `backend =
    /// Oidc` for the same swap-by-config reason.
    #[serde(default)]
    pub atproto: AtprotoAuthConfig,
    /// Hardware-key (WebAuthn / FIDO2) post-login gate (issue #40,
    /// design.md §6 + §9.1).
    ///
    /// `None` means "use the profile default": [`Profile::Bluesky`]
    /// defaults to `true` (the first-party deployment refuses access
    /// without a registered hardware key), [`Profile::Labeler`] defaults
    /// to `false` (the self-hosted labeler is unaffected unless the
    /// operator opts in). The runtime decision is computed by
    /// [`AuthConfig::resolve_require_hardware_key`].
    #[serde(default)]
    pub require_hardware_key: Option<bool>,
}

impl AuthConfig {
    /// Build from environment.
    ///
    /// Recognises `POLARIS_REQUIRE_HARDWARE_KEY` (`true` / `false` /
    /// `1` / `0` / `yes` / `no`). Anything else is rejected with
    /// [`ConfigError::InvalidEnumValue`]. Unset leaves the field `None`
    /// so the profile default applies (see
    /// [`Self::resolve_require_hardware_key`]).
    ///
    /// # Errors
    ///
    /// - [`ConfigError::InvalidEnumValue`] if `POLARIS_AUTH_BACKEND` is
    ///   not one of `oidc` / `atproto`, or if
    ///   `POLARIS_REQUIRE_HARDWARE_KEY` is set to a value outside the
    ///   accepted truthy / falsy set.
    pub fn from_env() -> Result<Self, ConfigError> {
        let backend = match env::var("POLARIS_AUTH_BACKEND").ok().as_deref() {
            None | Some("oidc") => AuthBackend::Oidc,
            Some("atproto") => AuthBackend::Atproto,
            Some(other) => {
                return Err(ConfigError::InvalidEnumValue {
                    field: "POLARIS_AUTH_BACKEND",
                    value: other.to_owned(),
                    accepted: &["oidc", "atproto"],
                });
            }
        };
        let oidc = OidcConfig::from_env();
        let atproto = AtprotoAuthConfig::from_env();
        let require_hardware_key = parse_optional_bool_env("POLARIS_REQUIRE_HARDWARE_KEY")?;
        Ok(Self {
            backend,
            oidc,
            atproto,
            require_hardware_key,
        })
    }

    /// Resolve [`Self::require_hardware_key`] against the deployment
    /// profile.
    ///
    /// Precedence: explicit `Some(_)` override wins; otherwise the
    /// profile default applies — `Profile::Bluesky` → `true`,
    /// `Profile::Labeler` → `false`. See design.md §6 + §9.1.
    #[must_use]
    pub fn resolve_require_hardware_key(&self, profile: Profile) -> bool {
        self.require_hardware_key
            .unwrap_or(matches!(profile, Profile::Bluesky))
    }
}

/// Parse a tri-state env var (`unset` / `truthy` / `falsy`).
///
/// Accepts `true` / `1` / `yes` (case-insensitive) for `Some(true)` and
/// `false` / `0` / `no` for `Some(false)`. Unset returns `None`. Anything
/// else surfaces as [`ConfigError::InvalidEnumValue`] so a typo at config
/// time fails closed at startup rather than silently defaulting the
/// flag.
fn parse_optional_bool_env(var: &'static str) -> Result<Option<bool>, ConfigError> {
    match env::var(var).ok() {
        None => Ok(None),
        Some(raw) => {
            let trimmed = raw.trim();
            let lower = trimmed.to_ascii_lowercase();
            match lower.as_str() {
                "true" | "1" | "yes" => Ok(Some(true)),
                "false" | "0" | "no" => Ok(Some(false)),
                _ => Err(ConfigError::InvalidEnumValue {
                    field: var,
                    value: raw,
                    accepted: &["true", "false", "1", "0", "yes", "no"],
                }),
            }
        }
    }
}

/// ATProto OAuth backend configuration (issue #31 / REQ-4).
///
/// The operator hosts a JSON document describing the OAuth client at
/// `client_id` (per the atproto OAuth client-id-metadata-document
/// profile); Polaris reads the same JSON off disk at startup to drive
/// [`crate::auth::atproto::AtprotoOauthAuthVerifier`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AtprotoAuthConfig {
    /// Path to the OAuth `client_metadata.json` file. The public
    /// `client_id` URL inside that document MUST point at the
    /// `client_uri` the operator serves it from — both proto-blue's
    /// validation and the AS will reject a mismatch.
    #[serde(default)]
    pub client_metadata_path: PathBuf,
    /// Public `client_id` URL — duplicated here so the binary can
    /// startup-validate without re-reading the JSON file. Empty when the
    /// operator hasn't configured the atproto backend; the
    /// `AtprotoOauthAuthVerifier` constructor refuses to boot against an
    /// empty path.
    #[serde(default)]
    pub client_id: String,
}

impl AtprotoAuthConfig {
    /// Build from environment.
    ///
    /// Recognises:
    ///
    /// | Variable                            | Field                  |
    /// |-------------------------------------|------------------------|
    /// | `POLARIS_ATPROTO_CLIENT_METADATA`   | `client_metadata_path` |
    /// | `POLARIS_ATPROTO_CLIENT_ID`         | `client_id`            |
    ///
    /// Both default to empty when unset — the verifier constructor
    /// refuses to boot against an empty path so a `backend = "atproto"`
    /// startup without these set fails closed.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            client_metadata_path: env::var("POLARIS_ATPROTO_CLIENT_METADATA")
                .map(PathBuf::from)
                .unwrap_or_default(),
            client_id: env::var("POLARIS_ATPROTO_CLIENT_ID").unwrap_or_default(),
        }
    }
}

/// Which authentication backend is active.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthBackend {
    /// `OpenID` Connect against the operator's `IdP` (issue #9, default).
    #[default]
    Oidc,
    /// ATProto OAuth (issue #31; backend not yet implemented).
    Atproto,
}

/// OIDC backend configuration.
///
/// `client_secret` is wrapped in [`SecretString`] so it never lands in a log
/// line via the default `Debug` derive — the `Debug` impl prints
/// `Secret(REDACTED)` and the secret bytes are zeroised on drop by the
/// `secrecy` crate. `Serialize` is implemented by hand below so a future
/// `polaris.toml` export can never round-trip a real secret to disk; we emit
/// `"[REDACTED]"` instead.
#[derive(Clone, Deserialize)]
pub struct OidcConfig {
    /// Issuer URL (e.g. `https://accounts.example.com`). Discovery hits
    /// `{issuer_url}/.well-known/openid-configuration`.
    pub issuer_url: String,
    /// Client ID registered with the `IdP`.
    pub client_id: String,
    /// Client secret. Wrapped to redact in `Debug` and zeroise on drop.
    #[serde(default = "default_client_secret")]
    pub client_secret: SecretString,
    /// Polaris-side OAuth redirect URL.
    pub redirect_url: String,
}

impl Serialize for OidcConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        // The client_secret field is deliberately serialised as the
        // sentinel string "[REDACTED]" rather than the actual value. This
        // protects against a developer accidentally `serde_json::to_string`-ing
        // an `OidcConfig` into a log line.
        let mut s = serializer.serialize_struct("OidcConfig", 4)?;
        s.serialize_field("issuer_url", &self.issuer_url)?;
        s.serialize_field("client_id", &self.client_id)?;
        s.serialize_field("client_secret", "[REDACTED]")?;
        s.serialize_field("redirect_url", &self.redirect_url)?;
        s.end()
    }
}

fn default_client_secret() -> SecretString {
    SecretString::from(String::new())
}

impl std::fmt::Debug for OidcConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcConfig")
            .field("issuer_url", &self.issuer_url)
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("redirect_url", &self.redirect_url)
            .finish()
    }
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            client_id: String::new(),
            client_secret: SecretString::from(String::new()),
            redirect_url: String::new(),
        }
    }
}

impl OidcConfig {
    /// Build from environment variables. All four fields fall back to the
    /// empty string if unset; the auth subsystem will refuse to boot a real
    /// `OidcAuthVerifier` against empty values, so configuration mistakes
    /// surface at process start (not at the first login attempt).
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            issuer_url: env::var("POLARIS_OIDC_ISSUER_URL").unwrap_or_default(),
            client_id: env::var("POLARIS_OIDC_CLIENT_ID").unwrap_or_default(),
            client_secret: SecretString::from(
                env::var("POLARIS_OIDC_CLIENT_SECRET").unwrap_or_default(),
            ),
            redirect_url: env::var("POLARIS_OIDC_REDIRECT_URL").unwrap_or_default(),
        }
    }
}

/// Security-sensitive configuration.
///
/// Currently houses the AES-256-GCM wrapping key used to encrypt refresh
/// tokens at rest. Parsed from `POLARIS_COOKIE_KEY`, a 64-character hex
/// string. The struct cannot be `Default`-constructed with a real key —
/// callers MUST supply 32 bytes of randomness via the env. The `Default`
/// impl returns a zero-key placeholder so [`AppConfig::default`] can compose;
/// downstream code that mints a [`crate::auth::crypto::Crypto`] from
/// [`SecurityConfig::cookie_key`] should validate non-zeroness in production
/// startup.
#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// 32-byte AES-256 key. Operators must supply this; defaulting to a
    /// zero array is a startup-only convenience that the binary refuses to
    /// run against in non-test builds.
    #[serde(with = "cookie_key_serde")]
    pub cookie_key: [u8; 32],
}

mod cookie_key_serde {
    //! Serialise / deserialise the 32-byte cookie key as a lowercase hex
    //! string so `polaris.toml` (when introduced) can stringly-type the
    //! field without inventing a base64 nesting.

    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("cookie_key must be 32 bytes (64 hex chars)"))?;
        Ok(arr)
    }
}

impl std::fmt::Debug for SecurityConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityConfig")
            .field("cookie_key", &"[REDACTED 32 bytes]")
            .finish()
    }
}

// Allow: the manual `Default` impl exists to host the "zero-key is a
// startup placeholder" comment that `SecurityConfig::ensure_non_zero`
// enforces against. The derived form would compile but the reader would
// lose the safety note at exactly the place they need it. The deliberate
// override is the documentation, not the body.
#[allow(clippy::derivable_impls)]
impl Default for SecurityConfig {
    fn default() -> Self {
        // Zero key is a placeholder for `Default`-constructed `AppConfig`s in
        // unit tests. `SecurityConfig::from_env` rejects a zero key.
        Self {
            cookie_key: [0_u8; 32],
        }
    }
}

impl SecurityConfig {
    /// Read `POLARIS_COOKIE_KEY` (64 hex chars → 32 bytes).
    ///
    /// # Errors
    ///
    /// - [`ConfigError::MissingRequired`] if the variable is unset and the
    ///   process is running in non-test mode (we treat an unset key as a
    ///   default-zero-key here; the binary's startup path validates
    ///   non-zeroness — see [`Self::ensure_non_zero`]).
    /// - [`ConfigError::InvalidHex`] if the value is not 64 hex chars.
    pub fn from_env() -> Result<Self, ConfigError> {
        let Some(value) = env::var("POLARIS_COOKIE_KEY").ok() else {
            // Allow unset in dev / tests so `AppConfig::default()` keeps
            // working. The binary's startup checks `ensure_non_zero`.
            return Ok(Self::default());
        };
        if value.len() != 64 {
            return Err(ConfigError::InvalidHex {
                field: "POLARIS_COOKIE_KEY",
                reason: format!("expected 64 hex chars, got {}", value.len()),
            });
        }
        let bytes = hex::decode(&value).map_err(|e| ConfigError::InvalidHex {
            field: "POLARIS_COOKIE_KEY",
            reason: e.to_string(),
        })?;
        let cookie_key: [u8; 32] = bytes.try_into().map_err(|_| ConfigError::InvalidHex {
            field: "POLARIS_COOKIE_KEY",
            reason: "expected 32 bytes after hex decode".to_owned(),
        })?;
        Ok(Self { cookie_key })
    }

    /// Verify the key is not the all-zero placeholder. Called from the
    /// binary entrypoint immediately before constructing
    /// [`crate::auth::crypto::Crypto`].
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::MissingRequired`] if every byte is zero.
    pub fn ensure_non_zero(&self) -> Result<(), ConfigError> {
        if self.cookie_key.iter().all(|b| *b == 0) {
            return Err(ConfigError::MissingRequired {
                field: "POLARIS_COOKIE_KEY",
            });
        }
        Ok(())
    }
}

/// Configuration errors.
///
/// Reserved for future fallible parsing — currently every supported override
/// is a free-form string, so `from_env` is infallible. The variant is here so
/// callers do not need to break their `Result` ergonomics when (e.g.) a
/// `POLARIS_DB_MAX_CONNECTIONS` env override lands later.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to parse an integer-valued setting.
    #[error("invalid integer for {field}: {source}")]
    InvalidInt {
        /// Configuration field that failed to parse.
        field: &'static str,
        /// Underlying parse error.
        #[source]
        source: ParseIntError,
    },

    /// An enum-typed env variable was set to a value outside the accepted
    /// set.
    #[error("invalid value {value:?} for {field}: must be one of {accepted:?}")]
    InvalidEnumValue {
        /// Offending env-variable name.
        field: &'static str,
        /// Value the operator supplied.
        value: String,
        /// Permitted values.
        accepted: &'static [&'static str],
    },

    /// A hex-encoded env variable failed to parse.
    #[error("invalid hex value for {field}: {reason}")]
    InvalidHex {
        /// Offending env-variable name.
        field: &'static str,
        /// Human-readable reason for the rejection.
        reason: String,
    },

    /// A required env variable was unset (or set to the unsafe default).
    #[error("required configuration {field} is unset")]
    MissingRequired {
        /// Offending env-variable name.
        field: &'static str,
    },
}

/// Deployment profile (issue #29 / AC-14).
///
/// Polaris ships two deployment topologies that share the same binary
/// but differ on which defaults and which safety rails apply:
///
/// - [`Profile::Labeler`] — self-hosted operator running their own
///   labeler (the de-facto Ozone-replacement use case). The labeler
///   profile *permits* `file-plain` custody for the signing key
///   (matching Ozone's `OZONE_SIGNING_KEY_HEX` posture); the startup
///   WARN is the only feedback.
/// - [`Profile::Bluesky`] — first-party Bluesky deployment. The
///   profile *refuses* to start with `file-plain` because a first-party
///   deployment running KMS infrastructure should never regress to a
///   plaintext on-disk key.
///
/// The selection is read from `POLARIS_PROFILE` (env) or `[profile]
/// mode` (TOML, future). The TOML-friendly serde rename matches the
/// design-document spelling — `[profile] mode = "labeler"`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Profile {
    /// Self-hosted operator running their own labeler. Default.
    #[default]
    Labeler,
    /// First-party Bluesky deployment.
    Bluesky,
}

impl Profile {
    /// Build from environment.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidEnumValue`] when `POLARIS_PROFILE`
    /// is set to anything other than `labeler` / `bluesky`.
    pub fn from_env() -> Result<Self, ConfigError> {
        match env::var("POLARIS_PROFILE").ok().as_deref() {
            None | Some("labeler") => Ok(Self::Labeler),
            Some("bluesky") => Ok(Self::Bluesky),
            Some(other) => Err(ConfigError::InvalidEnumValue {
                field: "POLARIS_PROFILE",
                value: other.to_owned(),
                accepted: &["labeler", "bluesky"],
            }),
        }
    }
}

/// Labeler subsystem settings (issue #29).
///
/// Currently houses the signing-key custody selection. Future fields
/// (publish-record schedule, upstream-labeler trust weights, …)
/// extend this struct without an `AppConfig` shape change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LabelerConfig {
    /// Selected signing-key custody mode and its per-mode parameters.
    #[serde(default)]
    pub signing_key: LabelerSigningKeyConfig,
}

impl LabelerConfig {
    /// Build from environment.
    ///
    /// Recognises:
    ///
    /// | Variable                                | Field                                    |
    /// |-----------------------------------------|------------------------------------------|
    /// | `POLARIS_LABELER_SIGNING_KEY_MODE`      | `signing_key` enum discriminant          |
    /// | `POLARIS_LABELER_SIGNING_KEY_PATH`      | `FilePlain.path` / `PassphraseSealed.path` |
    /// | `POLARIS_LABELER_SIGNING_KEY_ACCOUNT`   | `OsKeychain.account`                     |
    /// | `POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER` | `CloudKms.provider`                  |
    /// | `POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID`  | `CloudKms.key_id`                    |
    /// | `POLARIS_LABELER_SIGNING_KEY_KMS_REGION`  | `CloudKms.region`                    |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidEnumValue`] for an unrecognised
    /// `mode` or `kms_provider`, and [`ConfigError::MissingRequired`]
    /// for a mode whose required fields are absent (e.g. file-plain
    /// without a path).
    pub fn from_env() -> Result<Self, ConfigError> {
        let mode = env::var("POLARIS_LABELER_SIGNING_KEY_MODE").ok();
        let signing_key = match mode.as_deref() {
            // Unset == labeler-profile default == file-plain with a
            // path the labeler-profile binary's startup check would
            // resolve. The struct-level default *is* file-plain at a
            // sentinel path; `build_signing_key` will fail at key
            // load if the path is bogus, surfacing a clear "you need
            // to configure POLARIS_LABELER_SIGNING_KEY_PATH" message.
            None => LabelerSigningKeyConfig::default(),
            Some("file-plain") => {
                let path = env::var("POLARIS_LABELER_SIGNING_KEY_PATH")
                    .map(PathBuf::from)
                    .map_err(|_| ConfigError::MissingRequired {
                        field: "POLARIS_LABELER_SIGNING_KEY_PATH",
                    })?;
                LabelerSigningKeyConfig::FilePlain { path }
            }
            Some("passphrase-sealed") => {
                let path = env::var("POLARIS_LABELER_SIGNING_KEY_PATH")
                    .map(PathBuf::from)
                    .map_err(|_| ConfigError::MissingRequired {
                        field: "POLARIS_LABELER_SIGNING_KEY_PATH",
                    })?;
                LabelerSigningKeyConfig::PassphraseSealed { path }
            }
            Some("os-keychain") => {
                let account = env::var("POLARIS_LABELER_SIGNING_KEY_ACCOUNT").map_err(|_| {
                    ConfigError::MissingRequired {
                        field: "POLARIS_LABELER_SIGNING_KEY_ACCOUNT",
                    }
                })?;
                LabelerSigningKeyConfig::OsKeychain { account }
            }
            Some("cloud-kms-oracle") => {
                let provider_str =
                    env::var("POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER").map_err(|_| {
                        ConfigError::MissingRequired {
                            field: "POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER",
                        }
                    })?;
                let provider = match provider_str.as_str() {
                    "aws" => KmsProvider::Aws,
                    "gcp" => KmsProvider::Gcp,
                    "azure" => KmsProvider::Azure,
                    other => {
                        return Err(ConfigError::InvalidEnumValue {
                            field: "POLARIS_LABELER_SIGNING_KEY_KMS_PROVIDER",
                            value: other.to_owned(),
                            accepted: &["aws", "gcp", "azure"],
                        });
                    }
                };
                let key_id = env::var("POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID").map_err(|_| {
                    ConfigError::MissingRequired {
                        field: "POLARIS_LABELER_SIGNING_KEY_KMS_KEY_ID",
                    }
                })?;
                let region = env::var("POLARIS_LABELER_SIGNING_KEY_KMS_REGION").map_err(|_| {
                    ConfigError::MissingRequired {
                        field: "POLARIS_LABELER_SIGNING_KEY_KMS_REGION",
                    }
                })?;
                LabelerSigningKeyConfig::CloudKms {
                    provider,
                    key_id,
                    region,
                }
            }
            Some(other) => {
                return Err(ConfigError::InvalidEnumValue {
                    field: "POLARIS_LABELER_SIGNING_KEY_MODE",
                    value: other.to_owned(),
                    accepted: &[
                        "file-plain",
                        "passphrase-sealed",
                        "os-keychain",
                        "cloud-kms-oracle",
                    ],
                });
            }
        };
        Ok(Self { signing_key })
    }
}

/// Signing-key custody selection (issue #29 / REQ-11).
///
/// One enum variant per mode in the AC-13 matrix. The serde
/// representation tags on `mode` with kebab-case names so a future
/// `polaris.toml` block reads:
///
/// ```toml
/// [labeler.signing_key]
/// mode = "file-plain"
/// path = "/etc/polaris/labeler.key"
/// ```
///
/// The struct shape is deliberately flat per variant so each mode's
/// required fields live next to its name; the alternative
/// (`mode = "file-plain"` + a nested `[labeler.signing_key.file_plain]`
/// table) nests one extra layer for no benefit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum LabelerSigningKeyConfig {
    /// `file-plain` — hex-encoded K-256 secret in a 0o600 file on
    /// disk. Default for the labeler profile (Ozone-equivalent
    /// posture). Logs a startup WARN.
    FilePlain {
        /// Filesystem path to the hex-encoded secret.
        path: PathBuf,
    },
    /// `passphrase-sealed` — AES-256-GCM at rest, scrypt-derived KEK.
    /// Passphrase from `POLARIS_SIGNING_PASSPHRASE` or stdin.
    PassphraseSealed {
        /// Filesystem path to the sealed key blob.
        path: PathBuf,
    },
    /// `os-keychain` — wrapped by macOS Keychain / freedesktop Secret
    /// Service / Windows DPAPI under the `polaris.labeler` service.
    OsKeychain {
        /// Operator-configured account name (e.g. their domain).
        account: String,
    },
    /// `cloud-kms-oracle` — KMS RPC per signature. Default for the
    /// Bluesky profile. The private key never enters the process.
    ///
    /// The serde tag is the design-doc-canonical
    /// `"cloud-kms-oracle"` (not the kebab-derived `"cloud-kms"`).
    /// The variant name elides the `Oracle` suffix because the type
    /// is the oracle — there is no non-oracle KMS variant — but the
    /// on-the-wire mode name keeps the explicit qualifier so it
    /// stays self-describing in `polaris.toml`.
    #[serde(rename = "cloud-kms-oracle")]
    CloudKms {
        /// Which cloud KMS provider. Only `Aws` is wired today.
        provider: KmsProvider,
        /// Provider-specific key identifier (e.g. AWS KMS key ARN).
        key_id: String,
        /// Provider-specific region identifier.
        region: String,
    },
}

impl Default for LabelerSigningKeyConfig {
    /// Default: `file-plain` at a placeholder path. The path must be
    /// overridden via env (or the future TOML layer) before
    /// [`crate::labeler::signer::build_signing_key`] can succeed.
    fn default() -> Self {
        Self::FilePlain {
            path: PathBuf::from("/etc/polaris/labeler.key"),
        }
    }
}

/// Cloud KMS provider selector.
///
/// Today only [`KmsProvider::Aws`] is wired. The `Gcp` / `Azure`
/// variants exist on the config so an operator's TOML / env can name
/// them; constructing a signer for an unwired variant returns
/// `SigningError::Sign { reason: "... not yet implemented" }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KmsProvider {
    /// AWS KMS via `aws-sdk-kms` (feature-gated).
    Aws,
    /// GCP Cloud KMS — config-only stub, not yet implemented.
    Gcp,
    /// Azure Key Vault — config-only stub, not yet implemented.
    Azure,
}

/// Evidence-preservation worker settings (issue #33 / REQ-10 / AC-11).
///
/// Drives [`crate::evidence::worker::EvidenceWorker`] at startup: how
/// many simultaneous CAR fetches to allow, how often to poll for new
/// `evidence_jobs` rows, and which [`BlobStoreKind`] to instantiate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceConfig {
    /// Which blob-store backend to use. Defaults to
    /// [`BlobStoreKind::InMemory`] so a stock test build runs without
    /// touching disk; the labeler-profile binary overrides this to
    /// `LocalFs` via env, and the Bluesky-profile binary overrides to
    /// `S3`.
    #[serde(default)]
    pub blob_store: BlobStoreKind,
    /// Worker semaphore size — caps the number of in-flight CAR
    /// fetches. Default 4.
    #[serde(default = "default_evidence_concurrency")]
    pub worker_concurrency: usize,
    /// Seconds between drain ticks when the queue is empty. Default 5.
    #[serde(default = "default_evidence_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Maximum number of attempts before a failure is permanent
    /// (issue #69). Defaults to
    /// [`crate::evidence::worker::DEFAULT_MAX_ATTEMPTS`] (= 8).
    #[serde(default = "default_evidence_max_attempts")]
    pub max_attempts: u32,
    /// Base seconds for the exponential backoff (issue #69). Defaults
    /// to [`crate::evidence::worker::DEFAULT_RETRY_BASE_SECS`] (= 30).
    #[serde(default = "default_evidence_retry_base_secs")]
    pub retry_base_secs: u64,
}

const fn default_evidence_concurrency() -> usize {
    4
}

const fn default_evidence_poll_interval_secs() -> u64 {
    5
}

const fn default_evidence_max_attempts() -> u32 {
    crate::evidence::worker::DEFAULT_MAX_ATTEMPTS
}

const fn default_evidence_retry_base_secs() -> u64 {
    crate::evidence::worker::DEFAULT_RETRY_BASE_SECS
}

impl Default for EvidenceConfig {
    fn default() -> Self {
        Self {
            blob_store: BlobStoreKind::default(),
            worker_concurrency: default_evidence_concurrency(),
            poll_interval_secs: default_evidence_poll_interval_secs(),
            max_attempts: default_evidence_max_attempts(),
            retry_base_secs: default_evidence_retry_base_secs(),
        }
    }
}

impl EvidenceConfig {
    /// Build from environment.
    ///
    /// Recognises:
    ///
    /// | Variable                              | Field                |
    /// |---------------------------------------|----------------------|
    /// | `POLARIS_EVIDENCE_BLOB_STORE`         | `blob_store` discriminant (`in-memory` / `local-fs` / `s3`) |
    /// | `POLARIS_EVIDENCE_LOCAL_FS_ROOT`      | `BlobStoreKind::LocalFs.root`            |
    /// | `POLARIS_EVIDENCE_S3_BUCKET`          | `BlobStoreKind::S3.bucket`               |
    /// | `POLARIS_EVIDENCE_S3_REGION`          | `BlobStoreKind::S3.region`               |
    /// | `POLARIS_EVIDENCE_WORKER_CONCURRENCY` | `worker_concurrency` (default 4)         |
    /// | `POLARIS_EVIDENCE_POLL_INTERVAL_SECS` | `poll_interval_secs` (default 5)         |
    /// | `POLARIS_EVIDENCE_MAX_ATTEMPTS`       | `max_attempts` (issue #69, default 8)    |
    /// | `POLARIS_EVIDENCE_RETRY_BASE_SECS`    | `retry_base_secs` (issue #69, default 30)|
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInt`] on a non-numeric concurrency
    /// or interval, [`ConfigError::InvalidEnumValue`] on an unknown
    /// `blob_store` discriminant, [`ConfigError::MissingRequired`]
    /// when the chosen backend's required env var is unset.
    pub fn from_env() -> Result<Self, ConfigError> {
        let blob_store = match env::var("POLARIS_EVIDENCE_BLOB_STORE").ok().as_deref() {
            None | Some("in-memory") => BlobStoreKind::InMemory,
            Some("local-fs") => {
                let root = env::var("POLARIS_EVIDENCE_LOCAL_FS_ROOT")
                    .map(PathBuf::from)
                    .map_err(|_| ConfigError::MissingRequired {
                        field: "POLARIS_EVIDENCE_LOCAL_FS_ROOT",
                    })?;
                BlobStoreKind::LocalFs { root }
            }
            Some("s3") => {
                let bucket = env::var("POLARIS_EVIDENCE_S3_BUCKET").map_err(|_| {
                    ConfigError::MissingRequired {
                        field: "POLARIS_EVIDENCE_S3_BUCKET",
                    }
                })?;
                let region = env::var("POLARIS_EVIDENCE_S3_REGION").map_err(|_| {
                    ConfigError::MissingRequired {
                        field: "POLARIS_EVIDENCE_S3_REGION",
                    }
                })?;
                BlobStoreKind::S3 { bucket, region }
            }
            Some(other) => {
                return Err(ConfigError::InvalidEnumValue {
                    field: "POLARIS_EVIDENCE_BLOB_STORE",
                    value: other.to_owned(),
                    accepted: &["in-memory", "local-fs", "s3"],
                });
            }
        };
        let worker_concurrency = match env::var("POLARIS_EVIDENCE_WORKER_CONCURRENCY").ok() {
            Some(raw) => raw
                .parse::<usize>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_EVIDENCE_WORKER_CONCURRENCY",
                    source,
                })?,
            None => default_evidence_concurrency(),
        };
        let poll_interval_secs = match env::var("POLARIS_EVIDENCE_POLL_INTERVAL_SECS").ok() {
            Some(raw) => raw
                .parse::<u64>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_EVIDENCE_POLL_INTERVAL_SECS",
                    source,
                })?,
            None => default_evidence_poll_interval_secs(),
        };
        let max_attempts = match env::var("POLARIS_EVIDENCE_MAX_ATTEMPTS").ok() {
            Some(raw) => raw
                .parse::<u32>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_EVIDENCE_MAX_ATTEMPTS",
                    source,
                })?,
            None => default_evidence_max_attempts(),
        };
        let retry_base_secs = match env::var("POLARIS_EVIDENCE_RETRY_BASE_SECS").ok() {
            Some(raw) => raw
                .parse::<u64>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_EVIDENCE_RETRY_BASE_SECS",
                    source,
                })?,
            None => default_evidence_retry_base_secs(),
        };
        Ok(Self {
            blob_store,
            worker_concurrency,
            poll_interval_secs,
            max_attempts,
            retry_base_secs,
        })
    }
}

/// Blob-store backend selection for the evidence worker (#33).
///
/// See [`crate::evidence::blob_store`] for the trait + per-variant
/// impls.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BlobStoreKind {
    /// In-process `HashMap`-backed store. Default for tests.
    #[default]
    InMemory,
    /// Filesystem store rooted at `root`. Default for the labeler
    /// profile binary.
    LocalFs {
        /// Root directory under which CARs are written
        /// (e.g. `/var/lib/polaris/evidence`).
        root: PathBuf,
    },
    /// S3-compatible bucket. Feature-gated behind `s3-blob-store` at
    /// the consumer crate; constructing the backend requires the
    /// AWS SDK default credential chain to be configured in the
    /// process environment.
    S3 {
        /// Bucket name.
        bucket: String,
        /// Region (e.g. `us-east-2`).
        region: String,
    },
}

/// Reporter-reputation tunables (issue #37, design.md §9.3).
///
/// Operators tune the Bayesian prior and the time-decay half-life to
/// match the volume and noisiness of their deployment. The defaults
/// (1.0, 1.0, 90 days) are the "no strong prior, three-month memory"
/// posture — appropriate for both the labeler and Bluesky profiles
/// out of the box.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct ReputationConfig {
    /// Beta-prior pseudo-count for "actioned" outcomes. Default 1.0.
    ///
    /// Higher values pull a brand-new reporter's score toward 1.0;
    /// lower values (e.g. 0.5) pull toward 0.5. Must be > 0.
    #[serde(default = "default_reputation_prior_actioned")]
    pub prior_actioned: f32,
    /// Beta-prior pseudo-count for "dismissed" outcomes. Default 1.0.
    /// Must be > 0.
    #[serde(default = "default_reputation_prior_dismissed")]
    pub prior_dismissed: f32,
    /// Days after which the decay factor is `e^-1` ≈ 0.368. Default 90.0.
    /// Higher values keep older history more influential; lower values
    /// age it out faster. Must be > 0.
    #[serde(default = "default_reputation_half_life_days")]
    pub half_life_days: f32,
}

const fn default_reputation_prior_actioned() -> f32 {
    1.0
}

const fn default_reputation_prior_dismissed() -> f32 {
    1.0
}

const fn default_reputation_half_life_days() -> f32 {
    90.0
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            prior_actioned: default_reputation_prior_actioned(),
            prior_dismissed: default_reputation_prior_dismissed(),
            half_life_days: default_reputation_half_life_days(),
        }
    }
}

impl ReputationConfig {
    /// Build from environment variables.
    ///
    /// Recognises:
    ///
    /// | Variable                                  | Field             |
    /// |-------------------------------------------|-------------------|
    /// | `POLARIS_REPUTATION_PRIOR_ACTIONED`       | `prior_actioned`  |
    /// | `POLARIS_REPUTATION_PRIOR_DISMISSED`      | `prior_dismissed` |
    /// | `POLARIS_REPUTATION_HALF_LIFE_DAYS`       | `half_life_days`  |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidFloat`] when an override cannot be
    /// parsed as an `f32`, or [`ConfigError::InvalidEnumValue`] when the
    /// parsed value is non-positive (the reputation function rejects
    /// non-positive priors and half-lives — see
    /// [`crate::reputation::PgReputationProvider::new`]).
    pub fn from_env() -> Result<Self, ConfigError> {
        let prior_actioned = parse_positive_f32_env(
            "POLARIS_REPUTATION_PRIOR_ACTIONED",
            default_reputation_prior_actioned(),
        )?;
        let prior_dismissed = parse_positive_f32_env(
            "POLARIS_REPUTATION_PRIOR_DISMISSED",
            default_reputation_prior_dismissed(),
        )?;
        let half_life_days = parse_positive_f32_env(
            "POLARIS_REPUTATION_HALF_LIFE_DAYS",
            default_reputation_half_life_days(),
        )?;
        Ok(Self {
            prior_actioned,
            prior_dismissed,
            half_life_days,
        })
    }
}

/// Moderator-behavior-anomaly detector configuration (#73).
///
/// Drives [`crate::pattern::moderator_anomaly::check_and_emit`] from the
/// action-insert path. The threshold is the maximum action count the
/// detector tolerates inside the rolling window; counts strictly above
/// the threshold fire a
/// [`polaris_types::ObservationKind::ModeratorBehaviorAnomaly`].
///
/// The wire form mirrors the `from_env` precedence rules — both fields
/// fall back to the architect's pre-flight defaults (50 actions, 3600
/// seconds) when unset, so a stock binary boots with the T1 detector
/// active.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModeratorAnomalyEnvConfig {
    /// Emit when the moderator's action count in the rolling window
    /// strictly exceeds this value. Default 50.
    #[serde(default = "default_moderator_anomaly_threshold")]
    pub threshold: u32,
    /// Rolling-window size in seconds. Default 3600 (one hour).
    #[serde(default = "default_moderator_anomaly_window_secs")]
    pub window_secs: u32,
}

const fn default_moderator_anomaly_threshold() -> u32 {
    50
}

const fn default_moderator_anomaly_window_secs() -> u32 {
    3600
}

impl Default for ModeratorAnomalyEnvConfig {
    fn default() -> Self {
        Self {
            threshold: default_moderator_anomaly_threshold(),
            window_secs: default_moderator_anomaly_window_secs(),
        }
    }
}

impl ModeratorAnomalyEnvConfig {
    /// Build from environment variables.
    ///
    /// Recognises:
    ///
    /// | Variable                                  | Field        |
    /// |-------------------------------------------|--------------|
    /// | `POLARIS_MODERATOR_ANOMALY_THRESHOLD`     | `threshold`  |
    /// | `POLARIS_MODERATOR_ANOMALY_WINDOW_SECS`   | `window_secs`|
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInt`] when either env value cannot
    /// be parsed as a `u32`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let threshold = match env::var("POLARIS_MODERATOR_ANOMALY_THRESHOLD").ok() {
            Some(raw) => raw
                .parse::<u32>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_MODERATOR_ANOMALY_THRESHOLD",
                    source,
                })?,
            None => default_moderator_anomaly_threshold(),
        };
        let window_secs = match env::var("POLARIS_MODERATOR_ANOMALY_WINDOW_SECS").ok() {
            Some(raw) => raw
                .parse::<u32>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_MODERATOR_ANOMALY_WINDOW_SECS",
                    source,
                })?,
            None => default_moderator_anomaly_window_secs(),
        };
        Ok(Self {
            threshold,
            window_secs,
        })
    }
}

/// Report-aggregator worker configuration (#75, design.md §9 #4).
///
/// Drives [`crate::ingest::ReportAggregator`] at startup: the per-tick
/// batch size, the idle poll interval, and the "attach to existing
/// incident" window. The defaults mirror the constants exposed by the
/// [`crate::ingest::aggregator`] module so the env-form contract reads
/// the same value an operator would see in `cargo doc`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregatorEnvConfig {
    /// Maximum number of un-aggregated reports to claim per tick.
    /// Defaults to [`crate::ingest::DEFAULT_BATCH_SIZE`] (= 256).
    #[serde(default = "default_aggregator_batch_size")]
    pub batch_size: i64,
    /// Idle wait between drain ticks, in seconds. Defaults to
    /// [`crate::ingest::DEFAULT_POLL_INTERVAL_SECS`] (= 5).
    #[serde(default = "default_aggregator_poll_interval_secs")]
    pub poll_interval_secs: u64,
    /// Width of the "attach to existing incident" window in seconds.
    /// Defaults to [`crate::ingest::DEFAULT_WINDOW_SECS`] (= `86_400`).
    #[serde(default = "default_aggregator_window_secs")]
    pub window_secs: i64,
}

const fn default_aggregator_batch_size() -> i64 {
    crate::ingest::DEFAULT_BATCH_SIZE
}

const fn default_aggregator_poll_interval_secs() -> u64 {
    crate::ingest::DEFAULT_POLL_INTERVAL_SECS
}

const fn default_aggregator_window_secs() -> i64 {
    crate::ingest::DEFAULT_WINDOW_SECS
}

impl Default for AggregatorEnvConfig {
    fn default() -> Self {
        Self {
            batch_size: default_aggregator_batch_size(),
            poll_interval_secs: default_aggregator_poll_interval_secs(),
            window_secs: default_aggregator_window_secs(),
        }
    }
}

impl AggregatorEnvConfig {
    /// Build from environment variables.
    ///
    /// Recognises:
    ///
    /// | Variable                              | Field                |
    /// |---------------------------------------|----------------------|
    /// | `POLARIS_AGGREGATOR_BATCH_SIZE`       | `batch_size`         |
    /// | `POLARIS_AGGREGATOR_POLL_INTERVAL_SECS` | `poll_interval_secs` |
    /// | `POLARIS_AGGREGATOR_WINDOW_SECS`      | `window_secs`        |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidInt`] when any override cannot be
    /// parsed as the documented integer type.
    pub fn from_env() -> Result<Self, ConfigError> {
        let batch_size = match env::var("POLARIS_AGGREGATOR_BATCH_SIZE").ok() {
            Some(raw) => raw
                .parse::<i64>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_AGGREGATOR_BATCH_SIZE",
                    source,
                })?,
            None => default_aggregator_batch_size(),
        };
        let poll_interval_secs = match env::var("POLARIS_AGGREGATOR_POLL_INTERVAL_SECS").ok() {
            Some(raw) => raw
                .parse::<u64>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_AGGREGATOR_POLL_INTERVAL_SECS",
                    source,
                })?,
            None => default_aggregator_poll_interval_secs(),
        };
        let window_secs = match env::var("POLARIS_AGGREGATOR_WINDOW_SECS").ok() {
            Some(raw) => raw
                .parse::<i64>()
                .map_err(|source| ConfigError::InvalidInt {
                    field: "POLARIS_AGGREGATOR_WINDOW_SECS",
                    source,
                })?,
            None => default_aggregator_window_secs(),
        };
        Ok(Self {
            batch_size,
            poll_interval_secs,
            window_secs,
        })
    }
}

/// Parse a positive-`f32` env override, falling back to `default` when unset.
///
/// Rejects non-finite (NaN / inf) and non-positive values via
/// [`ConfigError::InvalidEnumValue`]. The "enum" framing is intentional:
/// the accepted set is "any finite positive number", which is what the
/// operator-facing diagnostic should say.
fn parse_positive_f32_env(var: &'static str, default: f32) -> Result<f32, ConfigError> {
    let Some(raw) = env::var(var).ok() else {
        return Ok(default);
    };
    let parsed: f32 = raw.parse().map_err(|_| ConfigError::InvalidEnumValue {
        field: var,
        value: raw.clone(),
        accepted: &["a positive finite f32 (e.g. 1.0, 90.0)"],
    })?;
    if !parsed.is_finite() || parsed <= 0.0 {
        return Err(ConfigError::InvalidEnumValue {
            field: var,
            value: raw,
            accepted: &["a positive finite f32 (e.g. 1.0, 90.0)"],
        });
    }
    Ok(parsed)
}

// ── federation config ─────────────────────────────────────────────────────

/// Cross-instance federation settings (issue #107 / M5 PR 1).
///
/// Controls whether the Polaris instance subscribes to peer Polaris instances'
/// Firehose streams and materialises incoming records into `federation_quarantine`.
///
/// Env-var mapping:
///
/// | Variable                              | Field                    |
/// |---------------------------------------|--------------------------|
/// | `POLARIS_FEDERATION_ENABLED`          | `enabled` (bool)         |
/// | `POLARIS_FEDERATION_KEY_CACHE_TTL_SECS` | `public_key_cache_ttl_secs` |
///
/// Individual peers are configured via `POLARIS_FEDERATION_PEERS`, a
/// comma-separated list of `<did>@<pds_host>` pairs (e.g.
/// `did:plc:peerA@pds.example.com,did:plc:peerB@pds.other.com`). The optional
/// `+direction` suffix selects the replication direction:
/// `bidirectional` (default), `incoming-only`, `outgoing-only`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    /// Whether the federation worker is enabled. Default `false`.
    ///
    /// All other fields are ignored when this is `false`.
    #[serde(default)]
    pub enabled: bool,

    /// Seconds to keep a peer's signing-key `did:key` in the in-process
    /// cache before re-fetching from the peer's PLC document. Default
    /// 21,600 (6 hours) — matches Bluesky's stated PLC TTL conventions.
    #[serde(default = "default_federation_key_cache_ttl_secs")]
    pub public_key_cache_ttl_secs: u64,

    /// Configured peers. Populated from `POLARIS_FEDERATION_PEERS`; the
    /// default is empty (no federation).
    #[serde(default)]
    pub peers: Vec<PeerConfig>,
}

const fn default_federation_key_cache_ttl_secs() -> u64 {
    21_600 // 6 hours
}

impl Default for FederationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            public_key_cache_ttl_secs: default_federation_key_cache_ttl_secs(),
            peers: vec![],
        }
    }
}

impl FederationConfig {
    /// Build from environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::InvalidEnumValue`] if a peer entry's direction
    /// token is not one of the accepted values, or [`ConfigError::InvalidInt`]
    /// if `POLARIS_FEDERATION_KEY_CACHE_TTL_SECS` is not a valid `u64`.
    pub fn from_env() -> Result<Self, ConfigError> {
        let enabled = parse_optional_bool_env("POLARIS_FEDERATION_ENABLED")?.unwrap_or(false);

        let public_key_cache_ttl_secs =
            match env::var("POLARIS_FEDERATION_KEY_CACHE_TTL_SECS").ok() {
                Some(raw) => raw
                    .parse::<u64>()
                    .map_err(|source| ConfigError::InvalidInt {
                        field: "POLARIS_FEDERATION_KEY_CACHE_TTL_SECS",
                        source,
                    })?,
                None => default_federation_key_cache_ttl_secs(),
            };

        let peers = parse_federation_peers_env()?;

        Ok(Self {
            enabled,
            public_key_cache_ttl_secs,
            peers,
        })
    }
}

/// Parse `POLARIS_FEDERATION_PEERS` into a `Vec<PeerConfig>`.
///
/// Format: comma-separated `<did>@<pds_host>` pairs with an optional
/// `+<direction>` suffix. Example:
/// ```text
/// did:plc:peerA@pds.example.com+bidirectional,did:plc:peerB@pds.other.com
/// ```
///
/// Unknown direction tokens are rejected with [`ConfigError::InvalidEnumValue`].
fn parse_federation_peers_env() -> Result<Vec<PeerConfig>, ConfigError> {
    let raw = match env::var("POLARIS_FEDERATION_PEERS").ok() {
        Some(r) if !r.trim().is_empty() => r,
        _ => return Ok(vec![]),
    };

    raw.split(',')
        .map(|entry| {
            let entry = entry.trim();
            // Split off optional `+direction` suffix.
            let (at_part, direction_str) = if let Some((left, right)) = entry.split_once('+') {
                (left, right)
            } else {
                (entry, "bidirectional")
            };

            // Split DID and PDS host on `@`.
            let (did, pds_host) = at_part.split_once('@').ok_or(ConfigError::InvalidEnumValue {
                field: "POLARIS_FEDERATION_PEERS",
                value: entry.to_owned(),
                accepted: &["<did>@<pds_host>[+direction]"],
            })?;

            let direction = match direction_str {
                "bidirectional" => FederationDirection::Bidirectional,
                "incoming-only" => FederationDirection::IncomingOnly,
                "outgoing-only" => FederationDirection::OutgoingOnly,
                other => {
                    return Err(ConfigError::InvalidEnumValue {
                        field: "POLARIS_FEDERATION_PEERS direction",
                        value: other.to_owned(),
                        accepted: &["bidirectional", "incoming-only", "outgoing-only"],
                    });
                }
            };

            Ok(PeerConfig {
                did: did.to_owned(),
                pds_host: pds_host.to_owned(),
                direction,
            })
        })
        .collect()
}

/// Peer replication direction.
///
/// Controls which data flows:
///
/// - [`Bidirectional`](Self::Bidirectional) — this instance subscribes to the
///   peer's Firehose AND (when outbound federation lands in PR 3) publishes to
///   the peer.
/// - [`IncomingOnly`](Self::IncomingOnly) — this instance only reads from the peer.
/// - [`OutgoingOnly`](Self::OutgoingOnly) — this instance only publishes to the
///   peer (reserved for PR 3; no inbound subscription is spawned).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FederationDirection {
    /// Subscribe to the peer and publish to the peer.
    #[default]
    Bidirectional,
    /// Subscribe to the peer only.
    IncomingOnly,
    /// Publish to the peer only (reserved for PR 3).
    OutgoingOnly,
}

/// One configured federation peer.
///
/// Constructed from `POLARIS_FEDERATION_PEERS` (env) or from a future
/// `[[federation_peers]]` TOML table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// The peer's DID (e.g. `did:plc:peerA`).
    pub did: String,
    /// The bare hostname of the peer's PDS (no scheme, no path;
    /// e.g. `pds.example.com`). Used to build the `wss://` URL.
    pub pds_host: String,
    /// Replication direction. Default [`FederationDirection::Bidirectional`].
    #[serde(default)]
    pub direction: FederationDirection,
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

    #[test]
    fn defaults_are_stable() {
        let cfg = AppConfig::default();
        assert_eq!(
            cfg.db.url,
            "postgres://polaris:polaris@localhost:5432/polaris"
        );
        assert_eq!(cfg.db.max_connections, 16);
        assert_eq!(cfg.db.min_connections, 1);
        assert_eq!(cfg.db.acquire_timeout_secs, 5);
        assert_eq!(cfg.http.bind, "127.0.0.1:8080");
        // Issue #29: the default profile is `labeler` and the default
        // signing-key mode is `file-plain` — matching Ozone's
        // posture, which the design document explicitly chose to
        // preserve onboarding velocity.
        assert_eq!(cfg.profile, Profile::Labeler);
        assert!(matches!(
            cfg.labeler.signing_key,
            LabelerSigningKeyConfig::FilePlain { .. }
        ));
    }

    #[test]
    fn labeler_signing_key_config_serde_tags_on_mode() {
        // The TOML/JSON contract is `mode = "file-plain"` etc.; assert
        // that the kebab-case + tag-on-`mode` derivation matches.
        let v = LabelerSigningKeyConfig::OsKeychain {
            account: "ops@example.com".to_owned(),
        };
        let json = serde_json::to_value(&v).unwrap_or_else(|e| panic!("serialise: {e}"));
        assert_eq!(json["mode"], "os-keychain");
        assert_eq!(json["account"], "ops@example.com");
    }

    #[test]
    fn labeler_signing_key_config_deserialises_each_mode() {
        let cases = [
            (r#"{"mode":"file-plain","path":"/tmp/x"}"#, "FilePlain"),
            (
                r#"{"mode":"passphrase-sealed","path":"/tmp/x"}"#,
                "PassphraseSealed",
            ),
            (r#"{"mode":"os-keychain","account":"acct"}"#, "OsKeychain"),
            (
                r#"{"mode":"cloud-kms-oracle","provider":"aws","key_id":"k","region":"r"}"#,
                "CloudKms",
            ),
        ];
        for (json, label) in cases {
            let v: LabelerSigningKeyConfig =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{label}: {e}"));
            let dbg = format!("{v:?}");
            assert!(dbg.contains(label), "{label} did not round-trip: {dbg}");
        }
    }

    #[test]
    fn defaults_helpers_are_plain_values() {
        // `from_env` interaction is exercised in the integration tests under
        // `tests/`. Unit-testing it here would require mutating process-wide
        // env, which (a) became `unsafe fn` in Rust 1.84+ and is denied by
        // the workspace lint, and (b) races other tests in parallel runs.
        // Instead we lock down the helper functions so an accidental default
        // change shows up as a deliberate edit to this test.
        assert_eq!(default_max_connections(), 16);
        assert_eq!(default_min_connections(), 1);
        assert_eq!(default_acquire_timeout_secs(), 5);
        assert_eq!(default_http_bind(), "127.0.0.1:8080");
    }
}
