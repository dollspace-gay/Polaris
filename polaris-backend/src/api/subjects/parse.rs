//! Identifier parser for `POST /api/subjects/lookup` (issue #92).
//!
//! Pure function that classifies a moderator-supplied identifier into
//! one of four typed shapes:
//!
//! 1. [`ParsedIdentifier::Did`] — bare DID (`did:plc:...` /
//!    `did:web:...`). Account kind by construction; no resolution
//!    needed.
//! 2. [`ParsedIdentifier::AtUriWithDid`] — AT-URI whose authority is
//!    already a DID. Post kind by construction; no resolution needed.
//! 3. [`ParsedIdentifier::AtUriWithHandle`] — AT-URI whose authority
//!    is a handle. Post kind; the caller must resolve the handle to a
//!    DID before synthesising the canonical AT-URI.
//! 4. [`ParsedIdentifier::BskyAppProfile`] — `https://bsky.app/profile/<who>`
//!    (account kind) or `https://bsky.app/profile/<who>/post/<rkey>`
//!    (post kind). The `who` segment may be a handle OR a DID; the
//!    caller resolves the handle case via the identity resolver.
//! 5. [`ParsedIdentifier::BareHandle`] — a hostname-shaped handle
//!    (`alice.bsky.social`). Account kind; resolution required.
//!
//! Every parse runs through [`url::Url::parse`] for the URL forms — no
//! regex. The handle / DID shape checks are explicit pattern matches
//! against the prefix or `.`-containing-substring heuristic.
//!
//! # Forbidden patterns enforced here
//!
//! - No `unwrap()` / `expect()` on the parsing path. The function is a
//!   pure `Result<ParsedIdentifier, ParseError>`; the only panic
//!   sites are inside `#[cfg(test)]`.
//! - No `String::from_utf8_lossy` — the input is `&str` and arrives
//!   through JSON deserialisation, which guarantees valid UTF-8.
//! - No regex for URL parsing — `url::Url::parse` is the one path.

use url::Url;

/// Maximum identifier length accepted by the parser.
///
/// 2048 bytes is the conservative URL-length ceiling (matches the
/// historical IE URL limit and is well above any reasonable AT-URI or
/// `did:web:` form). Rejecting longer inputs caps the work the
/// downstream handle resolver does and gives operators a tractable
/// upper bound on log-line size.
pub const MAX_IDENTIFIER_LEN: usize = 2048;

/// Outcome of identifier parsing.
///
/// Each variant carries the typed payload the caller needs to drive
/// the next step (DID lookup, handle→DID resolution, AT-URI lookup).
/// The caller never re-parses the original string — the parser owns
/// the URL / scheme classification once and hands typed values out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsedIdentifier {
    /// A bare DID. Always an account kind.
    Did {
        /// The DID itself (`did:plc:...` or `did:web:...`).
        did: String,
    },
    /// An AT-URI whose authority component is already a DID.
    AtUriWithDid {
        /// The authority component (e.g. `did:plc:abc`).
        did: String,
        /// Collection NSID (e.g. `app.bsky.feed.post`). May be empty
        /// if the moderator pasted a bare `at://did:plc:abc` form.
        collection: String,
        /// Record key, when present in the URI tail.
        rkey: Option<String>,
    },
    /// An AT-URI whose authority component is a handle (the caller
    /// must resolve to a DID before synthesising the canonical
    /// `at://did:plc:.../<collection>/<rkey>` form).
    AtUriWithHandle {
        /// The handle authority (e.g. `alice.bsky.social`).
        handle: String,
        /// Collection NSID.
        collection: String,
        /// Record key, when present in the URI tail.
        rkey: Option<String>,
    },
    /// A `https://bsky.app/profile/<who>` URL.
    BskyAppProfile {
        /// The `<who>` segment after `/profile/` — either a handle or
        /// a DID. The caller branches on [`identity_is_did`] to skip
        /// the handle resolver.
        who: String,
        /// `Some(<rkey>)` when the URL had a `/post/<rkey>` tail;
        /// `None` for a bare profile URL.
        post_rkey: Option<String>,
    },
    /// A bare handle (e.g. `alice.bsky.social`). Always an account
    /// kind; the caller must resolve to a DID.
    BareHandle {
        /// The handle string.
        handle: String,
    },
}

/// Quick check: does the supplied identity segment look like a DID?
///
/// `did:plc:...`, `did:web:...`, or any future method form. The check
/// is a strict prefix match — anything that doesn't start with `did:`
/// is treated as a handle by [`ParsedIdentifier::BskyAppProfile`]
/// consumers.
#[must_use]
pub fn identity_is_did(segment: &str) -> bool {
    segment.starts_with("did:")
}

/// Parse errors surfaced as `400 malformed_identifier` at the HTTP
/// layer.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Empty or whitespace-only input.
    #[error("identifier is empty")]
    Empty,
    /// Input length exceeds [`MAX_IDENTIFIER_LEN`].
    #[error("identifier exceeds maximum length of {max} bytes")]
    TooLong {
        /// The configured length cap that was tripped.
        max: usize,
    },
    /// Could not classify as DID, AT-URI, `bsky.app` URL, or handle.
    #[error("identifier does not match any known shape")]
    Unrecognised,
    /// AT-URI authority segment is empty or missing.
    #[error("AT-URI is missing its authority segment")]
    AtUriMissingAuthority,
    /// AT-URI authority is neither a DID nor a handle.
    #[error("AT-URI authority is not a DID or handle")]
    AtUriInvalidAuthority,
    /// `https://bsky.app/profile/...` path is malformed.
    #[error("bsky.app URL is missing the profile segment")]
    BskyAppMissingProfile,
    /// URL host other than `bsky.app` rejected (we don't resolve
    /// arbitrary upstream hosts via this endpoint).
    #[error("https URL host must be bsky.app")]
    UnsupportedHost,
}

/// Classify the supplied identifier.
///
/// The dispatch is a single-pass match on the input's leading shape:
/// `did:` prefix → DID; `at://` prefix → AT-URI; `https://` prefix →
/// URL parse with `bsky.app`-only host gate; otherwise → bare handle.
///
/// # Errors
///
/// Returns [`ParseError`] when the input is empty, oversized, or does
/// not match any of the supported shapes. The handler maps every
/// variant to the same `400 malformed_identifier` wire response — the
/// granular shape is preserved for log lines.
pub fn parse_identifier(raw: &str) -> Result<ParsedIdentifier, ParseError> {
    // Strip leading + trailing whitespace; an empty result after the
    // trim is the empty-input failure. The trim is the only
    // normalisation we apply — we do NOT lower-case (DIDs are
    // case-sensitive after the `did:method:` prefix per the spec).
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ParseError::Empty);
    }
    if trimmed.len() > MAX_IDENTIFIER_LEN {
        return Err(ParseError::TooLong {
            max: MAX_IDENTIFIER_LEN,
        });
    }

    // Strip a trailing slash so `did:plc:abc/` and bare handles like
    // `alice.bsky.social/` parse identically to their no-slash form.
    let normalized = trimmed.trim_end_matches('/');

    if identity_is_did(normalized) {
        // The DID syntax check is intentionally minimal here: the
        // parser only verifies the `did:` prefix is present. The
        // handler hands the value through to `polaris_types::Did`,
        // which is a string newtype; the downstream PLC resolver
        // catches malformed DIDs at resolve time when the row does
        // not already exist.
        return Ok(ParsedIdentifier::Did {
            did: normalized.to_owned(),
        });
    }

    if let Some(at_uri_tail) = normalized.strip_prefix("at://") {
        return parse_at_uri_tail(at_uri_tail);
    }

    if normalized.starts_with("http://") || normalized.starts_with("https://") {
        return parse_https_url(normalized);
    }

    // Bare-handle fallback. We accept anything that contains at least
    // one `.` and no whitespace; the upstream identity resolver
    // applies the full atproto handle syntax check at resolve time.
    if is_handle_shaped(normalized) {
        return Ok(ParsedIdentifier::BareHandle {
            handle: normalized.to_owned(),
        });
    }

    Err(ParseError::Unrecognised)
}

/// Parse the body of an `at://<authority>/<collection>/<rkey>` AT-URI,
/// having already stripped the `at://` prefix.
fn parse_at_uri_tail(tail: &str) -> Result<ParsedIdentifier, ParseError> {
    // Split off any URL-style fragment or query — AT-URIs do not carry
    // either in practice, but a moderator paste may include one (e.g.
    // copied from a deep link). The fragment / query is dropped, not
    // an error: the canonical AT-URI we store excludes both.
    let no_fragment = tail.split('#').next().unwrap_or(tail);
    let no_query = no_fragment.split('?').next().unwrap_or(no_fragment);

    let mut segments = no_query.splitn(3, '/');
    let authority = segments.next().unwrap_or_default();
    if authority.is_empty() {
        return Err(ParseError::AtUriMissingAuthority);
    }
    let collection = segments.next().unwrap_or_default().to_owned();
    let rkey = segments
        .next()
        .map(|s| s.trim_end_matches('/'))
        .filter(|s| !s.is_empty())
        .map(str::to_owned);

    if identity_is_did(authority) {
        Ok(ParsedIdentifier::AtUriWithDid {
            did: authority.to_owned(),
            collection,
            rkey,
        })
    } else if is_handle_shaped(authority) {
        Ok(ParsedIdentifier::AtUriWithHandle {
            handle: authority.to_owned(),
            collection,
            rkey,
        })
    } else {
        Err(ParseError::AtUriInvalidAuthority)
    }
}

/// Parse a `https://bsky.app/profile/<who>[/post/<rkey>]` URL.
fn parse_https_url(raw: &str) -> Result<ParsedIdentifier, ParseError> {
    let url = Url::parse(raw).map_err(|_| ParseError::Unrecognised)?;
    let host = url.host_str().ok_or(ParseError::UnsupportedHost)?;
    if host != "bsky.app" {
        return Err(ParseError::UnsupportedHost);
    }
    // `path_segments()` returns `None` for cannot-be-a-base URLs only;
    // `https://bsky.app/...` is always base-able, so the closure path
    // is reached.
    let mut segments = url
        .path_segments()
        .ok_or(ParseError::BskyAppMissingProfile)?
        .filter(|s| !s.is_empty());

    let first = segments.next().ok_or(ParseError::BskyAppMissingProfile)?;
    if first != "profile" {
        return Err(ParseError::BskyAppMissingProfile);
    }
    let who = segments
        .next()
        .ok_or(ParseError::BskyAppMissingProfile)?
        .to_owned();
    if who.is_empty() {
        return Err(ParseError::BskyAppMissingProfile);
    }

    // Optional `post/<rkey>` tail. Anything other than `post/<rkey>`
    // tail is rejected to keep the surface tight; future expansion
    // (lists, feeds) lands as explicit additional matches.
    let post_rkey = match segments.next() {
        None => None,
        Some("post") => {
            let rkey = segments
                .next()
                .ok_or(ParseError::BskyAppMissingProfile)?
                .to_owned();
            if rkey.is_empty() {
                return Err(ParseError::BskyAppMissingProfile);
            }
            Some(rkey)
        }
        Some(_) => {
            // An unknown second segment ("feed", "list", …) lands here.
            // Treat as unrecognised so the parser surface stays narrow
            // to what the case-page renderer actually supports today.
            return Err(ParseError::Unrecognised);
        }
    };

    Ok(ParsedIdentifier::BskyAppProfile { who, post_rkey })
}

/// Is `s` shaped like a handle? Conservative: must contain a `.`,
/// must contain no whitespace, must be non-empty.
///
/// The upstream identity resolver applies the full atproto handle
/// syntax check; this is a parser-side gate that distinguishes
/// "definitely garbage" from "plausibly a handle, defer to resolver".
fn is_handle_shaped(s: &str) -> bool {
    !s.is_empty()
        && s.contains('.')
        && !s.chars().any(char::is_whitespace)
        && !s.starts_with('.')
        && !s.ends_with('.')
}

/// Build the canonical AT-URI string from a DID + collection + rkey.
///
/// Used by the handler to normalise an [`AtUriWithHandle`] into the
/// `at://did:plc:.../<collection>/<rkey>` form persisted in
/// `subjects.uri` AND to synthesise the AT-URI for a
/// `https://bsky.app/profile/<who>/post/<rkey>` post.
///
/// [`AtUriWithHandle`]: ParsedIdentifier::AtUriWithHandle
#[must_use]
pub fn build_at_uri(did: &str, collection: &str, rkey: &str) -> String {
    format!("at://{did}/{collection}/{rkey}")
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
    fn parses_bare_did_plc() {
        let got = parse_identifier("did:plc:abc123").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::Did {
                did: "did:plc:abc123".to_owned()
            }
        );
    }

    #[test]
    fn parses_bare_did_web() {
        let got = parse_identifier("did:web:example.com").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::Did {
                did: "did:web:example.com".to_owned()
            }
        );
    }

    #[test]
    fn parses_at_uri_with_did() {
        let got = parse_identifier("at://did:plc:abc/app.bsky.feed.post/3lxyz").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::AtUriWithDid {
                did: "did:plc:abc".to_owned(),
                collection: "app.bsky.feed.post".to_owned(),
                rkey: Some("3lxyz".to_owned()),
            }
        );
    }

    #[test]
    fn parses_at_uri_with_handle() {
        let got = parse_identifier("at://alice.bsky.social/app.bsky.feed.post/3lxyz").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::AtUriWithHandle {
                handle: "alice.bsky.social".to_owned(),
                collection: "app.bsky.feed.post".to_owned(),
                rkey: Some("3lxyz".to_owned()),
            }
        );
    }

    #[test]
    fn parses_bsky_app_profile_account() {
        let got = parse_identifier("https://bsky.app/profile/alice.bsky.social").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::BskyAppProfile {
                who: "alice.bsky.social".to_owned(),
                post_rkey: None,
            }
        );
    }

    #[test]
    fn parses_bsky_app_profile_post() {
        let got =
            parse_identifier("https://bsky.app/profile/alice.bsky.social/post/3lxyz").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::BskyAppProfile {
                who: "alice.bsky.social".to_owned(),
                post_rkey: Some("3lxyz".to_owned()),
            }
        );
    }

    #[test]
    fn parses_bsky_app_profile_did() {
        let got = parse_identifier("https://bsky.app/profile/did:plc:abc").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::BskyAppProfile {
                who: "did:plc:abc".to_owned(),
                post_rkey: None,
            }
        );
    }

    #[test]
    fn parses_bare_handle() {
        let got = parse_identifier("alice.bsky.social").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::BareHandle {
                handle: "alice.bsky.social".to_owned()
            }
        );
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn trims_leading_and_trailing_whitespace() {
        let got = parse_identifier("   did:plc:abc   ").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::Did {
                did: "did:plc:abc".to_owned()
            }
        );
    }

    #[test]
    fn strips_trailing_slash_on_bare_handle() {
        let got = parse_identifier("alice.bsky.social/").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::BareHandle {
                handle: "alice.bsky.social".to_owned()
            }
        );
    }

    #[test]
    fn strips_query_string_on_at_uri() {
        let got = parse_identifier("at://did:plc:abc/app.bsky.feed.post/3lxyz?foo=bar").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::AtUriWithDid {
                did: "did:plc:abc".to_owned(),
                collection: "app.bsky.feed.post".to_owned(),
                rkey: Some("3lxyz".to_owned()),
            }
        );
    }

    #[test]
    fn strips_fragment_on_at_uri() {
        let got = parse_identifier("at://did:plc:abc/app.bsky.feed.post/3lxyz#section").unwrap();
        assert_eq!(
            got,
            ParsedIdentifier::AtUriWithDid {
                did: "did:plc:abc".to_owned(),
                collection: "app.bsky.feed.post".to_owned(),
                rkey: Some("3lxyz".to_owned()),
            }
        );
    }

    #[test]
    fn empty_input_is_rejected() {
        assert_eq!(parse_identifier(""), Err(ParseError::Empty));
        assert_eq!(parse_identifier("   "), Err(ParseError::Empty));
    }

    #[test]
    fn oversized_input_is_rejected() {
        let big = "a".repeat(MAX_IDENTIFIER_LEN + 1);
        assert!(matches!(
            parse_identifier(&big),
            Err(ParseError::TooLong { .. })
        ));
    }

    #[test]
    fn non_bsky_app_https_url_is_rejected() {
        assert_eq!(
            parse_identifier("https://twitter.com/alice"),
            Err(ParseError::UnsupportedHost),
        );
    }

    #[test]
    fn unrecognised_garbage_is_rejected() {
        // No `.` -> not handle-shaped; no `did:` -> not a DID; no
        // recognised URL form. Falls through to Unrecognised.
        assert_eq!(parse_identifier("hello"), Err(ParseError::Unrecognised));
    }

    #[test]
    fn whitespace_inside_handle_is_rejected() {
        assert_eq!(
            parse_identifier("alice .bsky.social"),
            Err(ParseError::Unrecognised),
        );
    }

    #[test]
    fn bsky_app_url_with_no_profile_segment_rejected() {
        assert_eq!(
            parse_identifier("https://bsky.app/"),
            Err(ParseError::BskyAppMissingProfile),
        );
    }

    #[test]
    fn bsky_app_url_with_unknown_tail_rejected() {
        assert_eq!(
            parse_identifier("https://bsky.app/profile/alice.bsky.social/feed/whats-hot"),
            Err(ParseError::Unrecognised),
        );
    }

    #[test]
    fn at_uri_without_authority_rejected() {
        assert_eq!(
            parse_identifier("at:///app.bsky.feed.post/3lxyz"),
            Err(ParseError::AtUriMissingAuthority),
        );
    }

    #[test]
    fn build_at_uri_round_trips() {
        let s = build_at_uri("did:plc:abc", "app.bsky.feed.post", "3lxyz");
        assert_eq!(s, "at://did:plc:abc/app.bsky.feed.post/3lxyz");
    }

    #[test]
    fn identity_is_did_classifier() {
        assert!(identity_is_did("did:plc:abc"));
        assert!(identity_is_did("did:web:example.com"));
        assert!(!identity_is_did("alice.bsky.social"));
        assert!(!identity_is_did(""));
    }
}
