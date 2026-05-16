//! Identifier newtypes.
//!
//! Every entity in the §4 data model carries a typed UUID newtype rather than
//! a raw [`uuid::Uuid`]. This prevents the common bug class of passing an
//! `IncidentId` where a `SubjectId` is expected — the compiler catches the
//! mistake at the call site.
//!
//! All ID types share an identical surface:
//!
//! - `new()` mints a fresh `v4` UUID.
//! - `Default` delegates to `new()` so `T::default()` is always a fresh id.
//! - `Display` forwards to the wrapped `Uuid`'s canonical hyphenated form.
//! - `Copy` is implemented because UUIDs are 16 bytes; passing them by value
//!   is at least as cheap as borrowing.
//! - `serde::{Serialize, Deserialize}` use `#[serde(transparent)]` so the
//!   wire form is the bare UUID string (matching the §4 design).
//!
//! `Did` and `AtUri` are *string* newtypes — Polaris does not parse them at
//! this layer. The `proto-blue` typed versions live in `polaris-backend`;
//! `polaris-types` deliberately keeps the AC-8 invariant clean (no proto-blue
//! dependency).

use uuid::Uuid;

/// Macro that defines a UUID newtype with the standard surface documented at
/// the module level.
///
/// Defined as a `macro_rules!` rather than a generic struct because each ID
/// type needs to be a distinct nominal type at the compiler level — a generic
/// `Id<Subject>` would still permit accidental cross-type comparison via the
/// blanket `PartialEq` impl. Distinct named types give every call site
/// type-checked safety.
macro_rules! define_uuid_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            Copy,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            /// Mint a fresh v4 UUID-backed id.
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Borrow the inner [`Uuid`].
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Consume the id and return the inner [`Uuid`].
            #[must_use]
            pub const fn into_uuid(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl From<Uuid> for $name {
            fn from(value: Uuid) -> Self {
                Self(value)
            }
        }

        impl From<$name> for Uuid {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

define_uuid_id!(
    /// Identifier for a [`crate::subject::Subject`].
    SubjectId
);
define_uuid_id!(
    /// Identifier for a [`crate::incident::Incident`].
    IncidentId
);
define_uuid_id!(
    /// Identifier for an [`crate::action::Action`].
    ActionId
);
define_uuid_id!(
    /// Identifier for a [`crate::report::Report`].
    ReportId
);
define_uuid_id!(
    /// Identifier for an [`crate::observation::Observation`].
    ObservationId
);
define_uuid_id!(
    /// Identifier for a moderator. The `moderators` row id is the source of
    /// truth; this newtype exists so handlers and repos can carry the value
    /// without dragging in any auth-backend-specific type.
    ModeratorId
);
define_uuid_id!(
    /// Identifier for an [`crate::escalation::Escalation`] (issue #103 / M5 PR 3).
    ///
    /// An escalation is a cross-instance federation record: one Polaris instance
    /// sends an escalation to a peer instance carrying the safe-to-federate subset
    /// of an incident's pattern evidence. The `EscalationId` is the internal
    /// primary key; it is DROPPED at the to-wire boundary (never federated).
    EscalationId
);
define_uuid_id!(
    /// Identifier for a `pattern_actions` row (issue #21).
    ///
    /// Pattern actions are the bulk-on-pattern endpoint (design.md §5.3) —
    /// a moderator selects a pattern (image-hash cluster, account cohort,
    /// anomaly bucket) and an action template; the system materialises one
    /// per-subject `Action` row inside a single transaction. The
    /// `PatternActionId` is the header row's PK and is referenced by the
    /// `pattern_action_signatures` co-sign rows and the
    /// `pattern_action_subjects` join rows.
    PatternActionId
);

/// An ATProto DID (e.g. `did:plc:xxxx`).
///
/// String-typed at this layer — `polaris-types` does not parse DIDs. The
/// `proto-blue`-backed parser lives in `polaris-backend`, which can construct
/// a `Did` from its typed form via the `From<String>` impl when persisting.
///
/// # AC-8 invariant
///
/// Keeping `Did` as a string newtype is what lets `polaris-types` stay
/// `proto-blue`-free. Backend code converts to/from the typed `proto_blue`
/// representation at its own boundary.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct Did(pub String);

impl Did {
    /// Construct a `Did` from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<String> for Did {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for Did {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// An AT-URI (e.g. `at://did:plc:xxxx/app.bsky.feed.post/3l...`).
///
/// String-typed at this layer for the same reason as [`Did`].
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct AtUri(pub String);

impl AtUri {
    /// Construct an `AtUri` from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AtUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<String> for AtUri {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for AtUri {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// Opaque policy reference (e.g. `community-guidelines.harassment.v3`).
///
/// Stored as a string at this layer; the policy registry (and its
/// resolution rules) live outside `polaris-types`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct PolicyId(pub String);

impl PolicyId {
    /// Construct a `PolicyId` from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<String> for PolicyId {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for PolicyId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// An ATProto label value (e.g. `spam`, `!hide`, `graphic-media`).
///
/// String-typed; the labeler-side validation that the value sits inside the
/// labeler's declared value-set lives in `polaris-backend`'s emit pipeline,
/// not here.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct LabelValue(pub String);

impl LabelValue {
    /// Construct a `LabelValue` from any string-like value.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrow the underlying string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for LabelValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl From<String> for LabelValue {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for LabelValue {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
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

    #[test]
    fn ids_are_distinct_nominal_types() {
        // Compile-time check: the explicit-type let-binding only accepts a
        // `SubjectId`. A bare `let sid: SubjectId = IncidentId::new();` would
        // fail to compile — that's the property we want from nominal typing.
        let sid: SubjectId = SubjectId::new();
        let iid: IncidentId = IncidentId::new();
        // Inner Uuids must remain comparable across newtypes (audit code
        // does this), but the newtypes themselves are not directly comparable
        // by `PartialEq` — proven by the fact that there's no
        // `PartialEq<IncidentId> for SubjectId` impl. We instead compare the
        // inner UUID values, which is the supported audit path.
        assert_ne!(sid.into_uuid(), iid.into_uuid());
    }

    #[test]
    fn id_round_trips_through_serde_as_bare_uuid() {
        let s = SubjectId::new();
        let json = serde_json::to_string(&s).expect("serialize");
        // `#[serde(transparent)]` means the JSON is a bare quoted UUID, not a
        // wrapper object.
        assert!(json.starts_with('"') && json.ends_with('"'));
        let back: SubjectId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(s, back);
    }

    #[test]
    fn did_round_trips_as_string() {
        let d = Did::new("did:plc:abc123");
        let json = serde_json::to_string(&d).expect("serialize");
        assert_eq!(json, "\"did:plc:abc123\"");
        let back: Did = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(d, back);
    }

    #[test]
    fn at_uri_round_trips_as_string() {
        let u = AtUri::new("at://did:plc:x/app.bsky.feed.post/3l");
        let json = serde_json::to_string(&u).expect("serialize");
        assert_eq!(json, "\"at://did:plc:x/app.bsky.feed.post/3l\"");
        let back: AtUri = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(u, back);
    }

    #[test]
    fn default_mints_fresh_ids() {
        let a = SubjectId::default();
        let b = SubjectId::default();
        assert_ne!(a, b, "Default must produce fresh UUIDs");
    }

    #[test]
    fn display_matches_uuid_hyphenated_form() {
        let inner = Uuid::nil();
        let id = SubjectId(inner);
        assert_eq!(id.to_string(), inner.to_string());
    }
}
