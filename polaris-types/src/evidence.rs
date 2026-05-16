//! [`EvidencePointer`] — content-addressed pointer to a preserved evidence CAR file.
//!
//! An `EvidencePointer` locates a frozen CAR (Content-Addressed aRchive) blob
//! that preserves the ATProto records that were observed when an escalation was
//! generated. It is embedded inside an [`crate::escalation::Escalation`].
//!
//! On the wire, `EvidencePointer` maps to
//! `polaris_lexicons::gay::dollspace::polaris::evidence_pointer::Main`.
//! The mapping is handled by [`crate::lexicon_mapping`]; this module stays
//! plain serde Rust with no wire-type dependency.

/// Content-addressed pointer to a preserved evidence CAR file.
///
/// Embedded inside an [`crate::escalation::Escalation`].
/// Maps to `gay.dollspace.polaris.evidencePointer#main` on the wire
/// (see `lexicon_mapping::to_lexicon_evidence_pointer` /
/// `from_lexicon_evidence_pointer`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EvidencePointer {
    /// CID of the CAR file (content-addressed; used for retrieval and
    /// integrity verification).
    pub car_cid: String,
    /// MIME type of the preserved evidence (e.g. `application/vnd.ipld.car`).
    pub media_type: String,
    /// Byte length of the CAR blob. Stored as `u64`; the wire form uses
    /// `i64` (ATProto integers are signed), so the mapping clamps on
    /// deserialisation and errors on overflow on serialisation.
    pub byte_length: u64,
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
    fn evidence_pointer_round_trips_through_serde() {
        let ep = EvidencePointer {
            car_cid: "bafyreifoo".to_owned(),
            media_type: "application/vnd.ipld.car".to_owned(),
            byte_length: 1024,
        };
        let json = serde_json::to_string(&ep).expect("serialize");
        let back: EvidencePointer = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(ep, back);
    }
}
