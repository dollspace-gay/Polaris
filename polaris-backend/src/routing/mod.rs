//! Incident → moderator routing engine.
//!
//! `design.md` §5.4 — the router decides which moderator (if any) an
//! incident should be assigned to, or whether the incident must be forwarded
//! externally (CSAM/CSEM with no trained moderator on staff).
//!
//! # Pure function over a snapshot
//!
//! The decision is a **pure function** of a [`RoutingSnapshot`]:
//!
//! ```text
//!   pub fn route(snapshot: &RoutingSnapshot) -> RoutingDecision
//! ```
//!
//! No I/O, no async, no traits. The snapshot is built by
//! [`service::RoutingService`] (which queries the DB through a
//! [`service::ModeratorDirectory`] + [`crate::repo::IncidentRepo`]); the pure
//! function is unit-testable in isolation with hand-rolled fixtures and is
//! deterministic given its input. The split is what makes the §5.4
//! decision rules independently auditable.
//!
//! # Rule cascade
//!
//! `route` applies the §5.4 rules in this order, top-down. The first rule
//! that fires wins; later rules are not evaluated:
//!
//! 1. **CSAM/CSEM hard rule.** If the incident category
//!    [requires specialist training][polaris_types::RoutingCategory::requires_specialist_training]
//!    and no `csam_trained` moderator is in the snapshot, the decision is
//!    [`RoutingDecision::ForwardExternally`] (`ncmec: true, bluesky: true`).
//!    No fallback to a generalist — the labeler tool refuses to render.
//! 2. **Specialist-training filter.** For CSAM/CSEM-class incidents, drop
//!    every moderator with `csam_trained = false` from the pool.
//! 3. **Calibration filter.** Drop moderators whose `calibration_complete`
//!    is false from incidents whose category is **not** in
//!    [`EASY_MODE_CATEGORIES`].
//! 4. **Exposure budget filter.** Drop moderators whose remaining exposure
//!    budget is zero.
//! 5. **Load cap filter.** Drop moderators whose `current_load` is at or
//!    above [`SOFT_LOAD_CAP`].
//! 6. **Score & pick.** Rank remaining candidates: specialty-match
//!    (`specialties.contains(category)`) beats generalist; ties broken by
//!    lowest `current_load`, then by deterministic id ordering. The winner
//!    is the assignee.
//! 7. **Shadow-review wrap.** If the chosen moderator's
//!    `calibration_complete` is false (only reachable for easy-mode
//!    categories), wrap the decision as
//!    [`RoutingDecision::CalibrationShadow`] with a senior reviewer chosen
//!    from the calibration-complete pool.
//!
//! # Forbidden patterns
//!
//! Per the issue #22 pre-flight, this module enforces:
//!
//! - No `unwrap()` / `expect()` in non-test code.
//! - No `Arc<Mutex<...>>` around router state — the function is pure.
//! - No `anyhow` in library APIs.
//! - No I/O inside `route` — it cannot call `.await` or take any repo trait.
//! - `f32` (not `f64`) for any score value carried on the snapshot.

pub mod service;

use std::collections::HashSet;

use polaris_types::{IncidentId, ModeratorId, RoutingCategory, Severity, SubjectId};

/// Categories a non-calibrated moderator may be routed to.
///
/// Per `design.md` §5.4, new moderators see a "curated easy-mode queue with
/// shadow-review against senior decisions." The list is intentionally short:
/// spam and copyright complaints are low emotional load and have clear
/// objective criteria.
///
/// Harassment, impersonation, misinformation, and "other" are excluded
/// because they require contextual judgment best practiced under direct
/// senior supervision rather than via shadow review. CSAM/Csem are excluded
/// by the prior `requires_specialist_training` filter and never reach this
/// gate.
pub const EASY_MODE_CATEGORIES: &[RoutingCategory] =
    &[RoutingCategory::Spam, RoutingCategory::Copyright];

/// Soft load cap: moderators at or above this many in-flight incidents are
/// skipped by the router.
///
/// Chosen at 8 because:
/// - It exceeds the typical 4–6 cases a moderator holds open during a
///   shift, leaving headroom for ad-hoc senior-routed escalations.
/// - It is small enough that an over-loaded moderator with the requested
///   specialty cannot starve the queue — the next-best generalist with
///   load < 8 is routed instead.
///
/// Operator-tunable in a future config pass; the current constant captures
/// the §5.4 intent without prematurely introducing a config knob.
pub const SOFT_LOAD_CAP: u32 = 8;

/// Snapshot of the routing-relevant world at the moment of decision.
///
/// Built by [`service::RoutingService`] via repo queries; passed by reference
/// to [`route`]. The struct is deliberately a plain data record — every
/// field is owned and serialisable so the snapshot can be logged for audit.
#[derive(Debug, Clone)]
pub struct RoutingSnapshot {
    /// The incident under consideration.
    pub incident: IncidentForRouting,
    /// All moderators the directory considers in-scope for this routing
    /// attempt. The router applies the §5.4 filters internally — callers
    /// pass the full pool and let `route` discriminate.
    pub eligible_moderators: Vec<ModeratorForRouting>,
}

/// Routing-relevant projection of an [`polaris_types::Incident`].
#[derive(Debug, Clone)]
pub struct IncidentForRouting {
    /// Polaris-internal identifier (carried for trace logs / audit).
    pub id: IncidentId,
    /// Primary subject (carried so audit logs can correlate).
    pub primary_subject: SubjectId,
    /// Routing-time category (closed enum; see
    /// [`polaris_types::RoutingCategory`]).
    pub category: RoutingCategory,
    /// Severity tier from the incident record.
    pub severity: Severity,
    /// Moderator who must be filtered out of the candidate pool.
    ///
    /// Used by the appeals workflow (issue #24): when routing an appeal,
    /// the original action's author is the one moderator who categorically
    /// cannot review the appeal of their own decision (design.md §5.8 —
    /// "Original moderator cannot review their own appeal"). Callers set
    /// `Some(<original author>)`; ordinary incident routing passes `None`.
    ///
    /// The filter is enforced in [`route`] before the score-and-pick step
    /// so the §5.4 cascade still applies to the remaining pool.
    pub exclude_moderator: Option<ModeratorId>,
}

/// Routing-relevant projection of a moderator.
///
/// Combines the moderator-row state (`csam_trained`, `calibration_complete`,
/// specialties), the live load (`current_load`), the wellness budget
/// (`exposure_budget_remaining`), and the calibration agreement signal
/// (`agreement_with_senior_rate`).
#[derive(Debug, Clone)]
pub struct ModeratorForRouting {
    /// Moderator id.
    pub id: ModeratorId,
    /// CSAM/CSEM-trained gate — must be true for incidents whose category
    /// [`RoutingCategory::requires_specialist_training`].
    pub csam_trained: bool,
    /// Calibration complete — if false, the moderator may only be routed
    /// easy-mode categories and the decision becomes a shadow review.
    pub calibration_complete: bool,
    /// Categories this moderator is a specialist in.
    pub specialties: HashSet<RoutingCategory>,
    /// Open assignments currently held by this moderator (count of
    /// `incidents.assigned_to = id AND status IN ('open','in_review')`).
    pub current_load: u32,
    /// Remaining graphic-content exposure budget (design.md §5.7).
    ///
    /// `u32::MAX` is the placeholder until issue #23 lands real accounting;
    /// the router treats it as "no cap" via the
    /// [`polaris_types::ExposureBudget::is_exhausted`] check.
    pub exposure_budget_remaining: u32,
    /// Agreement rate with senior reviewers on shadow-review decisions in
    /// `[0.0, 1.0]`. Used as a tie-breaker preference once #23 lands; today
    /// the router consults it only as a stable secondary tie-break.
    ///
    /// `f32` per the issue #22 forbidden-pattern checklist — protocol-bearing
    /// scores must not be `f64`.
    pub agreement_with_senior_rate: f32,
}

/// Output of [`route`] — the decision the upstream caller must enact.
///
/// All variants are total; the function never panics on a valid snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Assign to the named moderator. Calibration-complete moderators only.
    Assigned(ModeratorId),
    /// Assign to the named moderator AND attach a senior shadow reviewer.
    ///
    /// Used when `assigned` is a not-yet-calibrated moderator and the
    /// incident category is in [`EASY_MODE_CATEGORIES`].
    CalibrationShadow {
        /// The new moderator who gets the case.
        assigned: ModeratorId,
        /// The senior reviewer shadowing the decision.
        shadow_reviewer: ModeratorId,
    },
    /// Refuse to assign and forward to external takedown channels.
    ///
    /// Per `design.md` §5.4 the labeler tool refuses to render
    /// CSAM/CSEM-class material when no specialist-trained moderator is on
    /// staff; the caller is expected to fire NCMEC + Bluesky forwarding
    /// events on this decision.
    ForwardExternally {
        /// Whether to forward to NCMEC (US National Center for Missing &
        /// Exploited Children).
        ncmec: bool,
        /// Whether to forward to Bluesky's first-party safety team.
        bluesky: bool,
        /// Reason the forward fired (carried for audit).
        reason: ForwardReason,
    },
    /// No moderator in the snapshot was eligible. The caller may retry
    /// later (after exposure budgets reset or load drops) or alert
    /// operations.
    NoEligibleModerator {
        /// Stable diagnostic string. The `&'static str` choice is deliberate:
        /// reasons come from a fixed enumeration of routing-time conditions,
        /// not from arbitrary user input.
        reason: &'static str,
    },
}

/// Why a [`RoutingDecision::ForwardExternally`] decision fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ForwardReason {
    /// Incident category is `Csam` and no `csam_trained` moderator is on
    /// staff.
    CsamNoTrainedModerators,
    /// Incident category is `Csem` and no `csam_trained` moderator is on
    /// staff.
    CsemNoTrainedModerators,
}

/// Apply the §5.4 rule cascade to a snapshot.
///
/// **Pure function.** Deterministic given input. No I/O, no allocation that
/// outlives the call (the returned enum is a value), no panics.
#[must_use]
pub fn route(snapshot: &RoutingSnapshot) -> RoutingDecision {
    let category = snapshot.incident.category;

    // Rule 1: CSAM/CSEM hard rule. Specialist training is non-negotiable.
    if category.requires_specialist_training() {
        let any_trained = snapshot.eligible_moderators.iter().any(|m| m.csam_trained);
        if !any_trained {
            return RoutingDecision::ForwardExternally {
                ncmec: true,
                bluesky: true,
                reason: forward_reason_for(category),
            };
        }
    }

    if snapshot.eligible_moderators.is_empty() {
        return RoutingDecision::NoEligibleModerator {
            reason: "no moderators available",
        };
    }

    // Rules 2-5: filter the pool down to candidates eligible for this
    // category. The appeal-author exclusion (issue #24) is applied first
    // so a category-eligible original author cannot be silently picked
    // by the score step.
    let exclude = snapshot.incident.exclude_moderator;
    let candidates: Vec<&ModeratorForRouting> = snapshot
        .eligible_moderators
        .iter()
        .filter(|m| Some(m.id) != exclude)
        .filter(|m| passes_specialist_filter(m, category))
        .filter(|m| passes_calibration_filter(m, category))
        .filter(|m| m.exposure_budget_remaining > 0)
        .filter(|m| m.current_load < SOFT_LOAD_CAP)
        .collect();

    if candidates.is_empty() {
        // Diagnose: distinguish "everyone is at load cap" from "no
        // candidate cleared the filters".
        return RoutingDecision::NoEligibleModerator {
            reason: diagnose_empty_pool(snapshot, category),
        };
    }

    // Rule 6: score & pick. Stable ordering: specialty match first, then
    // lowest current load, then highest senior-agreement, then id.
    //
    // Iterating with `min_by` (rather than sorting then taking [0]) keeps
    // the comparator stable and avoids a `Vec::sort_by` allocation churn
    // every time the cascade runs.
    let Some(best) = candidates
        .iter()
        .min_by(|a, b| score(a, category).cmp(&score(b, category)))
    else {
        // Unreachable because `candidates` is non-empty (checked above).
        // We choose `NoEligibleModerator` over `unreachable!()` to honour
        // the "no panics in pure router code" forbidden-pattern rule.
        return RoutingDecision::NoEligibleModerator {
            reason: "no candidate after scoring",
        };
    };

    // Rule 7: shadow-review wrap for non-calibrated assignees.
    if !best.calibration_complete {
        // Look for a senior shadow reviewer among the calibrated pool.
        // The shadow reviewer does not consume specialty filters — any
        // calibrated mod with budget can shadow.
        let shadow_reviewer = snapshot
            .eligible_moderators
            .iter()
            .filter(|m| m.id != best.id)
            .filter(|m| m.calibration_complete)
            .filter(|m| m.exposure_budget_remaining > 0)
            .min_by_key(|m| m.current_load)
            .map(|m| m.id);

        if let Some(shadow_reviewer) = shadow_reviewer {
            return RoutingDecision::CalibrationShadow {
                assigned: best.id,
                shadow_reviewer,
            };
        }
        // No shadow reviewer available — refuse rather than route a
        // calibration case without supervision. §5.4 makes shadow review a
        // hard requirement for new moderators.
        return RoutingDecision::NoEligibleModerator {
            reason: "no calibrated shadow reviewer available",
        };
    }

    RoutingDecision::Assigned(best.id)
}

/// CSAM/CSEM filter: incidents requiring specialist training only see
/// `csam_trained = true` moderators. All other categories pass through.
fn passes_specialist_filter(m: &ModeratorForRouting, category: RoutingCategory) -> bool {
    if category.requires_specialist_training() {
        m.csam_trained
    } else {
        true
    }
}

/// Calibration filter: non-calibrated moderators may only see easy-mode
/// categories. Calibrated moderators pass through.
fn passes_calibration_filter(m: &ModeratorForRouting, category: RoutingCategory) -> bool {
    if m.calibration_complete {
        true
    } else {
        EASY_MODE_CATEGORIES.contains(&category)
    }
}

/// Score a candidate so the `min` is the best pick.
///
/// Returned tuple is `(specialty_rank, load, neg_agreement_rate_bits, id_bits)`
/// where lower is better.
///
/// - `specialty_rank` — 0 for specialty match, 1 for generalist.
/// - `load` — `current_load` (lower first).
/// - `neg_agreement_rate_bits` — `u32::MAX - (agreement * 1_000_000)` so
///   higher agreement rates compare as smaller numbers. The `f32` is
///   quantised to integer micro-units for `Ord` (floats are not totally
///   ordered, and the issue's `f32`-precision rule forbids `f64`).
/// - `id_bits` — moderator UUID least-significant-bits; final deterministic
///   tiebreaker so the cascade is reproducible.
fn score(m: &ModeratorForRouting, category: RoutingCategory) -> (u8, u32, u32, u128) {
    let specialty_rank: u8 = u8::from(!m.specialties.contains(&category));
    // `agreement_with_senior_rate` is in [0.0, 1.0]; clamp before quantising
    // to defend against arbitrary inputs in the snapshot.
    let agreement = m.agreement_with_senior_rate.clamp(0.0, 1.0);
    // `as u32` on a finite, clamped, scaled f32 is well-defined; the value
    // fits in `[0, 1_000_000]`.
    #[allow(
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation,
        reason = "value is clamped to [0, 1] then scaled to [0, 1_000_000]; fits in u32"
    )]
    let scaled = (agreement * 1_000_000.0) as u32;
    let neg_agreement = u32::MAX - scaled;
    let id_bits = m.id.into_uuid().as_u128();
    (specialty_rank, m.current_load, neg_agreement, id_bits)
}

/// Map a specialist-required category to the matching [`ForwardReason`].
///
/// Only called on the CSAM/CSEM branch (the caller already verified
/// [`RoutingCategory::requires_specialist_training`]). Csem is the
/// distinguished variant; every other input (today only `Csam`, tomorrow
/// any new specialist-required variant) collapses to the CSAM-class
/// reason so a future addition fails routing-safe (no trained mods →
/// external forward) instead of silently slipping through.
fn forward_reason_for(category: RoutingCategory) -> ForwardReason {
    if matches!(category, RoutingCategory::Csem) {
        ForwardReason::CsemNoTrainedModerators
    } else {
        ForwardReason::CsamNoTrainedModerators
    }
}

/// Distinguish the two ways the candidate pool can collapse to empty so the
/// caller can act differently (alert ops vs. retry later).
fn diagnose_empty_pool(snapshot: &RoutingSnapshot, category: RoutingCategory) -> &'static str {
    let exclude = snapshot.incident.exclude_moderator;
    let any_passes_filters = snapshot.eligible_moderators.iter().any(|m| {
        Some(m.id) != exclude
            && passes_specialist_filter(m, category)
            && passes_calibration_filter(m, category)
            && m.exposure_budget_remaining > 0
    });
    if any_passes_filters {
        "all at load cap"
    } else {
        "no eligible moderator for category"
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
    use polaris_types::Severity;
    use proptest::prelude::*;

    fn mk_incident(category: RoutingCategory) -> IncidentForRouting {
        IncidentForRouting {
            id: IncidentId::new(),
            primary_subject: SubjectId::new(),
            category,
            severity: Severity::Medium,
            exclude_moderator: None,
        }
    }

    fn mk_mod(
        id: ModeratorId,
        csam_trained: bool,
        calibration_complete: bool,
        specialties: &[RoutingCategory],
        current_load: u32,
        exposure_budget_remaining: u32,
    ) -> ModeratorForRouting {
        ModeratorForRouting {
            id,
            csam_trained,
            calibration_complete,
            specialties: specialties.iter().copied().collect(),
            current_load,
            exposure_budget_remaining,
            agreement_with_senior_rate: 0.5,
        }
    }

    #[test]
    fn csam_with_no_trained_mod_forwards_externally() {
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Csam),
            eligible_moderators: vec![mk_mod(
                ModeratorId::new(),
                false, // not trained
                true,
                &[],
                0,
                u32::MAX,
            )],
        };
        let decision = route(&snap);
        assert_eq!(
            decision,
            RoutingDecision::ForwardExternally {
                ncmec: true,
                bluesky: true,
                reason: ForwardReason::CsamNoTrainedModerators,
            }
        );
    }

    #[test]
    fn csam_with_trained_mod_routes_to_them() {
        let trained_id = ModeratorId::new();
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Csam),
            eligible_moderators: vec![
                mk_mod(ModeratorId::new(), false, true, &[], 0, u32::MAX),
                mk_mod(trained_id, true, true, &[], 0, u32::MAX),
            ],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(trained_id));
    }

    #[test]
    fn csem_with_no_trained_mod_forwards_externally_with_csem_reason() {
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Csem),
            eligible_moderators: vec![
                mk_mod(ModeratorId::new(), false, true, &[], 0, u32::MAX),
                mk_mod(ModeratorId::new(), false, true, &[], 0, u32::MAX),
            ],
        };
        let decision = route(&snap);
        assert_eq!(
            decision,
            RoutingDecision::ForwardExternally {
                ncmec: true,
                bluesky: true,
                reason: ForwardReason::CsemNoTrainedModerators,
            }
        );
    }

    #[test]
    fn harassment_routes_to_specialty_over_generalist() {
        let specialist_id = ModeratorId::new();
        let generalist_id = ModeratorId::new();
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Harassment),
            eligible_moderators: vec![
                mk_mod(generalist_id, false, true, &[], 0, u32::MAX),
                mk_mod(
                    specialist_id,
                    false,
                    true,
                    &[RoutingCategory::Harassment],
                    3, // even with higher load, specialty wins
                    u32::MAX,
                ),
            ],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(specialist_id));
    }

    #[test]
    fn new_moderator_gets_shadow_review_for_easy_mode_only() {
        let newbie = ModeratorId::new();
        let senior = ModeratorId::new();
        // Spam IS easy-mode → newbie eligible with shadow review.
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Spam),
            eligible_moderators: vec![
                mk_mod(newbie, false, false, &[], 0, u32::MAX),
                mk_mod(senior, false, true, &[], 5, u32::MAX),
            ],
        };
        assert_eq!(
            route(&snap),
            RoutingDecision::CalibrationShadow {
                assigned: newbie,
                shadow_reviewer: senior,
            }
        );

        // Harassment is NOT easy-mode → newbie filtered out, only senior
        // candidate left.
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Harassment),
            eligible_moderators: vec![
                mk_mod(newbie, false, false, &[], 0, u32::MAX),
                mk_mod(senior, false, true, &[], 5, u32::MAX),
            ],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(senior));
    }

    #[test]
    fn moderator_with_zero_exposure_budget_is_skipped() {
        let exhausted = ModeratorId::new();
        let available = ModeratorId::new();
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Harassment),
            eligible_moderators: vec![
                // Exhausted: zero budget — even with specialty, must be skipped.
                mk_mod(exhausted, false, true, &[RoutingCategory::Harassment], 0, 0),
                mk_mod(available, false, true, &[], 0, u32::MAX),
            ],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(available));
    }

    #[test]
    fn all_at_load_cap_returns_no_eligible_with_diagnostic() {
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Harassment),
            eligible_moderators: vec![
                mk_mod(
                    ModeratorId::new(),
                    false,
                    true,
                    &[],
                    SOFT_LOAD_CAP,
                    u32::MAX,
                ),
                mk_mod(
                    ModeratorId::new(),
                    false,
                    true,
                    &[],
                    SOFT_LOAD_CAP + 5,
                    u32::MAX,
                ),
            ],
        };
        assert_eq!(
            route(&snap),
            RoutingDecision::NoEligibleModerator {
                reason: "all at load cap",
            }
        );
    }

    #[test]
    fn empty_moderator_pool_returns_no_moderators_available() {
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Spam),
            eligible_moderators: vec![],
        };
        assert_eq!(
            route(&snap),
            RoutingDecision::NoEligibleModerator {
                reason: "no moderators available",
            }
        );
    }

    #[test]
    fn ties_on_specialty_break_by_lower_load() {
        let busy_id = ModeratorId::new();
        let idle_id = ModeratorId::new();
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Harassment),
            eligible_moderators: vec![
                mk_mod(
                    busy_id,
                    false,
                    true,
                    &[RoutingCategory::Harassment],
                    4,
                    u32::MAX,
                ),
                mk_mod(
                    idle_id,
                    false,
                    true,
                    &[RoutingCategory::Harassment],
                    1,
                    u32::MAX,
                ),
            ],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(idle_id));
    }

    #[test]
    fn calibration_case_without_senior_falls_back_to_no_eligible() {
        // Only candidate is non-calibrated; no calibrated mod exists to
        // shadow. Must NOT silently assign without supervision.
        let newbie = ModeratorId::new();
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Spam),
            eligible_moderators: vec![mk_mod(newbie, false, false, &[], 0, u32::MAX)],
        };
        assert_eq!(
            route(&snap),
            RoutingDecision::NoEligibleModerator {
                reason: "no calibrated shadow reviewer available",
            }
        );
    }

    #[test]
    fn excluded_moderator_is_filtered_out_even_when_otherwise_best() {
        // Appeal of an action by `original`. The router must not pick
        // `original` even when they are the strongest specialty match.
        let original = ModeratorId::new();
        let other = ModeratorId::new();
        let mut incident = mk_incident(RoutingCategory::Harassment);
        incident.exclude_moderator = Some(original);
        let snap = RoutingSnapshot {
            incident,
            eligible_moderators: vec![
                // Specialist at low load — would be picked without exclusion.
                mk_mod(
                    original,
                    false,
                    true,
                    &[RoutingCategory::Harassment],
                    0,
                    u32::MAX,
                ),
                // Plain generalist with higher load.
                mk_mod(other, false, true, &[], 3, u32::MAX),
            ],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(other));
    }

    #[test]
    fn excluded_moderator_alone_yields_no_eligible() {
        // If the only candidate is excluded, the cascade must surface
        // `NoEligibleModerator` rather than silently routing to them.
        let original = ModeratorId::new();
        let mut incident = mk_incident(RoutingCategory::Harassment);
        incident.exclude_moderator = Some(original);
        let snap = RoutingSnapshot {
            incident,
            eligible_moderators: vec![mk_mod(original, false, true, &[], 0, u32::MAX)],
        };
        assert!(matches!(
            route(&snap),
            RoutingDecision::NoEligibleModerator { .. }
        ));
    }

    #[test]
    fn non_specialist_category_does_not_filter_csam_trained_false_mods() {
        // Sanity: a harassment incident must not be filtered to csam_trained
        // mods only. The pool has only non-trained mods and harassment
        // should still route.
        let id = ModeratorId::new();
        let snap = RoutingSnapshot {
            incident: mk_incident(RoutingCategory::Harassment),
            eligible_moderators: vec![mk_mod(id, false, true, &[], 0, u32::MAX)],
        };
        assert_eq!(route(&snap), RoutingDecision::Assigned(id));
    }

    proptest! {
        /// Property: a CSAM incident with no trained mods ALWAYS yields
        /// `ForwardExternally`, regardless of how many other moderators,
        /// specialties, or loads exist in the snapshot.
        ///
        /// Generates between 0 and 16 untrained moderators with arbitrary
        /// specialties / load / budget / agreement. The hard rule is
        /// absolute — no combination of generalist moderators must ever
        /// cause CSAM to be routed in-house.
        #[test]
        fn csam_with_no_trained_mods_always_forwards(
            n in 0usize..=16,
            seed in any::<u64>(),
        ) {
            // Build a synthetic moderator pool of size `n`, all untrained.
            let mut mods = Vec::with_capacity(n);
            for i in 0..n {
                // Vary fields via the seed so the test exercises a range.
                let v = seed.wrapping_add(i as u64);
                let calibrated = v & 1 == 0;
                // Truncating cast is intentional: `v` is a random u64 seed
                // and we only need the low bits for a bounded test value.
                #[allow(clippy::cast_possible_truncation, reason = "bounded seed-derived value")]
                let load = ((v >> 1) as u32) % (SOFT_LOAD_CAP + 4);
                let budget = if (v >> 2) & 1 == 0 { 0 } else { u32::MAX };
                let specs: Vec<RoutingCategory> = if (v >> 3) & 1 == 0 {
                    vec![RoutingCategory::Harassment]
                } else {
                    vec![]
                };
                mods.push(mk_mod(
                    ModeratorId::new(),
                    /* csam_trained */ false,
                    calibrated,
                    &specs,
                    load,
                    budget,
                ));
            }
            let snap = RoutingSnapshot {
                incident: mk_incident(RoutingCategory::Csam),
                eligible_moderators: mods,
            };
            let decision = route(&snap);
            prop_assert_eq!(
                decision,
                RoutingDecision::ForwardExternally {
                    ncmec: true,
                    bluesky: true,
                    reason: ForwardReason::CsamNoTrainedModerators,
                }
            );
        }
    }
}
