//! Pure scoring: [`ReputationScore`] newtype + the [`reputation`] function.
//!
//! `design.md` §9.3 calls for "reporter reputation scoring" weighted by
//! historical actioned-to-dismissed ratio with a Bayesian prior so a brand-
//! new reporter does not receive an extreme score from a single report. The
//! pure shape of this module — `(stats, now) -> ReputationScore` — keeps the
//! function unit-testable without a database.
//!
//! # Scoring shape
//!
//! Given counts `(actioned, dismissed)` and a Beta-style prior
//! `(prior_actioned, prior_dismissed)`:
//!
//! ```text
//! raw_ratio = (actioned + prior_actioned)
//!           / (actioned + dismissed + prior_actioned + prior_dismissed)
//! ```
//!
//! `raw_ratio` is the posterior mean under a `Beta(prior_actioned,
//! prior_dismissed)` prior over the "this reporter is correct" probability.
//! With the default `(1.0, 1.0)` prior, a brand-new reporter scores exactly
//! 0.5 (the neutral prior) and a 10k-actioned, 100-dismissed established
//! reporter scores ≈ 0.99 (`10001 / 10102`).
//!
//! # Time decay
//!
//! Activity ages out: a reporter inactive for `half_life_days` has their
//! confidence cut in half, drifting back toward the prior (0.5). The
//! blend is exponential:
//!
//! ```text
//! days_since = (now - last_active).as_days()
//! decay      = exp(-days_since / half_life_days)              // in [0, 1]
//! score      = decay * raw_ratio + (1 - decay) * 0.5
//! ```
//!
//! At `decay = 1.0` the score equals `raw_ratio` (full confidence in the
//! history). At `decay = 0.0` the score equals 0.5 (the prior). Half a
//! half-life later, `decay = 0.5`, and the score is the average of
//! `raw_ratio` and 0.5.
//!
//! # Why this shape
//!
//! Bayesian smoothing is the standard fix for "one report from a new
//! reporter is not strong evidence." The Beta prior is the conjugate prior
//! for the binomial likelihood of (actioned, dismissed) outcomes, so the
//! posterior mean has a closed form and no MCMC is required. Time decay is
//! a simple exponential because it is well-understood, monotone, and has
//! exactly one tunable (`half_life_days`); more complex schedules
//! (sigmoid, piecewise) optimise for nothing we can measure today.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A reporter-reputation score, clamped to `[0.0, 1.0]` at construction.
///
/// `0.0` means "every report from this reporter has been dismissed", `1.0`
/// means "every report has produced an action", `0.5` is the neutral prior
/// (no history, or fully decayed history). Constructors enforce the
/// range invariant so the rest of the codebase can treat the inner `f32`
/// as a probability without re-validating.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct ReputationScore(f32);

impl ReputationScore {
    /// Construct a [`ReputationScore`] from an `f32`.
    ///
    /// # Errors
    ///
    /// Returns [`ReputationError::OutOfRange`] when `value` is not finite
    /// (`NaN`, `±inf`) or lies outside `[0.0, 1.0]`.
    pub fn new(value: f32) -> Result<Self, ReputationError> {
        if !value.is_finite() || !(0.0..=1.0).contains(&value) {
            return Err(ReputationError::OutOfRange { value });
        }
        Ok(Self(value))
    }

    /// Unwrap to the underlying `f32`.
    #[must_use]
    pub fn into_inner(self) -> f32 {
        self.0
    }

    /// The neutral prior score (`0.5`) — what a brand-new reporter scores
    /// under the default `(1.0, 1.0)` prior. Exposed as a convenience for
    /// fallback paths that need a stable "no data" value without going
    /// through [`Self::new`].
    #[must_use]
    pub const fn neutral() -> Self {
        Self(0.5)
    }
}

/// Aggregate reporter history loaded from the `reporter_stats` table.
///
/// `did` is the keyed-on raw DID string (not a [`polaris_types::Did`] —
/// keeping the field a plain `String` lets [`reputation`] stay free of
/// crate-graph dependencies, and the conversion is a borrow at call sites).
#[derive(Debug, Clone)]
pub struct ReporterStats {
    /// Raw DID of the reporter.
    pub did: String,
    /// Lifetime count of reports filed by this reporter.
    pub reports_filed: i64,
    /// Subset of [`Self::reports_filed`] that produced a Label or Takedown
    /// action against the subject.
    pub reports_actioned: i64,
    /// Subset of [`Self::reports_filed`] that produced a `NoAction`
    /// (the "dismissed" path).
    pub reports_dismissed: i64,
    /// When Polaris first saw this reporter (their first inserted report).
    pub first_seen: DateTime<Utc>,
    /// When this reporter last filed a report or had one of theirs actioned.
    pub last_active: DateTime<Utc>,
}

/// Tunables for the [`reputation`] function. Operator-configurable via
/// [`crate::config::ReputationConfig`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ReputationParams {
    /// Beta-prior pseudo-count for "actioned" outcomes. Default 1.0.
    pub prior_actioned: f32,
    /// Beta-prior pseudo-count for "dismissed" outcomes. Default 1.0.
    pub prior_dismissed: f32,
    /// Days after which the decay factor is `e^-1` ≈ 0.368. Default 90.0.
    pub half_life_days: f32,
}

impl Default for ReputationParams {
    fn default() -> Self {
        Self {
            prior_actioned: 1.0,
            prior_dismissed: 1.0,
            half_life_days: 90.0,
        }
    }
}

/// Errors raised by the reputation subsystem.
#[derive(Debug, thiserror::Error)]
pub enum ReputationError {
    /// A reputation score landed outside `[0.0, 1.0]` (or was non-finite).
    #[error("reputation score out of range: {value}")]
    OutOfRange {
        /// The offending value.
        value: f32,
    },

    /// Database failure during reputation read or update.
    #[error("reputation database error")]
    Db(#[from] sqlx::Error),

    /// `score_for` was called against a DID with no row in `reporter_stats`.
    ///
    /// The pattern-engine integration paths surface this as "treat as
    /// neutral" — a never-before-seen reporter has by definition no
    /// history to weight against, so the caller falls back to
    /// [`ReputationScore::neutral`].
    #[error("reporter did has no stats row: {did}")]
    UnknownReporter {
        /// The DID that has no row in `reporter_stats`.
        did: String,
    },
}

/// Compute a reputation score from a reporter's stats at the given
/// observation time.
///
/// Pure: no I/O, no allocation beyond stack, no time-of-day reads. The
/// function is unit-testable in isolation; integration tests cover the
/// wiring from the `reporter_stats` row through to this call.
///
/// See the module-level docs for the scoring shape and why-this-shape.
///
/// # Examples
///
/// Brand-new reporter scores the neutral prior:
///
/// ```
/// use chrono::Utc;
/// use polaris_backend::reputation::{ReporterStats, ReputationParams, reputation};
///
/// let now = Utc::now();
/// let stats = ReporterStats {
///     did: "did:plc:new".to_owned(),
///     reports_filed: 0,
///     reports_actioned: 0,
///     reports_dismissed: 0,
///     first_seen: now,
///     last_active: now,
/// };
/// let score = reputation(&stats, now, &ReputationParams::default());
/// assert!((score.into_inner() - 0.5).abs() < 1e-6);
/// ```
#[must_use]
pub fn reputation(
    stats: &ReporterStats,
    now: DateTime<Utc>,
    params: &ReputationParams,
) -> ReputationScore {
    // Smoothed numerator / denominator with the Beta prior. The casts from
    // `i64` to `f32` are bounded: report counts are not negative (the DB
    // CHECK constraint enforces) and report counts > 2^24 imply a single
    // reporter filing 16 million reports — three orders of magnitude beyond
    // any plausible Bluesky deployment. The precision loss at realistic
    // scale is zero.
    #[expect(
        clippy::cast_precision_loss,
        reason = "i64 -> f32 cast: report counts up to 2^24 are exact; \
                  the realistic upper bound (a single reporter filing \
                  thousands of reports a year) sits multiple orders of \
                  magnitude below that threshold."
    )]
    let actioned = stats.reports_actioned as f32 + params.prior_actioned;
    #[expect(
        clippy::cast_precision_loss,
        reason = "see actioned cast above — same bound applies."
    )]
    let dismissed = stats.reports_dismissed as f32 + params.prior_dismissed;
    let total = actioned + dismissed;

    // Defence-in-depth: with a non-zero prior `total` is always > 0. If a
    // caller passes `(0.0, 0.0)` priors and zero counts we fall back to the
    // neutral score rather than emit NaN. (Construction-time validation in
    // `PgReputationProvider` rejects non-positive priors, so this branch is
    // unreachable on the wired path, but the pure function defends itself.)
    let raw_ratio = if total > 0.0 { actioned / total } else { 0.5 };

    // Time decay toward the prior. `half_life_days <= 0` would mean
    // "instant decay" which produces a degenerate score = 0.5 for any
    // history; we treat that as a config error and fall back to the
    // neutral score rather than divide by zero. (Construction-time
    // validation rejects non-positive half-lives, again, so this branch
    // is unreachable in production.)
    let blended = if params.half_life_days > 0.0 {
        let days_since_secs = (now - stats.last_active).num_seconds();
        // `days_since_secs as f32` is exact for ranges below 2^24 seconds
        // (~194 days). Beyond that, the float loses a second at a time —
        // immaterial for half-life-day computations.
        #[expect(
            clippy::cast_precision_loss,
            reason = "i64 seconds -> f32 days: precision loss below \
                      one second per measured day, far smaller than \
                      the half-life scale."
        )]
        let days_since = days_since_secs as f32 / 86_400.0_f32;
        let decay = (-days_since / params.half_life_days).exp().clamp(0.0, 1.0);
        decay * raw_ratio + (1.0 - decay) * 0.5
    } else {
        0.5
    };

    // `blended` is the affine combination of two values both in `[0, 1]`
    // with weights also in `[0, 1]` summing to 1, so it is mathematically
    // in `[0, 1]`. Floating-point rounding can nudge it microscopically
    // outside; the clamp absorbs that. `ReputationScore::new` cannot
    // reject `clamped` (it is finite-by-construction and in `[0, 1]`),
    // but if a future refactor reintroduces a NaN-producing path we fall
    // back to the neutral score rather than panic.
    let clamped = blended.clamp(0.0, 1.0);
    ReputationScore::new(clamped).unwrap_or_else(|_| ReputationScore::neutral())
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
    use chrono::TimeZone;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
    }

    fn stats_with(actioned: i64, dismissed: i64, last_active: DateTime<Utc>) -> ReporterStats {
        ReporterStats {
            did: "did:plc:test".to_owned(),
            reports_filed: actioned + dismissed,
            reports_actioned: actioned,
            reports_dismissed: dismissed,
            first_seen: last_active,
            last_active,
        }
    }

    // ── Newtype invariants ───────────────────────────────────────────

    #[test]
    fn reputation_score_new_accepts_midpoint() {
        let s = ReputationScore::new(0.5).expect("0.5 is in [0,1]");
        assert!((s.into_inner() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn reputation_score_new_accepts_zero_and_one() {
        ReputationScore::new(0.0).expect("0.0 is in [0,1]");
        ReputationScore::new(1.0).expect("1.0 is in [0,1]");
    }

    #[test]
    fn reputation_score_new_rejects_below_zero() {
        let err = ReputationScore::new(-0.1).expect_err("negative is out of range");
        match err {
            ReputationError::OutOfRange { value } => assert!((value + 0.1).abs() < f32::EPSILON),
            other => panic!("expected OutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn reputation_score_new_rejects_above_one() {
        let err = ReputationScore::new(1.1).expect_err("above 1 is out of range");
        match err {
            ReputationError::OutOfRange { value } => assert!((value - 1.1).abs() < f32::EPSILON),
            other => panic!("expected OutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn reputation_score_new_rejects_nan() {
        let err = ReputationScore::new(f32::NAN).expect_err("NaN is not finite");
        assert!(matches!(err, ReputationError::OutOfRange { .. }));
    }

    #[test]
    fn reputation_score_new_rejects_infinity() {
        let err =
            ReputationScore::new(f32::INFINITY).expect_err("infinity is not in [0,1] or finite");
        assert!(matches!(err, ReputationError::OutOfRange { .. }));
        let err =
            ReputationScore::new(f32::NEG_INFINITY).expect_err("-infinity is not finite either");
        assert!(matches!(err, ReputationError::OutOfRange { .. }));
    }

    // ── Property-style: the cases called out in the architect's pre-flight ──

    #[test]
    fn brand_new_reporter_scores_the_prior() {
        // (0, 0) counts with `last_active == now` and default priors
        // should land exactly on 0.5 — the Beta(1,1) posterior mean
        // with no observations.
        let n = now();
        let s = stats_with(0, 0, n);
        let score = reputation(&s, n, &ReputationParams::default());
        assert!(
            (score.into_inner() - 0.5).abs() < 1e-6,
            "brand-new reporter should score the prior (0.5), got {}",
            score.into_inner()
        );
    }

    #[test]
    fn established_good_reporter_scores_above_zero_point_nine_five() {
        // 10_000 actioned vs. 100 dismissed should be deep in the
        // "highly credible" zone. With prior (1,1) the raw ratio is
        // 10_001 / 10_102 ≈ 0.99001; no decay (last_active == now).
        let n = now();
        let s = stats_with(10_000, 100, n);
        let score = reputation(&s, n, &ReputationParams::default());
        assert!(
            score.into_inner() > 0.95,
            "10k actioned / 100 dismissed should score > 0.95, got {}",
            score.into_inner()
        );
    }

    #[test]
    fn established_bad_reporter_scores_below_zero_point_zero_five() {
        // 10 actioned vs. 10_000 dismissed — a serial false-reporter.
        // With prior (1,1) the raw ratio is 11 / 10_012 ≈ 0.0011; no decay.
        let n = now();
        let s = stats_with(10, 10_000, n);
        let score = reputation(&s, n, &ReputationParams::default());
        assert!(
            score.into_inner() < 0.05,
            "10 actioned / 10k dismissed should score < 0.05, got {}",
            score.into_inner()
        );
    }

    #[test]
    fn time_decay_pulls_idle_history_toward_the_prior() {
        // Established-good reporter inactive for 5 half-lives.
        // `decay = e^-5 ≈ 0.00674`, so the blended score is
        // `0.00674 * raw_ratio + 0.99326 * 0.5` ≈ 0.5 ± ~0.003.
        let n = now();
        let half_life_days = 30.0_f32;
        let params = ReputationParams {
            prior_actioned: 1.0,
            prior_dismissed: 1.0,
            half_life_days,
        };
        let inactive_since = n - chrono::Duration::days(150); // 5 half-lives
        let s = stats_with(10_000, 100, inactive_since);
        let score = reputation(&s, n, &params);
        assert!(
            (score.into_inner() - 0.5).abs() < 0.05,
            "5-half-life-idle established-good reporter should drift \
             toward the prior, got {}",
            score.into_inner()
        );
    }

    #[test]
    fn fresh_activity_keeps_full_confidence() {
        // No time-decay penalty when `last_active == now`. Pin the
        // "decay does not over-fire on fresh data" path: the score
        // should be very close to the raw_ratio.
        let n = now();
        let s = stats_with(10_000, 100, n);
        let score = reputation(&s, n, &ReputationParams::default());
        // raw_ratio = 10_001 / 10_102 ≈ 0.9900
        assert!(
            (score.into_inner() - 0.9900).abs() < 0.001,
            "fresh established-good reporter should score near the raw \
             ratio (~0.99), got {}",
            score.into_inner()
        );
    }

    #[test]
    fn neutral_constructor_matches_prior() {
        // `ReputationScore::neutral()` is the value a brand-new reporter
        // gets — pin the two paths agree so the fallback in
        // `ReputationProvider::score_for` matches `reputation(...)` on a
        // zero-history reporter.
        let n = now();
        let s = stats_with(0, 0, n);
        let computed = reputation(&s, n, &ReputationParams::default());
        assert!((computed.into_inner() - ReputationScore::neutral().into_inner()).abs() < 1e-6);
    }

    // ── Degenerate-input defence-in-depth ─────────────────────────────

    #[test]
    fn zero_prior_with_zero_counts_falls_back_to_neutral() {
        // `(prior, counts) = (0,0)` is a degenerate config — the provider
        // rejects it, but the pure function defends itself by returning
        // the neutral score rather than producing NaN.
        let n = now();
        let s = stats_with(0, 0, n);
        let degenerate = ReputationParams {
            prior_actioned: 0.0,
            prior_dismissed: 0.0,
            half_life_days: 90.0,
        };
        let score = reputation(&s, n, &degenerate);
        assert!((score.into_inner() - 0.5).abs() < 1e-6);
    }

    #[test]
    fn zero_half_life_falls_back_to_neutral() {
        // Half-life of 0 days means "instant decay to the prior" —
        // again the provider rejects it at construction time. Pin the
        // fallback so a misconfigured caller can't crash this code.
        let n = now();
        let s = stats_with(10_000, 100, n);
        let degenerate = ReputationParams {
            prior_actioned: 1.0,
            prior_dismissed: 1.0,
            half_life_days: 0.0,
        };
        let score = reputation(&s, n, &degenerate);
        assert!((score.into_inner() - 0.5).abs() < 1e-6);
    }
}
