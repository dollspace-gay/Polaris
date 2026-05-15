//! Reputation-weighted report-volume anomaly bands.
//!
//! # Why this exists
//!
//! `design.md` §5.1 frames the pattern dashboard's "report volume
//! timeline ... with anomaly bands rendered" as the simplest pattern
//! detector and arguably the most operationally useful from day 1: when
//! incoming reports spike above their trailing baseline, the spike
//! itself is the signal — independent of whether the reports concern
//! the same image, account, or thread. `design.md` §3.2 names
//! rolling-window analytics as the underlying primitive. This module
//! turns those signals into typed [`AnomalyObservation`] values for
//! the pattern engine, complementing the content-level brigade
//! detector ([`super::simhash`], #17) and the account-level cohort
//! detector ([`super::minhash`], #18) with a volume-level signal that
//! fires when neither of the other two have enough evidence to.
//!
//! # Reputation weighting (issue #77, T3 mitigation)
//!
//! Every observation carries a per-event `weight` in `[0.0, 1.0]` —
//! the reporter's cached reputation score, defaulting to the
//! [`crate::reputation::ReputationScore::neutral`] prior `0.5` when
//! the reporter is unknown. Bucket aggregates are **weighted sums**
//! (`f64`), not raw counts (`u64`): a flood of 1000 reports from a
//! brand-new low-reputation reporter accumulates to `~50` weighted
//! units, the same magnitude as 50 reports from established
//! full-credit reporters. The detector therefore cannot be tricked
//! into emitting a 20× z-score by an adversary who creates fresh
//! accounts and fires reports en masse.
//!
//! # Algorithm
//!
//! The detector maintains:
//!
//! 1. A **current bucket** — weighted sums accumulating against the
//!    `bucket_duration`-aligned window that contains the most recently
//!    seen timestamp.
//! 2. A **history** of the last [`AnomalyConfig::history_size`] closed
//!    buckets' weighted sums.
//! 3. **Welford's online algorithm** state — `n`, running mean, and
//!    `M2` (sum of squared deviations from the running mean) over the
//!    weighted sums currently in the history deque.
//!
//! When a new event arrives whose timestamp falls past the end of the
//! current bucket, the current bucket is *closed*: its weighted sum is
//! appended to the history, Welford's state is updated, and — if the
//! history is now full — the oldest bucket is evicted with the
//! standard Welford removal formula. The newly-closed bucket's
//! z-score is computed against the *updated* statistics; an
//! [`AnomalyObservation`] is emitted iff the z-score exceeds
//! [`AnomalyConfig::threshold_z_score`].
//!
//! Bucket alignment is *epoch-aligned*: each bucket starts at a multiple
//! of `bucket_duration` from the Unix epoch. This makes bucket
//! boundaries deterministic across detector instances and reproducible
//! across test runs, independent of the order in which events arrive.
//!
//! # Welford update / removal formulae
//!
//! Add `x` (weighted sum of a closed bucket):
//!
//! ```text
//! n      += 1
//! delta   = x - mean
//! mean   += delta / n
//! delta2  = x - mean           // uses the NEW mean
//! m2     += delta * delta2
//! ```
//!
//! Remove `x` (when evicting the oldest history bucket):
//!
//! ```text
//! new_n    = n - 1
//! if new_n == 0: mean = 0, m2 = 0
//! else:
//!   new_mean = (n * mean - x) / new_n
//!   m2      -= (x - mean) * (x - new_mean)
//!   mean     = new_mean
//!   n        = new_n
//! ```
//!
//! Sample variance is `m2 / (n - 1)`; standard deviation is its square
//! root. The z-score for a weighted sum `x` is `(x - mean) / stddev`
//! when `stddev > 0`; when the history is perfectly stationary
//! (`stddev == 0`) any non-equal sum is treated as not-an-anomaly to
//! avoid a divide-by-zero — operators that need to detect "spike from
//! zero" should pair the detector with a separate hard-threshold rule.
//!
//! # Why this shape
//!
//! - **`&mut self`, not `Arc<Mutex<...>>`.** The trait method takes
//!   `&mut self` so the detector lives inside a single task (the
//!   pattern-engine driver). The integration site that wants to call
//!   the detector from inside a database transaction wraps the value
//!   in `Arc<tokio::sync::Mutex<...>>` at the outer layer — cross-task
//!   sharing is the *integration*'s concern, not the detector's.
//! - **Single global stream.** The detector observes a single weighted
//!   volume stream — category/severity partitioning is the
//!   pattern-engine driver's concern (it can hold one detector per
//!   shard if it wants finer granularity). Centralising the
//!   reputation-weighted volume in one detector keeps the
//!   #37 → #77 wiring linear.
//! - **Internal `f64`, external `f32`.** Welford's algorithm uses `f64`
//!   internally to keep `M2` stable across the `history_size` updates;
//!   the emitted `z_score` and `confidence` are narrowed to `f32` to
//!   match [`polaris_types::ObservationKind::ReportVolumeAnomaly`] and
//!   [`polaris_types::Observation::confidence`] without a lossy cast at
//!   the integration boundary.
//! - **Welford over naive sum + sum-of-squares.** With
//!   `history_size = 256` and weighted sums in the low thousands,
//!   naive running sums incur catastrophic cancellation in the
//!   variance estimate. Welford keeps the running statistics
//!   numerically stable to the full `f64` precision regardless of
//!   history size.
//! - **Per-bucket dedup.** Each closed bucket is tested for a z-score
//!   crossing at most once; subsequent events landing in the same
//!   bucket update the in-progress weighted sum but do not re-emit.
//!   This mirrors the simhash/minhash "emit-once-per-cluster"
//!   discipline.
//! - **No persistence inside the detector.** Returns
//!   `Option<AnomalyObservation>`; wiring it to the
//!   [`crate::repo::ObservationRepo`] is the pattern-engine driver's
//!   concern.
//!
//! # Follow-ups
//!
//! - A Redis-backed implementation for the Bluesky profile is a
//!   sibling concern tracked separately.
//! - Cold-start seeding (load last N days from the database to
//!   pre-populate the history) is left to the pattern-engine driver,
//!   not the detector — the detector exposes
//!   [`MemoryAnomalyDetector::seed_bucket`] so the driver can populate
//!   history without synthesizing fake events.

use std::collections::VecDeque;
use std::time::Duration;

use chrono::{DateTime, Utc};

use crate::pattern::PatternError;

/// Configuration for the [`MemoryAnomalyDetector`].
///
/// Construction-time validation in [`MemoryAnomalyDetector::new`] rejects
/// the misconfigurations the type system cannot express (non-finite
/// threshold, zero-duration bucket, history size below the minimum for
/// sample variance).
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Bucket width — incoming events are aggregated into windows of
    /// this duration. `Duration` typing rules out the
    /// "seconds-as-u64" footgun. Must be strictly positive.
    pub bucket_duration: Duration,

    /// Number of historical buckets retained for the running statistics.
    /// Must be `>= 2` so the sample-variance denominator (`n - 1`) is
    /// non-zero; values below 2 are rejected at construction.
    ///
    /// Typical values: 24 (hourly buckets over the last day), 168
    /// (hourly over the last week), 30 (daily over the last month).
    pub history_size: u16,

    /// Z-score above which a closed bucket's weighted sum is
    /// "anomalous." Must be strictly positive and finite — non-finite
    /// or `<= 0` values are rejected at construction so the per-event
    /// hot path never has to re-validate.
    ///
    /// Typical values: 3.0 (≈ 0.13% false-positive rate under
    /// normality), 4.0 (≈ 0.003%). Higher values trade recall for
    /// precision.
    pub threshold_z_score: f32,
}

/// An anomaly observation produced when a closed bucket crosses the
/// configured z-score threshold.
///
/// This is the typed payload the pattern-engine driver wraps into a
/// [`polaris_types::Observation`] with
/// [`polaris_types::ObservationKind::ReportVolumeAnomaly`]. The struct
/// intentionally does **not** include an
/// [`polaris_types::ObservationId`] or a free-form `evidence` value —
/// those are populated by the integration boundary, not by the
/// pure-function detector. Likewise category / severity tagging is the
/// driver's concern: the detector observes a single weighted stream.
#[derive(Debug, Clone)]
pub struct AnomalyObservation {
    /// The closed bucket's weighted volume — the sum of per-event
    /// reputation scores over the bucket's duration. `f64` because
    /// the bucket counter operates on weighted sums; the integration
    /// boundary narrows for the wire form if needed.
    pub weighted_volume: f64,

    /// The trailing-baseline mean over the history, as observed at
    /// emission time. Narrowed from the internal `f64` for the wire form.
    pub expected_mean: f32,

    /// The trailing-baseline standard deviation over the history.
    /// Narrowed from the internal `f64` for the wire form.
    pub expected_stddev: f32,

    /// Z-score above the trailing baseline, matching
    /// [`polaris_types::ObservationKind::ReportVolumeAnomaly::z_score`]
    /// exactly.
    pub z_score: f32,

    /// Detector confidence in `[0.0, 1.0]`, computed as
    /// `(z_score / threshold_z_score).clamp(0.0, 1.0)` — saturates at
    /// 1.0 once the spike reaches the threshold and grows no further.
    pub confidence: f32,

    /// When the bucket was *closed* — i.e. the bucket-aligned timestamp
    /// of the event whose arrival rolled the window forward.
    pub detected_at: DateTime<Utc>,
}

/// A rolling-window reputation-weighted report-volume anomaly
/// detector.
///
/// Implementations are single-task (`&mut self`) — see the module-level
/// "Why this shape" note. Implementors observe `(ts, weight)` tuples
/// and yield a typed [`AnomalyObservation`] iff the arrival closes a
/// prior bucket whose weighted sum crosses the configured
/// `threshold_z_score`.
pub trait ReportVolumeIndex {
    /// Observe a new report at time `ts`, contributing `weight` to the
    /// bucket's running weighted sum. Returns an
    /// [`AnomalyObservation`] iff this event's arrival closes a prior
    /// bucket whose weighted sum exceeds the configured z-score
    /// threshold against the now-updated baseline. Subsequent events
    /// landing in the same closed bucket do **not** re-emit.
    ///
    /// `weight` is intended to be a reporter's reputation score in
    /// `[0.0, 1.0]`. The detector does not clamp — non-finite weights
    /// would corrupt the Welford state and are rejected as no-ops; the
    /// caller is expected to pass a finite, bounded value (the
    /// [`crate::reputation::ReputationScore`] newtype already
    /// guarantees both).
    fn observe_report(&mut self, ts: DateTime<Utc>, weight: f64) -> Option<AnomalyObservation>;
}

/// In-memory [`ReportVolumeIndex`] implementation.
///
/// Per-bucket Welford state lives in a [`VecDeque`] of closed-bucket
/// weighted sums plus running `(n, mean, m2)` accumulators.
///
/// **Concurrency.** This type is not `Sync` — the pattern engine owns
/// one and drives it from a single task. Cross-task sharing requires
/// wrapping the value in `Arc<tokio::sync::Mutex<...>>` at the
/// integration boundary (see module docs).
#[derive(Debug)]
pub struct MemoryAnomalyDetector {
    cfg: AnomalyConfig,
    state: Option<BucketState>,
}

/// Rolling-window detector state.
///
/// Holds the closed-bucket history, the in-progress current bucket,
/// and the Welford accumulators over the history. The
/// `last_emit_bucket` field is the per-bucket dedup token: each closed
/// bucket emits at most once.
#[derive(Debug)]
struct BucketState {
    /// Closed-bucket weighted sums, oldest at the front. Bounded above
    /// by `cfg.history_size`.
    history: VecDeque<f64>,
    /// Epoch-aligned start of the currently-accumulating bucket.
    current_bucket_start: DateTime<Utc>,
    /// Running weighted sum of events that landed in the current
    /// bucket so far.
    current_weight: f64,
    /// Number of closed-bucket weighted sums currently contributing to
    /// `welford_mean` / `welford_m2`. Always equal to `history.len()`.
    welford_n: u64,
    /// Running mean over the history. `f64` for numerical stability.
    welford_mean: f64,
    /// Running sum of squared deviations from `welford_mean`. `f64` for
    /// numerical stability.
    welford_m2: f64,
    /// Start timestamp of the most recently emitted-for bucket. Used to
    /// suppress duplicate emissions if the same bucket somehow re-tests
    /// (defence-in-depth — the close path only fires the emit branch
    /// once per close, but this guards against future code that adds a
    /// secondary emission path).
    last_emit_bucket: Option<DateTime<Utc>>,
}

impl MemoryAnomalyDetector {
    /// Construct a new in-memory anomaly detector with the given
    /// configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError::InvalidConfig`] when:
    /// - `cfg.threshold_z_score` is not finite or `<= 0.0`,
    /// - `cfg.bucket_duration` is zero,
    /// - `cfg.history_size < 2` (sample variance is undefined for
    ///   fewer than two closed buckets).
    pub fn new(cfg: AnomalyConfig) -> Result<Self, PatternError> {
        if !cfg.threshold_z_score.is_finite() || cfg.threshold_z_score <= 0.0 {
            return Err(PatternError::InvalidConfig(
                "threshold_z_score must be finite and > 0",
            ));
        }
        if cfg.bucket_duration.is_zero() {
            return Err(PatternError::InvalidConfig("bucket_duration must be > 0"));
        }
        if cfg.history_size < 2 {
            return Err(PatternError::InvalidConfig(
                "history_size must be >= 2 for sample variance",
            ));
        }
        Ok(Self { cfg, state: None })
    }

    /// Returns the configured threshold / window / history size for
    /// debugging and observability surfaces. The detector does not
    /// expose mutable access to its configuration — bucket statistics
    /// straddling a re-config would be undefined.
    #[must_use]
    pub fn config(&self) -> &AnomalyConfig {
        &self.cfg
    }

    /// Pre-populate the history with a prior bucket's weighted sum.
    /// Intended for cold-start seeding from the database — the
    /// pattern-engine driver loads the last `history_size` buckets'
    /// weighted-volume aggregates and pushes them in chronological
    /// order so the detector starts with a populated baseline instead
    /// of having to wait `history_size` real buckets before its first
    /// useful emission.
    ///
    /// `bucket_start` is taken as-is (no re-alignment) so the driver
    /// can use whatever bucket boundaries the database query already
    /// produced. If more than `history_size` buckets are seeded the
    /// oldest are evicted with the Welford removal formula.
    ///
    /// Non-finite or negative `weighted_sum` values are silently
    /// ignored — the detector never accepts state that would corrupt
    /// Welford. Production seeding from the dashboard query always
    /// produces non-negative finite values.
    pub fn seed_bucket(&mut self, bucket_start: DateTime<Utc>, weighted_sum: f64) {
        if !weighted_sum.is_finite() || weighted_sum < 0.0 {
            return;
        }
        let history_cap = usize::from(self.cfg.history_size);
        let state = self.state.get_or_insert_with(|| BucketState {
            history: VecDeque::with_capacity(history_cap),
            current_bucket_start: bucket_start,
            current_weight: 0.0,
            welford_n: 0,
            welford_mean: 0.0,
            welford_m2: 0.0,
            last_emit_bucket: None,
        });
        Self::push_history(state, weighted_sum, history_cap);
        // Advance the current-bucket cursor so the next observation
        // lands in a later bucket than the seeded ones.
        state.current_bucket_start = bucket_start;
        state.current_weight = 0.0;
    }

    /// Compute the epoch-aligned bucket start for a given timestamp.
    ///
    /// Bucket boundaries are multiples of `bucket_duration` from the
    /// Unix epoch. This makes them deterministic across detector
    /// instances and independent of event arrival order, which is
    /// important for both test reproducibility and operator intuition
    /// ("the 14:00 bucket is the same bucket no matter who is asking").
    fn align_to_bucket(&self, at: DateTime<Utc>) -> DateTime<Utc> {
        let bucket_secs = self.cfg.bucket_duration.as_secs();
        if bucket_secs == 0 {
            // Defence-in-depth — construction-time validation rejects
            // zero-duration buckets, so this branch is unreachable.
            return at;
        }
        let ts = at.timestamp();
        // `bucket_secs` is u64 and `ts` is i64. We need an i64 modulus.
        // Constructor caps history at u16, but the bucket width is a
        // `Duration` — we clamp to i64::MAX to keep the modulus well-
        // defined for pathological configurations.
        #[allow(
            clippy::cast_possible_wrap,
            reason = "bucket_secs values that would wrap to negative are\
 absurd (>292 billion years); the saturating cast keeps the modulus well-defined."
        )]
        let bucket_secs_i64 = bucket_secs.min(i64::MAX as u64) as i64;
        let aligned = ts - ts.rem_euclid(bucket_secs_i64);
        DateTime::<Utc>::from_timestamp(aligned, 0).unwrap_or(at)
    }

    /// Push `weighted_sum` onto the back of `history` and update Welford
    /// `(n, mean, m2)`. If the deque is already at `cap`, evict the
    /// front and remove its contribution from Welford first.
    fn push_history(state: &mut BucketState, weighted_sum: f64, cap: usize) {
        if state.history.len() >= cap {
            if let Some(evicted) = state.history.pop_front() {
                Self::welford_remove(state, evicted);
            }
        }
        state.history.push_back(weighted_sum);
        Self::welford_add(state, weighted_sum);
    }

    /// Welford "add `x`" step. See module-level docs for the formula.
    #[allow(
        clippy::cast_precision_loss,
        reason = "welford_n is bounded by history_size <= u16::MAX; \
exactly representable in f64."
    )]
    fn welford_add(state: &mut BucketState, x: f64) {
        state.welford_n += 1;
        let n_f = state.welford_n as f64;
        let delta = x - state.welford_mean;
        state.welford_mean += delta / n_f;
        let delta2 = x - state.welford_mean; // uses the NEW mean
        state.welford_m2 += delta * delta2;
    }

    /// Welford "remove `x`" step. See module-level docs for the formula.
    /// Inverse of [`Self::welford_add`].
    #[allow(
        clippy::cast_precision_loss,
        reason = "welford_n is bounded by history_size <= u16::MAX; \
exactly representable in f64."
    )]
    fn welford_remove(state: &mut BucketState, x: f64) {
        let new_n = state.welford_n.saturating_sub(1);
        if new_n == 0 {
            state.welford_n = 0;
            state.welford_mean = 0.0;
            state.welford_m2 = 0.0;
            return;
        }
        let n_f = state.welford_n as f64;
        let new_n_f = new_n as f64;
        let new_mean = (n_f * state.welford_mean - x) / new_n_f;
        state.welford_m2 -= (x - state.welford_mean) * (x - new_mean);
        // Floating-point error can leave m2 slightly negative when the
        // true variance is zero; clamp to keep stddev real-valued.
        if state.welford_m2 < 0.0 {
            state.welford_m2 = 0.0;
        }
        state.welford_mean = new_mean;
        state.welford_n = new_n;
    }

    /// Sample variance over the history (`m2 / (n - 1)`), or `None` if
    /// fewer than two closed buckets exist.
    fn sample_variance(state: &BucketState) -> Option<f64> {
        if state.welford_n < 2 {
            return None;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "welford_n is bounded by history_size <= u16::MAX; \
exactly representable in f64."
        )]
        let denom = (state.welford_n - 1) as f64;
        Some(state.welford_m2 / denom)
    }

    /// Compute the z-score of `weighted_sum` against the current
    /// Welford statistics. Returns `None` when the history is too
    /// small for sample variance or when the standard deviation is
    /// exactly zero (perfectly stationary history — see module docs
    /// for the rationale).
    fn z_score(state: &BucketState, weighted_sum: f64) -> Option<f64> {
        let variance = Self::sample_variance(state)?;
        if variance <= 0.0 {
            return None;
        }
        let stddev = variance.sqrt();
        if stddev == 0.0 {
            return None;
        }
        Some((weighted_sum - state.welford_mean) / stddev)
    }
}

impl ReportVolumeIndex for MemoryAnomalyDetector {
    fn observe_report(&mut self, ts: DateTime<Utc>, weight: f64) -> Option<AnomalyObservation> {
        // Reject non-finite weights — they would corrupt Welford state
        // across every subsequent observation. Negative weights are
        // also dropped; callers source these from a
        // `ReputationScore` newtype that already guarantees the value
        // lies in `[0.0, 1.0]`, but the silent drop is defence in
        // depth for the future case where the call site grows a
        // different source.
        if !weight.is_finite() || weight < 0.0 {
            return None;
        }

        let aligned = self.align_to_bucket(ts);
        let history_cap = usize::from(self.cfg.history_size);
        let threshold = f64::from(self.cfg.threshold_z_score);

        let state = self.state.get_or_insert_with(|| BucketState {
            history: VecDeque::with_capacity(history_cap),
            current_bucket_start: aligned,
            current_weight: 0.0,
            welford_n: 0,
            welford_mean: 0.0,
            welford_m2: 0.0,
            last_emit_bucket: None,
        });

        // Fast path: event lands in the current bucket — accumulate
        // weight and return. No close, no emit.
        if aligned == state.current_bucket_start {
            state.current_weight += weight;
            return None;
        }

        // Out-of-order event landing in an already-closed bucket. We
        // do not retroactively re-open closed buckets — that would
        // require either re-running Welford from scratch or carrying a
        // per-bucket undo log, neither of which buys us anything
        // operationally meaningful (reports usually arrive in
        // chronological order). Drop the event silently.
        if aligned < state.current_bucket_start {
            return None;
        }

        // Slow path: event lands in a future bucket. Close the current
        // bucket, push it onto the history, run the z-score test, then
        // open a new current bucket at `aligned` and credit the event's
        // weight.
        let closed_weight = state.current_weight;
        let closed_start = state.current_bucket_start;
        Self::push_history(state, closed_weight, history_cap);

        let emission = match Self::z_score(state, closed_weight) {
            Some(z) if z > threshold && state.last_emit_bucket != Some(closed_start) => {
                state.last_emit_bucket = Some(closed_start);
                Some(build_observation(
                    closed_weight,
                    state.welford_mean,
                    state.welford_m2,
                    state.welford_n,
                    z,
                    self.cfg.threshold_z_score,
                    closed_start,
                ))
            }
            _ => None,
        };

        // Open the new bucket and credit the triggering event.
        state.current_bucket_start = aligned;
        state.current_weight = weight;

        emission
    }
}

/// Materialize the emitted observation. Pulled out so the slow path is
/// readable; takes the f64 Welford values and the f64 z-score, narrows
/// to f32 for the wire form, and clamps the confidence to `[0, 1]`.
#[allow(
    clippy::cast_possible_truncation,
    reason = "f64 -> f32 narrowing is required by the wire-form \
shape (ObservationKind::ReportVolumeAnomaly carries f32). For realistic \
weighted sums the narrowing is well within f32 precision."
)]
fn build_observation(
    weighted_volume: f64,
    welford_mean: f64,
    welford_m2: f64,
    welford_n: u64,
    z_score: f64,
    threshold_z_score: f32,
    detected_at: DateTime<Utc>,
) -> AnomalyObservation {
    let expected_mean = welford_mean as f32;
    let expected_stddev = if welford_n >= 2 {
        #[allow(
            clippy::cast_precision_loss,
            reason = "welford_n is bounded by history_size <= u16::MAX."
        )]
        let denom = (welford_n - 1) as f64;
        (welford_m2 / denom).sqrt() as f32
    } else {
        0.0_f32
    };
    let z_score_f32 = z_score as f32;
    let confidence = (z_score_f32 / threshold_z_score).clamp(0.0, 1.0);
    AnomalyObservation {
        weighted_volume,
        expected_mean,
        expected_stddev,
        z_score: z_score_f32,
        confidence,
        detected_at,
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
    use chrono::TimeZone;
    use proptest::prelude::*;

    fn cfg(bucket_secs: u64, history_size: u16, threshold: f32) -> AnomalyConfig {
        AnomalyConfig {
            bucket_duration: Duration::from_secs(bucket_secs),
            history_size,
            threshold_z_score: threshold,
        }
    }

    /// Test-fixture timestamp. The base `1_700_006_400` is chosen
    /// because it is exactly divisible by 3600 (and therefore by every
    /// realistic test bucket width — 60s, 120s, 600s, 3600s), so
    /// `at(b * bucket_secs)` lands on the start of bucket `b` under
    /// the detector's epoch-aligned bucket boundaries.
    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_006_400 + secs, 0)
            .single()
            .expect("valid utc timestamp")
    }

    // -- 1. Config validation ------------------------------------------

    #[test]
    fn rejects_non_positive_or_non_finite_threshold() {
        let cases: [f32; 4] = [0.0, -1.0, f32::NAN, f32::INFINITY];
        for t in cases {
            let err = MemoryAnomalyDetector::new(cfg(60, 16, t)).unwrap_err();
            match err {
                PatternError::InvalidConfig(msg) => {
                    assert!(msg.contains("threshold_z_score"), "msg = {msg}");
                }
            }
        }
    }

    #[test]
    fn rejects_zero_bucket_duration() {
        let err = MemoryAnomalyDetector::new(cfg(0, 16, 3.0)).unwrap_err();
        match err {
            PatternError::InvalidConfig(msg) => {
                assert!(msg.contains("bucket_duration"), "msg = {msg}");
            }
        }
    }

    #[test]
    fn rejects_history_size_below_two() {
        for h in [0_u16, 1_u16] {
            let err = MemoryAnomalyDetector::new(cfg(60, h, 3.0)).unwrap_err();
            match err {
                PatternError::InvalidConfig(msg) => {
                    assert!(msg.contains("history_size"), "msg = {msg}");
                }
            }
        }
    }

    // -- 2. Stationary low-rate samples never emit ---------------------

    #[test]
    fn stationary_low_rate_never_emits() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 32, 3.0)).expect("ok");
        // Drive 64 buckets of exactly 5 weight=1.0 reports each —
        // completely stationary, z-score is undefined (stddev = 0) and
        // the detector treats that as not-an-anomaly.
        for b in 0..64_i64 {
            for i in 0..5_i64 {
                let trigger = det.observe_report(at(b * 60 + i), 1.0);
                assert!(
                    trigger.is_none(),
                    "stationary samples must not emit (b={b}, i={i})"
                );
            }
        }
    }

    // -- 3. Burst crosses threshold ------------------------------------

    #[test]
    fn burst_after_low_baseline_emits_with_z_above_threshold() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        // 16 buckets of low, slightly varying counts to populate the
        // history with a non-zero stddev: weight=1.0 events, count
        // alternates 2,3,2,3,...; weighted sums alternate 2.0, 3.0,
        // averaging 2.5, stddev ~ 0.5. A bucket of 50 weight=1.0
        // events (weighted = 50.0) is z = (50 - 2.5)/0.5 ≈ 95 — well
        // past threshold.
        for b in 0..16_i64 {
            let count = if b % 2 == 0 { 2 } else { 3 };
            for i in 0..count {
                det.observe_report(at(b * 60 + i), 1.0);
            }
        }
        // Burst bucket: 50 weight=1.0 reports in bucket 16. The
        // emission will fire when bucket 17 opens.
        for i in 0..50 {
            det.observe_report(at(16 * 60 + i), 1.0);
        }
        let trigger = det.observe_report(at(17 * 60), 1.0);
        let obs = trigger.expect("burst bucket of weighted=50 must emit on close");
        assert!(
            (obs.weighted_volume - 50.0).abs() < f64::EPSILON,
            "weighted_volume should be 50.0, got {}",
            obs.weighted_volume
        );
        assert!(
            obs.z_score > 3.0,
            "z_score should exceed threshold, got {}",
            obs.z_score
        );
        assert!(
            obs.confidence >= 1.0 - f32::EPSILON,
            "z >> threshold should saturate confidence to 1.0, got {}",
            obs.confidence
        );
    }

    // -- 4. Per-bucket dedup -------------------------------------------

    #[test]
    fn per_closed_bucket_emits_at_most_once() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        // Seed baseline.
        for b in 0..16_i64 {
            let count = if b % 2 == 0 { 2 } else { 3 };
            for i in 0..count {
                det.observe_report(at(b * 60 + i), 1.0);
            }
        }
        // Burst bucket 16 with 50 reports.
        for i in 0..50 {
            det.observe_report(at(16 * 60 + i), 1.0);
        }
        // Multiple events in the *next* bucket — only the first one
        // should close bucket 16 and emit. Subsequent events in bucket
        // 17 update the in-progress weight and do not re-emit for
        // bucket 16.
        let first = det.observe_report(at(17 * 60), 1.0);
        let second = det.observe_report(at(17 * 60 + 1), 1.0);
        let third = det.observe_report(at(17 * 60 + 2), 1.0);
        assert!(first.is_some(), "first close emits");
        assert!(
            second.is_none() && third.is_none(),
            "no re-emit for the same closed bucket"
        );
    }

    // -- 5. Welford numerical stability --------------------------------

    #[test]
    fn welford_running_mean_stays_stable_over_100k_updates() {
        // Drive 100,000 events with exactly 5 weight=1.0 events per
        // bucket over 20,000 buckets. Each closed bucket has weighted
        // sum 5.0 → the running mean must be exactly 5.0 (within f64
        // round-off, much tighter than f32 epsilon). The test proves
        // Welford does not drift on a large stationary sample — naive
        // sum-of-squares would accumulate cancellation error
        // proportional to the sample count.
        let mut det = MemoryAnomalyDetector::new(cfg(60, 1024, 3.0)).expect("ok");
        for b in 0..20_000_i64 {
            for i in 0..5_i64 {
                det.observe_report(at(b * 60 + i), 1.0);
            }
        }
        // Drive one more event to close bucket 20,000 — stationary
        // 100k-event stream must never emit.
        let trigger = det.observe_report(at(20_001 * 60), 1.0);
        assert!(
            trigger.is_none(),
            "stationary 100k-event stream must never emit, got {trigger:?}",
        );
    }

    // -- Seed-bucket cold start ----------------------------------------

    #[test]
    fn seeded_history_enables_first_real_bucket_to_emit() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        // Seed 16 buckets of slightly-varying weighted sums to give
        // the detector a non-zero stddev before any real events
        // arrive.
        for b in 0..16_i64 {
            let weighted = if b % 2 == 0 { 2.0 } else { 3.0 };
            det.seed_bucket(at(b * 60), weighted);
        }
        // Now drive a burst on the *first* real bucket — without
        // seeding this would require 16+ real buckets before the
        // baseline was populated.
        for i in 0..50 {
            det.observe_report(at(20 * 60 + i), 1.0);
        }
        let trigger = det.observe_report(at(21 * 60), 1.0);
        let obs = trigger.expect("seeded history enables first-bucket emission");
        assert!((obs.weighted_volume - 50.0).abs() < f64::EPSILON);
        assert!(obs.z_score > 3.0);
    }

    #[test]
    fn seed_bucket_rejects_non_finite_and_negative_values() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        // None of these should populate the history.
        det.seed_bucket(at(0), f64::NAN);
        det.seed_bucket(at(60), f64::INFINITY);
        det.seed_bucket(at(120), -1.0);
        // A subsequent legitimate observation should behave as on a
        // fresh detector — no history, no emission possible.
        let trigger = det.observe_report(at(180), 1.0);
        assert!(trigger.is_none(), "no state should have been seeded");
    }

    // -- Out-of-order events drop silently -----------------------------

    #[test]
    fn out_of_order_events_to_closed_buckets_drop_silently() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        // Advance to bucket 5.
        det.observe_report(at(5 * 60), 1.0);
        // Out-of-order event at bucket 1 should be dropped — no
        // emission, no panic, no state corruption.
        let dropped = det.observe_report(at(60), 1.0);
        assert!(dropped.is_none(), "out-of-order event must drop silently");
        // Forward progress still works.
        let _ = det.observe_report(at(6 * 60), 1.0);
    }

    // -- Non-finite weights drop silently ------------------------------

    #[test]
    fn non_finite_and_negative_weights_drop_silently() {
        let mut det = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        // Drive baseline.
        for b in 0..16_i64 {
            det.observe_report(at(b * 60), 1.0);
        }
        // Stuff a bunch of corrupting weights into bucket 16 — none
        // should land. The detector must not panic, must not corrupt
        // Welford state, and (after the close on bucket 17) must not
        // emit an anomaly attributable to the rejected events.
        for i in 0..50_i64 {
            det.observe_report(at(16 * 60 + i), f64::NAN);
            det.observe_report(at(16 * 60 + i), f64::INFINITY);
            det.observe_report(at(16 * 60 + i), -0.5);
        }
        // Close bucket 16 — the closed weighted sum should be 0.0
        // (matches the prior baseline), so no anomaly.
        let trigger = det.observe_report(at(17 * 60), 1.0);
        assert!(
            trigger.is_none(),
            "rejected weights must not produce an emission, got {trigger:?}"
        );
    }

    // -- 77c.1: weighted-equivalence — 100×1.0 ≡ 200×0.5 ---------------

    /// Feeding 100 weight=1.0 events per bucket should yield the same
    /// running statistics as 200 weight=0.5 events per bucket — both
    /// accumulate to identical bucket-level weighted sums, so
    /// Welford's `(n, mean, m2)` must agree across the two scenarios
    /// once the histories are populated. Equivalence is demonstrated
    /// through the public surface: drive identical per-bucket
    /// weighted-volume *patterns* through both detectors (using
    /// different `(event_count, weight)` decompositions), trigger a
    /// matching spike against each, and assert the emitted
    /// observations agree on `expected_mean` / `expected_stddev` /
    /// `z_score`.
    #[test]
    fn weighted_equivalence_unit_weight_vs_half_weight() {
        let mut det_a = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");
        let mut det_b = MemoryAnomalyDetector::new(cfg(60, 16, 3.0)).expect("ok");

        // Per-bucket weighted-volume targets: alternating 100.0 /
        // 110.0 to give Welford a non-zero stddev. Scenario A reaches
        // each target with weight=1.0 events (so the integer event
        // count matches the weighted sum); scenario B reaches the
        // same target with twice as many weight=0.5 events.
        for b in 0..16_i64 {
            let unit_events = if b % 2 == 0 { 100 } else { 110 };
            let half_events = unit_events * 2;
            for i in 0..unit_events {
                // weight=1.0 ⇒ bucket weighted sum = unit_events
                det_a.observe_report(at(b * 60 + (i % 60)), 1.0);
            }
            for i in 0..half_events {
                // weight=0.5 ⇒ bucket weighted sum = half_events * 0.5
                //                                  = unit_events
                det_b.observe_report(at(b * 60 + (i % 60)), 0.5);
            }
        }

        // Drive a spike of weighted-volume 500.0 into bucket 16 for
        // each detector; this is well above the alternating
        // 100 / 110 baseline so the z-score crossing is unambiguous.
        for i in 0..500_i64 {
            det_a.observe_report(at(16 * 60 + (i % 60)), 1.0);
        }
        for i in 0..1000_i64 {
            det_b.observe_report(at(16 * 60 + (i % 60)), 0.5);
        }

        // Close bucket 16 by stepping forward.
        let spike_a = det_a.observe_report(at(17 * 60), 1.0);
        let spike_b = det_b.observe_report(at(17 * 60), 0.5);
        let obs_a = spike_a.expect("scenario A (weight=1.0) spike should emit");
        let obs_b = spike_b.expect("scenario B (weight=0.5) spike should emit");

        // The two detectors are fed identical per-bucket weighted
        // sums, so their Welford state agrees and the emitted
        // observation statistics must match within f32 tolerance.
        let tol = 1.0_f32;
        assert!(
            (obs_a.expected_mean - obs_b.expected_mean).abs() < tol,
            "expected_mean should agree: a={}, b={}",
            obs_a.expected_mean,
            obs_b.expected_mean
        );
        assert!(
            (obs_a.expected_stddev - obs_b.expected_stddev).abs() < tol,
            "expected_stddev should agree: a={}, b={}",
            obs_a.expected_stddev,
            obs_b.expected_stddev
        );
        assert!(
            (obs_a.z_score - obs_b.z_score).abs() < tol,
            "z_score should agree: a={}, b={}",
            obs_a.z_score,
            obs_b.z_score
        );
        assert!(
            (obs_a.weighted_volume - obs_b.weighted_volume).abs() < f64::from(tol),
            "weighted_volume should agree: a={}, b={}",
            obs_a.weighted_volume,
            obs_b.weighted_volume
        );
    }

    // -- 77c.2: low-rep flood vs legitimate burst ----------------------

    /// A flood of 1000 weight=0.05 events spread uniformly across many
    /// buckets is indistinguishable from a low-volume steady-state
    /// stream after reputation weighting — no bucket spikes, no
    /// anomaly emission. By contrast 50 weight=1.0 events concentrated
    /// in a single bucket against a quiet baseline produces a clear
    /// z-score spike. This is the central reputation-weighting
    /// invariant: a low-reputation flood cannot manufacture a
    /// high-confidence anomaly signal merely by raising the event
    /// rate.
    #[test]
    fn low_rep_flood_does_not_emit_legit_burst_does() {
        // Scenario A: 1000 weight=0.05 events spread uniformly across
        // 50 buckets ⇒ 20 events/bucket × 0.05 = 1.0 weighted/bucket,
        // perfectly stationary, zero stddev, no anomaly.
        let mut det_flood = MemoryAnomalyDetector::new(cfg(60, 32, 3.0)).expect("ok");
        for b in 0..50_i64 {
            for i in 0..20_i64 {
                let trigger = det_flood.observe_report(at(b * 60 + i), 0.05);
                assert!(
                    trigger.is_none(),
                    "low-rep flood must not emit during accumulation, got {trigger:?}"
                );
            }
        }
        // Close the final bucket. The weighted sum is the same as the
        // baseline — no anomaly.
        let flood_close = det_flood.observe_report(at(50 * 60), 0.05);
        assert!(
            flood_close.is_none(),
            "low-rep flood must not produce an anomaly on close, got {flood_close:?}"
        );

        // Scenario B: low baseline of weight=1.0 events (one event
        // every other bucket, alternating with two-event buckets to
        // create non-zero stddev) + a single-bucket burst of 50
        // weight=1.0 events from established reporters. Weighted sum
        // of the burst = 50.0; against the small baseline this is a
        // large z-score and the detector emits.
        let mut det_legit = MemoryAnomalyDetector::new(cfg(60, 32, 3.0)).expect("ok");
        for b in 0..32_i64 {
            let count = if b % 2 == 0 { 1 } else { 2 };
            for i in 0..count {
                det_legit.observe_report(at(b * 60 + i), 1.0);
            }
        }
        // Burst bucket 32.
        for i in 0..50_i64 {
            det_legit.observe_report(at(32 * 60 + i), 1.0);
        }
        let legit_close = det_legit.observe_report(at(33 * 60), 1.0);
        let obs = legit_close
            .expect("legitimate burst against quiet baseline must emit a high-confidence anomaly");
        assert!(
            (obs.weighted_volume - 50.0).abs() < f64::EPSILON,
            "legitimate burst weighted_volume should be 50.0, got {}",
            obs.weighted_volume
        );
        assert!(
            obs.z_score > 3.0,
            "legitimate burst should produce z >> threshold, got {}",
            obs.z_score
        );
    }

    proptest! {
        /// Stationary property: under N uniformly-distributed
        /// weight=1.0 counts per bucket, false-positive emissions are
        /// rare. At threshold 3.0 with 32 buckets of history and a
        /// per-bucket count uniformly in `[3, 8]`, the
        /// burst-mass-on-arrival has to exceed roughly the high end
        /// of the range to fire — i.e. the false-positive rate is
        /// expected to be near zero on this distribution. We bound
        /// the rate at "no more than 10% of trials emit at all" to
        /// keep the test non-flaky while still catching gross
        /// regressions (e.g. a sign flip that makes the detector fire
        /// on every bucket).
        #[test]
        fn stationary_uniform_samples_have_low_false_positive_rate(
            counts in proptest::collection::vec(3_u64..=8_u64, 64..=64),
        ) {
            let mut det = MemoryAnomalyDetector::new(cfg(60, 32, 3.0)).expect("ok");
            let mut emissions = 0_usize;
            #[allow(clippy::cast_possible_wrap, reason = "indices bounded by vec len")]
            for (b, &c) in counts.iter().enumerate() {
                for i in 0..c {
                    #[allow(clippy::cast_possible_wrap, reason = "per-bucket count <= 8")]
                    let t = at((b as i64) * 60 + i as i64);
                    if det.observe_report(t, 1.0).is_some() {
                        emissions += 1;
                    }
                }
            }
            prop_assert!(
                emissions <= 6,
                "false positives should be rare on stationary uniform input; got {} of 64",
                emissions,
            );
        }
    }
}
