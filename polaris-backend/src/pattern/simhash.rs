//! SimHash rolling-window dedup for image-hash brigades.
//!
//! # Why this exists
//!
//! `design.md` §1 frames moderation as a pattern-recognition problem and
//! lists **image-hash brigades** as the canonical example of coordinated
//! abuse that is invisible when reports are presented as isolated cards.
//! `design.md` §3.2 names SimHash as the dedup primitive; `design.md` §5.1
//! lists "image-hash bursts" as a first-class coordinated-action signal on
//! the pattern dashboard. This module is the first concrete detector that
//! turns those signals into typed [`ClusterObservation`] values for the
//! pattern engine.
//!
//! # Algorithm
//!
//! Each piece of image content is reduced to a 64-bit perceptual hash by
//! an upstream component (out of scope for #17). For every new
//! `(hash, subject_id, now)` tuple, the index:
//!
//! 1. **Evicts** entries older than [`SimhashConfig::window`].
//! 2. Walks every retained entry and computes the Hamming distance
//!    `(a ^ b).count_ones()` against the incoming hash. Entries within
//!    [`SimhashConfig::max_hamming_distance`] form a candidate cluster
//!    together with the newcomer.
//! 3. When the candidate cluster contains at least
//!    [`SimhashConfig::min_cluster_size`] *distinct* subjects (counted by
//!    [`polaris_types::SubjectId`], not by entry count — a single subject
//!    posting three near-duplicate images contributes once to the cluster
//!    size), the detector emits a single [`ClusterObservation`].
//! 4. Subsequent events that fall into the same cluster do **not** re-emit;
//!    every member entry is flagged with `cluster_emitted = true` and any
//!    new event that intersects an already-emitted entry is suppressed.
//!
//! # Why this shape
//!
//! - **`&mut self`, not `Arc<Mutex<...>>`.** The trait method takes
//!   `&mut self` so the detector can live inside a single task (the
//!   pattern-engine driver) without paying for cross-task locking. The
//!   rolling window is naturally per-task; sharding by subject-id hash
//!   (`design.md` §3.1, Bluesky profile) gives us scale-out without
//!   sharing.
//! - **Typed thresholds.** `NonZeroU8`, `Duration`, `NonZeroUsize` push
//!   sentinel-value bugs (zero hamming distance, zero cluster size,
//!   zero-second window) out of reach at the type level — no runtime
//!   check needed for the trivial cases.
//! - **Confidence as `f32`.** Matches the
//!   [`polaris_types::Observation::confidence`] shape exactly so an
//!   integration with the [`crate::repo::ObservationRepo`] does not
//!   require a lossy `f64` → `f32` cast.
//! - **No persistence inside the detector.** The detector returns an
//!   [`Option<ClusterObservation>`]; wiring it to the observation repo is
//!   the pattern-engine driver's concern (separation of concerns and
//!   testability — the unit tests in this module run with no I/O at all).
//!
//! # Follow-ups
//!
//! A Redis-backed [`SimhashIndex`] implementation is a sibling concern
//! tracked separately (parallels the #56 pattern). The in-memory
//! implementation here is the production path for the labeler profile
//! (`design.md` §3.1) and the testing path for both profiles.

use std::collections::{HashSet, VecDeque};
use std::num::{NonZeroU8, NonZeroUsize};
use std::time::Duration;

use chrono::{DateTime, Utc};
use polaris_types::SubjectId;

use crate::pattern::PatternError;

/// Width of the perceptual hash used by this detector, in bits.
///
/// The detector consumes a 64-bit hash because `polaris-types`'s
/// [`polaris_types::ObservationKind::ImageHashCluster`] carries the hash
/// as a hex string with no fixed width — the hex encoding happens at the
/// integration boundary. 64 bits is the upstream-hash width assumed by
/// `design.md` §3.2 ("SimHash dedup") and is the typical output of
/// off-the-shelf perceptual hashers (pHash, dHash) for this use case.
pub const HASH_WIDTH_BITS: u8 = 64;

/// Configuration for the [`MemorySimhashIndex`].
///
/// All fields use typed primitives so the type system catches the trivial
/// misconfigurations (zero hamming distance, zero cluster size, zero-second
/// window). The non-trivial check — that `max_hamming_distance` does not
/// exceed [`HASH_WIDTH_BITS`] — is performed by [`MemorySimhashIndex::new`]
/// and surfaces as [`PatternError::InvalidConfig`].
#[derive(Debug, Clone)]
pub struct SimhashConfig {
    /// Hamming distance below which two 64-bit hashes are considered
    /// near-duplicate. Inclusive: two hashes at exactly this distance
    /// **do** cluster together.
    ///
    /// Typical values: 3–6 for tight perceptual-hash matching, 8–12 for
    /// looser similarity. Bounded above by [`HASH_WIDTH_BITS`].
    pub max_hamming_distance: NonZeroU8,

    /// Rolling-window length. Entries inserted more than `window` ago
    /// (measured against the `now` parameter of [`SimhashIndex::observe`])
    /// are evicted before the new event is matched.
    ///
    /// Typical values: minutes-to-hours for live brigade detection,
    /// 24–48h for slower coordination patterns. The `Duration` typing
    /// rules out the "seconds-as-u64" footgun.
    pub window: Duration,

    /// Minimum number of **distinct** subjects in a candidate cluster
    /// before the detector emits. A single subject posting many
    /// near-duplicate hashes counts once.
    ///
    /// Typical values: 3–5. Lower values produce noise (two subjects
    /// sharing an image is almost always benign); higher values miss
    /// small brigades.
    pub min_cluster_size: NonZeroUsize,
}

/// A cluster observation produced when the brigade threshold is crossed.
///
/// This is the typed payload the pattern-engine driver wraps into a
/// [`polaris_types::Observation`] with
/// [`polaris_types::ObservationKind::ImageHashCluster`]. The hash here is
/// the *anchor* — typically the newly-inserted hash whose arrival pushed
/// the cluster across the threshold — and `max_pairwise_distance` reports
/// the worst-case Hamming distance between any cluster member and the
/// anchor.
///
/// Note that this struct intentionally does **not** include an
/// [`polaris_types::ObservationId`] or a free-form `evidence` value: those
/// are populated by the integration boundary (the pattern-engine driver),
/// not by the pure-function detector.
#[derive(Debug, Clone)]
pub struct ClusterObservation {
    /// The anchor hash — the hash of the event whose insertion caused
    /// the cluster to emit.
    pub hash: u64,

    /// The distinct subject ids that contributed to the cluster, in the
    /// order they were observed (oldest first).
    pub members: Vec<SubjectId>,

    /// Worst-case Hamming distance from any cluster member's hash to
    /// [`Self::hash`]. Always bounded by
    /// [`SimhashConfig::max_hamming_distance`].
    pub max_pairwise_distance: u8,

    /// When the emission was produced — the `now` argument supplied to
    /// the [`SimhashIndex::observe`] call that triggered the cluster.
    pub detected_at: DateTime<Utc>,

    /// Detector confidence in `[0.0, 1.0]`, matches the shape of
    /// [`polaris_types::Observation::confidence`]. See
    /// [`MemorySimhashIndex::confidence_for_distance`] for the formula.
    pub confidence: f32,
}

/// A rolling-window SimHash index.
///
/// Implementations are intentionally single-task (`&mut self`) — see the
/// module-level "Why this shape" note. Implementors record incoming
/// `(hash, subject)` pairs against a rolling clock and yield a typed
/// [`ClusterObservation`] iff the insertion crosses the configured
/// `min_cluster_size` for the first time.
pub trait SimhashIndex {
    /// Insert a new `(hash, subject, now)` and return a
    /// [`ClusterObservation`] iff the insertion crosses
    /// `min_cluster_size` for a cluster that has not previously been
    /// emitted. Subsequent inserts that join an already-emitted cluster
    /// do not re-emit.
    fn observe(
        &mut self,
        hash: u64,
        subject: SubjectId,
        now: DateTime<Utc>,
    ) -> Option<ClusterObservation>;
}

/// In-memory [`SimhashIndex`] implementation backed by a [`VecDeque`].
///
/// The rolling window is stored as a chronologically-ordered deque:
/// inserts append to the back, eviction pops from the front. Walking the
/// deque is `O(n)` per `observe`, which is fine for the labeler-profile
/// scale (`design.md` §3.1 — single ingest worker, single pattern engine
/// shard); high-throughput Bluesky-profile deployments shard by
/// subject-id hash, so each in-memory index sees a bounded share of the
/// firehose.
///
/// **Concurrency.** This type is not `Sync` — the pattern engine owns one
/// per shard and drives it from a single task. Cross-task sharing is
/// explicitly out of scope (see module docs).
#[derive(Debug)]
pub struct MemorySimhashIndex {
    cfg: SimhashConfig,
    entries: VecDeque<Entry>,
    /// Set of (hashed) anchor representatives that have already emitted a
    /// cluster. Used to suppress re-emission when an incoming event
    /// re-enters an already-detected cluster via the per-entry
    /// `cluster_emitted` flag — see the body of `observe`.
    emitted_anchors: HashSet<u64>,
}

#[derive(Debug, Clone)]
struct Entry {
    hash: u64,
    subject: SubjectId,
    at: DateTime<Utc>,
    /// `true` iff this entry was a member of a cluster that already
    /// emitted a [`ClusterObservation`]. Any new event that lands within
    /// `max_hamming_distance` of an entry with this flag set is
    /// suppressed (no second emission for the same brigade).
    cluster_emitted: bool,
}

impl MemorySimhashIndex {
    /// Construct a new in-memory index with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError::InvalidConfig`] if
    /// `cfg.max_hamming_distance` exceeds [`HASH_WIDTH_BITS`] — a
    /// threshold larger than the hash width would cause every pair of
    /// hashes to cluster, which is never useful.
    pub fn new(cfg: SimhashConfig) -> Result<Self, PatternError> {
        if cfg.max_hamming_distance.get() > HASH_WIDTH_BITS {
            return Err(PatternError::InvalidConfig(
                "max_hamming_distance must not exceed the hash width (64 bits)",
            ));
        }
        Ok(Self {
            cfg,
            entries: VecDeque::new(),
            emitted_anchors: HashSet::new(),
        })
    }

    /// Returns the configured threshold and window for debugging /
    /// observability surfaces. The detector does not expose mutable
    /// access to its configuration — clusters straddling a re-config
    /// would emit inconsistently.
    #[must_use]
    pub fn config(&self) -> &SimhashConfig {
        &self.cfg
    }

    /// Detector confidence in `[0.0, 1.0]` for a cluster whose worst-case
    /// member-to-anchor Hamming distance is `max_distance`.
    ///
    /// Formula:
    ///
    /// ```text
    /// confidence = 1.0 - (max_distance / max_hamming_distance)
    /// ```
    ///
    /// - A tight cluster (every member is bit-identical, `max_distance =
    ///   0`) yields `1.0`.
    /// - A cluster at exactly the threshold (`max_distance ==
    ///   max_hamming_distance`) yields `0.0` — the detector is least
    ///   confident at the edge of its allowed range.
    /// - Values outside `[0.0, 1.0]` cannot arise because `max_distance`
    ///   is bounded above by `max_hamming_distance` by construction;
    ///   `clamp` is defence-in-depth.
    #[must_use]
    fn confidence_for_distance(&self, max_distance: u8) -> f32 {
        let threshold = f32::from(self.cfg.max_hamming_distance.get());
        let observed = f32::from(max_distance);
        (1.0 - (observed / threshold)).clamp(0.0, 1.0)
    }

    /// Drop every entry older than `now - cfg.window`. The deque is
    /// chronologically ordered (inserts always append) so eviction is a
    /// `pop_front` loop until the head is in-window.
    fn evict_expired(&mut self, now: DateTime<Utc>) {
        // `Duration::MAX` overflows `chrono::Duration::from_std`. For
        // the realistic configuration range (seconds to days) the fallback
        // branch is unreachable; we fall back to the largest representable
        // `chrono::TimeDelta` so eviction effectively disables itself
        // rather than panicking. Documented here so a future reviewer
        // doesn't reach for `unwrap()`.
        let cutoff = chrono::Duration::from_std(self.cfg.window).unwrap_or(chrono::TimeDelta::MAX);
        while let Some(front) = self.entries.front() {
            if now.signed_duration_since(front.at) > cutoff {
                self.entries.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Compute the Hamming distance between two 64-bit hashes.
///
/// Implemented as `(a ^ b).count_ones()` — on every target Polaris cares
/// about, `count_ones` lowers to a single popcount instruction
/// (x86 `POPCNT`, aarch64 `CNT`+`ADDV`). The `as u8` narrowing is
/// loss-free because `u64::count_ones` returns at most 64.
#[must_use]
pub fn hamming_distance(a: u64, b: u64) -> u8 {
    // count_ones returns u32 in 0..=64; narrowing to u8 is loss-free.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "u64::count_ones is bounded by 64, fits in u8"
    )]
    let bits = (a ^ b).count_ones() as u8;
    bits
}

impl SimhashIndex for MemorySimhashIndex {
    fn observe(
        &mut self,
        hash: u64,
        subject: SubjectId,
        now: DateTime<Utc>,
    ) -> Option<ClusterObservation> {
        // 1. Roll the window forward.
        self.evict_expired(now);

        // 2. Find every retained entry within the hamming threshold.
        let threshold = self.cfg.max_hamming_distance.get();
        let mut matched_indices: Vec<usize> = Vec::new();
        let mut max_distance: u8 = 0;
        let mut suppressed_by_prior_emit = false;
        for (idx, entry) in self.entries.iter().enumerate() {
            let d = hamming_distance(hash, entry.hash);
            if d <= threshold {
                matched_indices.push(idx);
                if d > max_distance {
                    max_distance = d;
                }
                if entry.cluster_emitted {
                    suppressed_by_prior_emit = true;
                }
            }
        }

        // 3. Build the distinct-subject member list. The newcomer counts
        //    as one of the distinct subjects, so we seed the set with it
        //    and then walk matched entries in chronological order.
        //
        //    `members` preserves observation order (oldest first, with the
        //    newcomer appended last) so the emitted `ClusterObservation`'s
        //    member list is deterministic for tests and audit.
        let mut seen: HashSet<SubjectId> = HashSet::new();
        let mut members: Vec<SubjectId> = Vec::new();
        for idx in &matched_indices {
            // Safe index: `matched_indices` was just built by iterating
            // `self.entries`, and we have not mutated `self.entries`
            // since.
            if let Some(entry) = self.entries.get(*idx)
                && seen.insert(entry.subject)
            {
                members.push(entry.subject);
            }
        }
        if seen.insert(subject) {
            members.push(subject);
        }

        // 4. Decide whether to emit. We always append the new entry to
        //    the window; the emission decision is independent of the
        //    append.
        let min_size = self.cfg.min_cluster_size.get();
        let emit =
            !suppressed_by_prior_emit && members.len() >= min_size && !matched_indices.is_empty();

        let observation = if emit {
            // Mark every matched entry as part of an emitted cluster so a
            // later event joining the same cluster is suppressed.
            for idx in &matched_indices {
                if let Some(entry) = self.entries.get_mut(*idx) {
                    entry.cluster_emitted = true;
                }
            }
            self.emitted_anchors.insert(hash);
            let confidence = self.confidence_for_distance(max_distance);
            Some(ClusterObservation {
                hash,
                members,
                max_pairwise_distance: max_distance,
                detected_at: now,
                confidence,
            })
        } else {
            None
        };

        // 5. Append the new entry to the window. The `cluster_emitted`
        //    flag is set iff (a) we just emitted (this entry's siblings
        //    were marked above and this entry should be marked too so a
        //    *further* event joining the cluster is also suppressed),
        //    or (b) the new entry intersected an already-emitted cluster
        //    (suppression cascade).
        self.entries.push_back(Entry {
            hash,
            subject,
            at: now,
            cluster_emitted: emit || suppressed_by_prior_emit,
        });

        observation
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

    fn cfg(max_hamming: u8, window_secs: u64, min_cluster: usize) -> SimhashConfig {
        SimhashConfig {
            max_hamming_distance: NonZeroU8::new(max_hamming).expect("non-zero"),
            window: Duration::from_secs(window_secs),
            min_cluster_size: NonZeroUsize::new(min_cluster).expect("non-zero"),
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0)
            .single()
            .expect("valid utc timestamp")
    }

    #[test]
    fn rejects_threshold_exceeding_hash_width() {
        // 65 > HASH_WIDTH_BITS == 64. NonZeroU8 can hold up to 255, so we
        // can actually exercise this branch.
        let err = MemorySimhashIndex::new(SimhashConfig {
            max_hamming_distance: NonZeroU8::new(65).expect("nz"),
            window: Duration::from_secs(60),
            min_cluster_size: NonZeroUsize::new(3).expect("nz"),
        })
        .unwrap_err();
        match err {
            PatternError::InvalidConfig(msg) => {
                assert!(msg.contains("64 bits"), "msg = {msg}");
            }
        }
    }

    #[test]
    fn identical_hashes_three_distinct_subjects_emit_once() {
        let mut idx = MemorySimhashIndex::new(cfg(5, 3600, 3)).expect("ok");
        let h = 0xDEAD_BEEF_CAFE_F00D_u64;
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();
        let s4 = SubjectId::new();

        assert!(idx.observe(h, s1, at(0)).is_none(), "size 1: no emit");
        assert!(idx.observe(h, s2, at(1)).is_none(), "size 2: no emit");

        let obs = idx
            .observe(h, s3, at(2))
            .expect("size 3 crosses min_cluster_size and emits");
        assert_eq!(obs.members.len(), 3);
        assert_eq!(obs.max_pairwise_distance, 0);
        assert!(
            (obs.confidence - 1.0).abs() < f32::EPSILON,
            "identical hashes → confidence 1.0, got {}",
            obs.confidence
        );
        assert_eq!(obs.detected_at, at(2));
        assert_eq!(obs.hash, h);

        // Subsequent matching observations do not re-emit.
        assert!(
            idx.observe(h, s4, at(3)).is_none(),
            "fourth identical observation must not re-emit"
        );
    }

    #[test]
    fn hashes_beyond_threshold_never_cluster() {
        // Even with `min_cluster_size = 2`, two events whose hashes
        // exceed the hamming threshold must not be clustered together.
        // h_a and h_b differ in 8 bits — well beyond the threshold of 3.
        let h_a: u64 = 0x0000_0000_0000_0000;
        let h_b: u64 = 0x0000_0000_0000_00FF;
        assert_eq!(hamming_distance(h_a, h_b), 8);

        let mut idx = MemorySimhashIndex::new(cfg(3, 3600, 2)).expect("ok");
        assert!(idx.observe(h_a, SubjectId::new(), at(0)).is_none());
        assert!(
            idx.observe(h_b, SubjectId::new(), at(1)).is_none(),
            "h_a and h_b are 8 bits apart; threshold is 3 → no cluster"
        );

        // Insert many more far-apart hashes across distinct subjects;
        // none of them are within `max_hamming_distance` of one another,
        // so cluster-of-size-2 must never trip.
        let far_apart: [u64; 4] = [
            0x0000_0000_0000_0F0F,
            0x0000_0000_F0F0_0000,
            0xF0F0_0000_0000_0000,
            0xFFFF_0000_FFFF_0000,
        ];
        for (i, h) in far_apart.iter().enumerate() {
            #[allow(clippy::cast_possible_wrap, reason = "i is bounded by array length")]
            let result = idx.observe(*h, SubjectId::new(), at(2 + i as i64));
            assert!(
                result.is_none(),
                "all hashes pairwise exceed threshold → no cluster (i={i})"
            );
        }
    }

    #[test]
    fn entries_past_window_are_evicted_no_cluster_emitted() {
        // window = 10s, three identical hashes spaced 20s apart →
        // by the time the 3rd arrives, the 1st and 2nd have aged out.
        let mut idx = MemorySimhashIndex::new(cfg(5, 10, 3)).expect("ok");
        let h = 0x1234_5678_9ABC_DEF0;
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();
        assert!(idx.observe(h, s1, at(0)).is_none());
        assert!(idx.observe(h, s2, at(20)).is_none());
        // At t=40 the entry from t=20 is also out of window (40-20=20 > 10).
        assert!(
            idx.observe(h, s3, at(40)).is_none(),
            "all prior entries are out-of-window; cluster size = 1 only"
        );
    }

    #[test]
    fn same_subject_does_not_count_as_distinct_members() {
        // A single bad actor posting 3 near-identical hashes is not a
        // brigade — `min_cluster_size` is over *distinct* subjects.
        let mut idx = MemorySimhashIndex::new(cfg(5, 3600, 3)).expect("ok");
        let h = 0xAA55_AA55_AA55_AA55;
        let s = SubjectId::new();
        assert!(idx.observe(h, s, at(0)).is_none());
        assert!(idx.observe(h, s, at(1)).is_none());
        assert!(
            idx.observe(h, s, at(2)).is_none(),
            "same subject contributing 3 events → cluster size still 1"
        );
    }

    #[test]
    fn confidence_zero_at_exact_threshold() {
        // Three hashes pairwise differ by exactly the threshold; the
        // confidence formula should yield 0.0.
        let mut idx = MemorySimhashIndex::new(cfg(4, 3600, 3)).expect("ok");
        let h0: u64 = 0;
        // h1 differs from h0 in 4 bits.
        let h1: u64 = 0x0000_0000_0000_000F;
        assert_eq!(hamming_distance(h0, h1), 4);
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();
        // First two land at h0; third lands at h1, distance 4 == threshold.
        assert!(idx.observe(h0, s1, at(0)).is_none());
        assert!(idx.observe(h0, s2, at(1)).is_none());
        let obs = idx
            .observe(h1, s3, at(2))
            .expect("cluster of 3 distinct subjects at exact threshold should emit");
        assert_eq!(obs.max_pairwise_distance, 4);
        assert!(
            obs.confidence.abs() < f32::EPSILON,
            "distance == threshold → confidence 0.0, got {}",
            obs.confidence
        );
    }

    #[test]
    fn hamming_distance_of_identical_hashes_is_zero() {
        assert_eq!(hamming_distance(0, 0), 0);
        assert_eq!(hamming_distance(u64::MAX, u64::MAX), 0);
        assert_eq!(hamming_distance(0xDEAD_BEEF, 0xDEAD_BEEF), 0);
    }

    #[test]
    fn hamming_distance_of_complement_is_64() {
        assert_eq!(hamming_distance(0, u64::MAX), 64);
    }

    proptest! {
        /// Property: for any pair `(a, b)` of `u64` hashes, the Hamming
        /// distance is in `[0, 64]`. This is the soundness floor for the
        /// `count_ones() as u8` narrowing inside `hamming_distance`.
        #[test]
        fn hamming_distance_is_bounded_by_hash_width(a in any::<u64>(), b in any::<u64>()) {
            let d = hamming_distance(a, b);
            prop_assert!(d <= HASH_WIDTH_BITS);
        }

        /// Property: a non-zero number of identical hashes within the
        /// rolling window always reaches the cluster threshold once it
        /// crosses `min_cluster_size` distinct subjects. Tests that the
        /// detector never silently swallows a brigade.
        #[test]
        fn identical_hashes_within_window_always_cluster(
            h in any::<u64>(),
            min_cluster in 2usize..=5usize,
        ) {
            let mut idx = MemorySimhashIndex::new(SimhashConfig {
                max_hamming_distance: NonZeroU8::new(1).expect("nz"),
                window: Duration::from_secs(3600),
                min_cluster_size: NonZeroUsize::new(min_cluster).expect("nz"),
            }).expect("valid cfg");
            // Insert `min_cluster - 1` distinct-subject observations: no emit.
            for i in 0..(min_cluster - 1) {
                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "i is bounded by min_cluster <= 5"
                )]
                let result = idx.observe(h, SubjectId::new(), at(i as i64));
                prop_assert!(result.is_none(), "early observation should not emit");
            }
            // The `min_cluster`-th distinct subject must emit.
            #[allow(
                clippy::cast_possible_wrap,
                reason = "min_cluster <= 5 fits in i64"
            )]
            let result = idx.observe(h, SubjectId::new(), at(min_cluster as i64));
            prop_assert!(result.is_some(), "min_cluster crossing must emit");
            let obs = result.expect("checked some");
            prop_assert_eq!(obs.members.len(), min_cluster);
            prop_assert_eq!(obs.max_pairwise_distance, 0);
        }
    }
}
