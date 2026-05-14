//! MinHash + LSH for sock-puppet cohort detection.
//!
//! # Why this exists
//!
//! `design.md` §1 lists **sock-puppet rings** as the canonical coordinated-abuse
//! pattern that is invisible when reports are presented as isolated cards.
//! `design.md` §3.2 names MinHash as the cohort-detection primitive;
//! `design.md` §5.1 surfaces "account cohorts created within narrow windows"
//! as a first-class coordinated-action signal on the pattern dashboard.
//! This module turns that signal into typed [`CohortObservation`] values for
//! the pattern engine, complementing the [`super::simhash`] image-hash
//! brigade detector (#17) with an account-level analogue.
//!
//! # Algorithm
//!
//! 1. **Feature extraction is the caller's concern.** Each account is
//!    summarized by a feature set — a slice of `u64` hashes capturing
//!    handle-creation hour, posting-cadence shingles, reply-graph
//!    fingerprints, and similar signals. The detector accepts the bag of
//!    hashes pre-computed; turning ATProto firehose events into those
//!    hashes lives upstream (the pattern-engine driver), not in this
//!    module.
//! 2. **MinHash signature.** With `K = num_perm` permutations, each
//!    permutation `i` reduces the feature set to one `u64` (the minimum
//!    of `a_i * f + b_i` over `f` in the set). The signature is the
//!    vector of `K` minima. Two accounts' signatures agree at position
//!    `i` with probability equal to their Jaccard similarity — that is
//!    the property the LSH banding exploits.
//! 3. **LSH banding.** The signature is partitioned into `num_bands`
//!    bands of `band_rows` rows each (with `num_perm == num_bands *
//!    band_rows`, enforced at construction). Each band hashes to a
//!    single `u64`; accounts whose band hashes collide in **any** band
//!    are LSH candidates. The `num_bands` × `band_rows` knob trades
//!    recall against precision: more bands = higher recall, more rows
//!    per band = higher precision.
//! 4. **Cohort emission.** When `min_cohort_size` *distinct* accounts
//!    share a band-hash within the rolling window, a single
//!    [`CohortObservation`] is emitted. The same `(band_idx, band_hash)`
//!    pair never re-emits — subsequent accounts that join an already-
//!    detected cohort are silently absorbed (see [`MemoryMinhashIndex`]
//!    docs).
//!
//! # Why this shape
//!
//! - **`&mut self`, not `Arc<Mutex<...>>`.** The trait method takes
//!   `&mut self` so the detector lives inside a single task (the
//!   pattern-engine driver). Sharding by subject-id hash (`design.md`
//!   §3.1, Bluesky profile) gives scale-out without sharing.
//! - **Typed configuration.** `NonZeroU16` and `NonZeroUsize` push the
//!   trivial misconfigurations (zero permutations, zero bands, zero
//!   rows, zero cohort size, zero-duration window) out of reach at the
//!   type level. The single non-trivial invariant — `num_perm ==
//!   num_bands * band_rows` — is verified at [`MemoryMinhashIndex::new`]
//!   and surfaces as [`PatternError::InvalidConfig`].
//! - **`f32` similarity.** Matches
//!   [`polaris_types::Observation::confidence`] exactly; the wire-form
//!   `f64` footgun (`design.md` §5.1 rust-quality note) never appears.
//! - **Deterministic permutations.** A fixed seed makes signatures
//!   reproducible across runs and across test invocations — required
//!   for the property test that asserts identical feature sets yield
//!   identical signatures.
//! - **No persistence in the detector.** The detector returns
//!   `Option<CohortObservation>`; wiring it to
//!   [`crate::repo::ObservationRepo`] is the pattern-engine driver's
//!   concern. The unit tests in this module run with no I/O at all.
//!
//! # Follow-ups
//!
//! A Redis-backed [`MinhashIndex`] for the Bluesky profile is a sibling
//! concern tracked separately. The in-memory implementation here is the
//! production path for the labeler profile (`design.md` §3.1) and the
//! testing path for both profiles.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::num::{NonZeroU16, NonZeroUsize};
use std::time::Duration;

use chrono::{DateTime, Utc};
use polaris_types::SubjectId;

use crate::pattern::PatternError;

/// Deterministic seed for the universal-hash family used by
/// [`MemoryMinhashIndex::minhash`].
///
/// Picked so the `(a, b)` coefficients derived from it cover the full
/// `u64` space and are reproducible run-to-run. The constant is
/// load-bearing for the property test: it is the reason "identical
/// feature sets produce identical signatures" holds across distinct
/// `MemoryMinhashIndex` instances.
const MINHASH_PERMUTATION_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// `b` coefficient for the universal-hash family. Co-prime with `2^64`
/// (odd) and a `splitmix64`-style mixer constant so consecutive
/// permutation indices yield well-distributed coefficients.
const MINHASH_PERMUTATION_STEP: u64 = 0xBF58_476D_1CE4_E5B9;

/// Configuration for the [`MemoryMinhashIndex`].
///
/// All numeric fields are `NonZero*` so the trivial misconfigurations
/// (zero permutations, zero bands, zero rows, zero cohort size) are
/// rejected at the type level. The single non-trivial invariant —
/// `num_perm == num_bands * band_rows` — is verified by
/// [`MemoryMinhashIndex::new`].
#[derive(Debug, Clone)]
pub struct MinhashConfig {
    /// Number of MinHash permutations. Equals the signature length.
    ///
    /// Typical values: 64–256. Higher `num_perm` increases the
    /// granularity of the Jaccard estimate at linear cost in signature
    /// computation and memory.
    pub num_perm: NonZeroU16,

    /// Number of LSH bands. Must satisfy `num_perm == num_bands *
    /// band_rows`; mismatches are rejected by [`MemoryMinhashIndex::new`].
    ///
    /// Typical values: 16–32. More bands trades precision for recall —
    /// a candidate cohort matches if **any** band hash collides.
    pub num_bands: NonZeroU16,

    /// Rows per band. Must satisfy `num_perm == num_bands * band_rows`.
    ///
    /// Typical values: 4–8. More rows per band tightens the per-band
    /// similarity threshold ([`band_rows`] rows must agree for a
    /// collision, equivalent to a per-band Jaccard floor of roughly
    /// `(1 / num_bands)^(1 / band_rows)`).
    ///
    /// [`band_rows`]: Self::band_rows
    pub band_rows: NonZeroU16,

    /// Rolling-window length. Entries inserted more than `window` ago
    /// (measured against the `now` parameter of
    /// [`MinhashIndex::observe`]) are evicted before the new event is
    /// matched. `Duration` typing rules out the "seconds-as-u64"
    /// footgun.
    pub window: Duration,

    /// Minimum number of **distinct** accounts in a cohort before the
    /// detector emits. A single account observed many times counts
    /// once.
    ///
    /// Typical values: 3–5. Lower values produce noise (a pair of
    /// near-duplicate accounts is almost always coincidence); higher
    /// values miss small rings.
    pub min_cohort_size: NonZeroUsize,
}

/// A cohort observation produced when the sock-puppet threshold is
/// crossed.
///
/// This is the typed payload the pattern-engine driver wraps into a
/// [`polaris_types::Observation`] with
/// [`polaris_types::ObservationKind::AccountCohort`]. The `cohort_id`
/// here is the band-hash that triggered the emission — opaque to the
/// caller, stable for the lifetime of the rolling window, useful only
/// for de-duplication against re-emission.
///
/// Note that this struct intentionally does **not** include an
/// [`polaris_types::ObservationId`] or a free-form `evidence` value:
/// those are populated by the integration boundary (the pattern-engine
/// driver), not by the pure-function detector.
#[derive(Debug, Clone)]
pub struct CohortObservation {
    /// The band-hash that triggered the cohort emission. Opaque to the
    /// caller; stable for the lifetime of the rolling window.
    pub cohort_id: u64,

    /// The distinct account ids that contributed to the cohort, in the
    /// order they were observed (oldest first, with the newcomer
    /// appended last).
    pub members: Vec<SubjectId>,

    /// Detector confidence in `[0.0, 1.0]`, computed as the fraction of
    /// LSH bands across which **every** member shares a band-hash with
    /// the newcomer. This is a Jaccard-similarity estimate: with `K`
    /// permutations split into `B` bands of `R` rows, the probability
    /// that one band collides is `J^R`, so the expected fraction of
    /// matching bands over `B` bands is itself an estimator for `J`
    /// (more precisely, of `J^R`; the formula deliberately reports the
    /// raw fraction so the caller can interpret it without round-tripping
    /// through the LSH parameters).
    pub similarity_estimate: f32,

    /// When the emission was produced — the `now` argument supplied to
    /// the [`MinhashIndex::observe`] call that triggered the cohort.
    pub detected_at: DateTime<Utc>,
}

/// A rolling-window MinHash + LSH index over per-account feature sets.
///
/// Implementations are intentionally single-task (`&mut self`) — see
/// the module-level "Why this shape" note. Implementors record incoming
/// `(account, feature_hashes, now)` tuples against a rolling clock and
/// yield a typed [`CohortObservation`] iff the insertion pushes a band
/// past the configured `min_cohort_size` for the first time.
pub trait MinhashIndex {
    /// Observe a new account with its pre-computed feature hashes.
    ///
    /// Returns a [`CohortObservation`] iff the insertion crosses
    /// `min_cohort_size` for an LSH band that has not previously
    /// emitted. Subsequent inserts that join an already-emitted band do
    /// not re-emit. Re-observing the same `account` is a no-op for the
    /// distinct-member count.
    fn observe(
        &mut self,
        account: SubjectId,
        feature_hashes: &[u64],
        now: DateTime<Utc>,
    ) -> Option<CohortObservation>;
}

/// In-memory [`MinhashIndex`] implementation backed by a per-band
/// [`HashMap`] and a chronologically-ordered [`VecDeque`] of entries.
///
/// The rolling window is stored both as a chronologically-ordered deque
/// (so eviction is `O(eviction_count)` per `observe` via repeated
/// `pop_front`) and as a per-band map from band-hash to set-of-accounts
/// (so candidate lookup is `O(num_bands)`). Walking the per-account
/// signature on insert is `O(num_perm * feature_count)`, which is
/// linear in both knobs and fine for the labeler-profile scale
/// (`design.md` §3.1 — single ingest worker, single pattern engine
/// shard). High-throughput Bluesky-profile deployments shard by
/// subject-id hash, so each in-memory index sees a bounded share of
/// the firehose.
///
/// **Concurrency.** This type is not `Sync` — the pattern engine owns
/// one per shard and drives it from a single task. Cross-task sharing
/// is explicitly out of scope (see module docs).
#[derive(Debug)]
pub struct MemoryMinhashIndex {
    cfg: MinhashConfig,
    /// `bands[i]` maps band-hash → set of accounts whose `i`-th band
    /// hashed to that value within the rolling window.
    bands: Vec<HashMap<u64, HashSet<SubjectId>>>,
    /// Chronologically-ordered entries. Inserts append to the back,
    /// eviction pops from the front. Stores per-account band hashes so
    /// eviction can remove the account from every band's map without
    /// recomputing the signature.
    entries: VecDeque<Entry>,
    /// `(band_idx, band_hash)` pairs that have already produced a
    /// [`CohortObservation`]. Subsequent accounts joining the same
    /// pair are silently absorbed: no second emission for the same
    /// detected cohort.
    emitted_bands: HashSet<(usize, u64)>,
    /// `BuildHasher` for the LSH band hashes. `RandomState` is
    /// per-instance non-deterministic, but it is deterministic *within*
    /// a process — two `band_hashes` calls on the same instance with
    /// the same signature yield the same band hashes. That is the
    /// guarantee we need; cross-instance reproducibility is provided
    /// by the MinHash signature, which uses a fixed seed.
    band_hasher: std::collections::hash_map::RandomState,
}

#[derive(Debug, Clone)]
struct Entry {
    subject: SubjectId,
    /// One band-hash per band; length equals `cfg.num_bands.get() as
    /// usize`.
    band_hashes: Vec<u64>,
    at: DateTime<Utc>,
}

impl MemoryMinhashIndex {
    /// Construct a new in-memory index with the given configuration.
    ///
    /// # Errors
    ///
    /// Returns [`PatternError::InvalidConfig`] if `cfg.num_perm` does
    /// not equal `cfg.num_bands * cfg.band_rows` — the LSH banding
    /// requires the signature to partition exactly into bands.
    pub fn new(cfg: MinhashConfig) -> Result<Self, PatternError> {
        // `u32` is wide enough to hold the product of two `u16`s
        // without overflow; we cast to `u32` rather than `u64` because
        // `num_perm` is itself a `u16`.
        let expected = u32::from(cfg.num_bands.get()) * u32::from(cfg.band_rows.get());
        let actual = u32::from(cfg.num_perm.get());
        if expected != actual {
            return Err(PatternError::InvalidConfig(
                "num_perm must equal num_bands * band_rows",
            ));
        }
        let num_bands = usize::from(cfg.num_bands.get());
        let bands = (0..num_bands).map(|_| HashMap::new()).collect();
        Ok(Self {
            cfg,
            bands,
            entries: VecDeque::new(),
            emitted_bands: HashSet::new(),
            band_hasher: std::collections::hash_map::RandomState::new(),
        })
    }

    /// Borrow the configured parameters for debugging / observability.
    /// The detector does not expose mutable configuration access:
    /// cohorts straddling a re-config would emit inconsistently.
    #[must_use]
    pub fn config(&self) -> &MinhashConfig {
        &self.cfg
    }

    /// Compute the `num_perm`-length MinHash signature of a feature
    /// set.
    ///
    /// For each permutation `i`, the hash is the minimum over `f` in
    /// `feature_hashes` of `a_i.wrapping_mul(f) ^ b_i`, where
    /// `(a_i, b_i)` are deterministic functions of `i` and the fixed
    /// seed [`MINHASH_PERMUTATION_SEED`]. An empty feature set yields
    /// `u64::MAX` for every position — a degenerate signature that
    /// will not collide with any real-feature account because real
    /// accounts have at least one feature hash with a non-`u64::MAX`
    /// minimum (probability `1 - 2^-64` per permutation).
    fn minhash(&self, feature_hashes: &[u64]) -> Vec<u64> {
        let k = usize::from(self.cfg.num_perm.get());
        let mut signature = Vec::with_capacity(k);
        for i in 0..k {
            // Derive `(a_i, b_i)` from the permutation index. Both
            // are forced odd so the multiplication is a bijection on
            // `u64` (preserving "min over a permutation" semantics).
            let i_u64 = i as u64;
            let a = MINHASH_PERMUTATION_SEED
                .wrapping_mul(i_u64.wrapping_add(1))
                .wrapping_add(MINHASH_PERMUTATION_STEP)
                | 1;
            let b = MINHASH_PERMUTATION_STEP
                .wrapping_mul(i_u64.wrapping_add(1))
                .wrapping_add(MINHASH_PERMUTATION_SEED);
            let mut min_h = u64::MAX;
            for &f in feature_hashes {
                let h = a.wrapping_mul(f) ^ b;
                if h < min_h {
                    min_h = h;
                }
            }
            signature.push(min_h);
        }
        signature
    }

    /// Partition a MinHash signature into `num_bands` band-hashes by
    /// feeding each `band_rows`-length slice through the instance's
    /// `BuildHasher`.
    fn band_hashes(&self, signature: &[u64]) -> Vec<u64> {
        let num_bands = usize::from(self.cfg.num_bands.get());
        let band_rows = usize::from(self.cfg.band_rows.get());
        let mut out = Vec::with_capacity(num_bands);
        for band_idx in 0..num_bands {
            let start = band_idx * band_rows;
            let end = start + band_rows;
            // `start..end` is in-bounds: the constructor verified
            // `num_perm == num_bands * band_rows == signature.len()`,
            // and the loop is bounded by `num_bands` with stride
            // `band_rows`.
            let mut hasher = self.band_hasher.build_hasher();
            // Salt with the band index so two bands containing the
            // same row sequence (which can happen for highly-redundant
            // signatures) hash to different band-hashes.
            hasher.write_usize(band_idx);
            for &row in &signature[start..end] {
                hasher.write_u64(row);
            }
            out.push(hasher.finish());
        }
        out
    }

    /// Drop every entry older than `now - cfg.window`. The deque is
    /// chronologically ordered (inserts always append) so eviction is
    /// a `pop_front` loop until the head is in-window. Each evicted
    /// entry is also removed from every band's map.
    fn evict_expired(&mut self, now: DateTime<Utc>) {
        // `Duration::MAX` overflows `chrono::Duration::from_std`. For
        // the realistic configuration range (seconds to days) the
        // fallback branch is unreachable; we fall back to the largest
        // representable `chrono::TimeDelta` so eviction effectively
        // disables itself rather than panicking. Mirrors the pattern
        // in `super::simhash::MemorySimhashIndex::evict_expired`.
        let cutoff = chrono::Duration::from_std(self.cfg.window).unwrap_or(chrono::TimeDelta::MAX);
        while let Some(front) = self.entries.front() {
            if now.signed_duration_since(front.at) > cutoff {
                // Front is out of window — evict it.
                if let Some(evicted) = self.entries.pop_front() {
                    for (band_idx, band_hash) in evicted.band_hashes.iter().enumerate() {
                        if let Some(map) = self.bands.get_mut(band_idx)
                            && let Some(set) = map.get_mut(band_hash)
                        {
                            set.remove(&evicted.subject);
                            if set.is_empty() {
                                map.remove(band_hash);
                            }
                        }
                    }
                }
            } else {
                break;
            }
        }
    }
}

impl MinhashIndex for MemoryMinhashIndex {
    fn observe(
        &mut self,
        account: SubjectId,
        feature_hashes: &[u64],
        now: DateTime<Utc>,
    ) -> Option<CohortObservation> {
        // 1. Roll the window forward before lookup so out-of-window
        //    entries can't contribute to cohort membership.
        self.evict_expired(now);

        // 2. Compute the signature and band hashes for the newcomer.
        let signature = self.minhash(feature_hashes);
        let band_hashes = self.band_hashes(&signature);

        // 3. Find a candidate cohort: across every band, collect the
        //    set of accounts (including the newcomer if it is already
        //    in the map for that band) sharing this band-hash. Pick
        //    the band with the largest member set and not previously
        //    emitted; if any band already crosses `min_cohort_size`,
        //    that is the cohort we emit on.
        //
        //    Tie-breaking: we walk bands in index order and stop at
        //    the first emit-eligible band. Deterministic for tests and
        //    audit; cohort detection is the goal, not exhaustive
        //    cohort enumeration (a second band that also triggers will
        //    fire on the next insert).
        let min_size = self.cfg.min_cohort_size.get();
        let mut chosen: Option<(usize, u64, Vec<SubjectId>)> = None;
        for (band_idx, band_hash) in band_hashes.iter().enumerate() {
            if self.emitted_bands.contains(&(band_idx, *band_hash)) {
                continue;
            }
            let mut members: Vec<SubjectId> = Vec::new();
            let mut seen: HashSet<SubjectId> = HashSet::new();
            // Order: existing members in insertion order, then the
            // newcomer. We walk `self.entries` once to get insertion
            // order for accounts at this band; the per-band map gives
            // us the membership set for O(1) test.
            if let Some(map) = self.bands.get(band_idx)
                && let Some(set) = map.get(band_hash)
            {
                for e in &self.entries {
                    if set.contains(&e.subject) && seen.insert(e.subject) {
                        members.push(e.subject);
                    }
                }
            }
            if seen.insert(account) {
                members.push(account);
            }
            if members.len() >= min_size {
                chosen = Some((band_idx, *band_hash, members));
                break;
            }
        }

        // 4. Build the observation (if any) before mutating the index
        //    state. The similarity estimate is the fraction of bands
        //    across which **every** chosen-cohort member shares the
        //    newcomer's band-hash — a Jaccard-similarity estimator
        //    consistent with the LSH banding (`design.md` §3.2).
        let observation = if let Some((_band_idx, band_hash, ref members)) = chosen {
            let similarity_estimate = self.similarity_for_cohort(members, &band_hashes);
            Some(CohortObservation {
                cohort_id: band_hash,
                members: members.clone(),
                similarity_estimate,
                detected_at: now,
            })
        } else {
            None
        };

        // 5. Insert the newcomer into every band's map and append to
        //    the chronological deque. Done **after** the candidate
        //    walk so the newcomer is counted exactly once (the manual
        //    `seen.insert(account)` above).
        for (band_idx, band_hash) in band_hashes.iter().enumerate() {
            if let Some(map) = self.bands.get_mut(band_idx) {
                map.entry(*band_hash).or_default().insert(account);
            }
        }
        self.entries.push_back(Entry {
            subject: account,
            band_hashes,
            at: now,
        });

        // 6. Mark the emitted band so re-entry does not re-emit.
        if let Some((band_idx, band_hash, _)) = chosen {
            self.emitted_bands.insert((band_idx, band_hash));
        }

        observation
    }
}

impl MemoryMinhashIndex {
    /// Estimate the cohort's Jaccard similarity as the fraction of
    /// LSH bands across which **every** cohort member shares the
    /// newcomer's band-hash.
    ///
    /// `members` is the full cohort including the newcomer;
    /// `newcomer_band_hashes` is the newcomer's per-band hash vector.
    /// For each band, we count it as "matching" iff every member
    /// (excluding the newcomer, who trivially matches) appears in
    /// the band's bucket at `newcomer_band_hashes[band_idx]`.
    ///
    /// Returns a value in `[0.0, 1.0]`. A perfect cohort (every
    /// member's band-hashes equal the newcomer's across every band)
    /// yields `1.0`; a cohort where only the triggering band matches
    /// yields `1.0 / num_bands`.
    fn similarity_for_cohort(&self, members: &[SubjectId], newcomer_band_hashes: &[u64]) -> f32 {
        let num_bands = usize::from(self.cfg.num_bands.get());
        if num_bands == 0 {
            // Unreachable: `NonZeroU16` rules this out. Defensive
            // default rather than a panic — the f32 cast cannot
            // divide by zero.
            return 0.0;
        }
        let mut matching_bands: u32 = 0;
        for (band_idx, band_hash) in newcomer_band_hashes.iter().enumerate() {
            let Some(map) = self.bands.get(band_idx) else {
                continue;
            };
            let Some(set) = map.get(band_hash) else {
                continue;
            };
            // Every prior member (members minus the newcomer at the
            // tail) must be in this bucket for the band to count.
            let prior_members = members.split_last().map_or(&[][..], |(_, rest)| rest);
            let all_present = prior_members.iter().all(|m| set.contains(m));
            if all_present {
                matching_bands += 1;
            }
        }
        // `num_bands` is a `u16` cast loss-free to f32; `matching_bands`
        // is bounded above by `num_bands` so the ratio is in `[0, 1]`.
        let total = f32::from(self.cfg.num_bands.get());
        // `matching_bands` is bounded by `num_bands <= u16::MAX`, so
        // `as f32` is loss-free.
        #[allow(
            clippy::cast_precision_loss,
            reason = "matching_bands is bounded by num_bands <= u16::MAX, well within f32 mantissa"
        )]
        let matching = matching_bands as f32;
        (matching / total).clamp(0.0, 1.0)
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

    fn cfg(
        num_perm: u16,
        num_bands: u16,
        band_rows: u16,
        window_secs: u64,
        min_cohort: usize,
    ) -> MinhashConfig {
        MinhashConfig {
            num_perm: NonZeroU16::new(num_perm).expect("non-zero"),
            num_bands: NonZeroU16::new(num_bands).expect("non-zero"),
            band_rows: NonZeroU16::new(band_rows).expect("non-zero"),
            window: Duration::from_secs(window_secs),
            min_cohort_size: NonZeroUsize::new(min_cohort).expect("non-zero"),
        }
    }

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_700_000_000 + secs, 0)
            .single()
            .expect("valid utc timestamp")
    }

    /// 1. Config validation: `num_perm = 128` and `num_bands * band_rows
    ///    = 64` is rejected with `InvalidConfig`.
    #[test]
    fn rejects_band_mismatch() {
        // num_perm = 128, num_bands = 8, band_rows = 8 → 64 != 128.
        let bad = MinhashConfig {
            num_perm: NonZeroU16::new(128).expect("nz"),
            num_bands: NonZeroU16::new(8).expect("nz"),
            band_rows: NonZeroU16::new(8).expect("nz"),
            window: Duration::from_secs(60),
            min_cohort_size: NonZeroUsize::new(3).expect("nz"),
        };
        let err = MemoryMinhashIndex::new(bad).unwrap_err();
        match err {
            PatternError::InvalidConfig(msg) => {
                assert!(
                    msg.contains("num_perm"),
                    "msg should mention num_perm, got {msg}"
                );
            }
        }
    }

    #[test]
    fn accepts_matching_band_product() {
        let ok = cfg(64, 16, 4, 60, 3);
        let idx = MemoryMinhashIndex::new(ok);
        assert!(idx.is_ok());
    }

    /// 2. Three accounts with identical feature sets emit a cohort.
    #[test]
    fn three_identical_feature_sets_emit_cohort() {
        let mut idx = MemoryMinhashIndex::new(cfg(64, 16, 4, 3600, 3)).expect("ok");
        let features: &[u64] = &[0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, 0xEEEE];
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();

        assert!(
            idx.observe(s1, features, at(0)).is_none(),
            "size 1: no emit"
        );
        assert!(
            idx.observe(s2, features, at(1)).is_none(),
            "size 2: no emit"
        );
        let obs = idx
            .observe(s3, features, at(2))
            .expect("size 3 should cross min_cohort_size and emit");
        assert_eq!(obs.members.len(), 3);
        assert_eq!(obs.detected_at, at(2));
        // Identical feature sets → identical signatures → identical band
        // hashes → similarity estimate ~ 1.0.
        assert!(
            (obs.similarity_estimate - 1.0).abs() < f32::EPSILON,
            "identical features → similarity 1.0, got {}",
            obs.similarity_estimate,
        );
    }

    /// 3. Three accounts with disjoint feature hashes never cluster.
    #[test]
    fn disjoint_features_do_not_cluster() {
        let mut idx = MemoryMinhashIndex::new(cfg(64, 16, 4, 3600, 2)).expect("ok");
        // Pathologically-disjoint hashes spaced wide apart in u64 space.
        let f1: &[u64] = &[0x0000_0000_0000_0001, 0x0000_0000_0000_0002];
        let f2: &[u64] = &[0xFFFF_FFFF_FFFF_FFFE, 0xFFFF_FFFF_FFFF_FFFD];
        let f3: &[u64] = &[0x5555_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA];

        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();
        assert!(idx.observe(s1, f1, at(0)).is_none());
        assert!(idx.observe(s2, f2, at(1)).is_none());
        // Pathologically unlikely to collide on any band, but the test
        // is probabilistic in principle. With 64 perms / 16 bands /
        // 4 rows and three disjoint feature sets, the band-collision
        // probability is astronomically small.
        assert!(
            idx.observe(s3, f3, at(2)).is_none(),
            "disjoint feature sets should not produce a cohort",
        );
    }

    /// 4. Same account observed multiple times does NOT count as
    ///    multiple distinct members.
    #[test]
    fn repeated_observation_of_same_account_does_not_inflate_cohort() {
        let mut idx = MemoryMinhashIndex::new(cfg(64, 16, 4, 3600, 3)).expect("ok");
        let features: &[u64] = &[0x1234, 0x5678, 0x9ABC];
        let s = SubjectId::new();
        assert!(idx.observe(s, features, at(0)).is_none());
        assert!(idx.observe(s, features, at(1)).is_none());
        assert!(
            idx.observe(s, features, at(2)).is_none(),
            "same account contributing 3 events → cohort size still 1",
        );
    }

    /// 5. Entries past `window` are evicted; same 3 accounts spread
    ///    over 2× window emit no cohort.
    #[test]
    fn entries_past_window_are_evicted_no_cohort_emitted() {
        let mut idx = MemoryMinhashIndex::new(cfg(64, 16, 4, 10, 3)).expect("ok");
        let features: &[u64] = &[0xCAFE, 0xBABE, 0xF00D];
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();
        // window = 10s, spacing = 20s → each new observation sees an
        // empty window because the prior entries are out-of-window.
        assert!(idx.observe(s1, features, at(0)).is_none());
        assert!(idx.observe(s2, features, at(20)).is_none());
        assert!(
            idx.observe(s3, features, at(40)).is_none(),
            "all prior entries out-of-window; cohort size = 1 only",
        );
    }

    /// 6. Cohort observation is single-emit: subsequent overlapping
    ///    observations don't re-emit on the same triggering band.
    #[test]
    fn cohort_emits_once_per_band() {
        let mut idx = MemoryMinhashIndex::new(cfg(64, 16, 4, 3600, 3)).expect("ok");
        let features: &[u64] = &[0x1111, 0x2222, 0x3333, 0x4444];
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();
        let s3 = SubjectId::new();
        let s4 = SubjectId::new();
        let s5 = SubjectId::new();

        assert!(idx.observe(s1, features, at(0)).is_none());
        assert!(idx.observe(s2, features, at(1)).is_none());
        let first = idx
            .observe(s3, features, at(2))
            .expect("size 3 should emit");
        let first_id = first.cohort_id;
        // The 4th and 5th observations join the same cohort: the same
        // triggering band should not re-emit.
        let fourth = idx.observe(s4, features, at(3));
        let fifth = idx.observe(s5, features, at(4));
        // At minimum: the triggering band must not re-emit. With 16
        // bands all hitting the same buckets for identical feature
        // sets, every band already emitted on the s3 insert, so no
        // re-emission is possible.
        if let Some(obs) = &fourth {
            assert_ne!(
                obs.cohort_id, first_id,
                "must not re-emit on the same triggering band",
            );
        }
        if let Some(obs) = &fifth {
            assert_ne!(
                obs.cohort_id, first_id,
                "must not re-emit on the same triggering band",
            );
        }
    }

    /// 7. Similarity estimate: identical feature sets → ~1.0; the
    ///    chosen-cohort similarity is the fraction of matching bands.
    #[test]
    fn similarity_estimate_is_one_for_identical_sets() {
        let mut idx = MemoryMinhashIndex::new(cfg(128, 32, 4, 3600, 2)).expect("ok");
        let features: &[u64] = &[0xDEAD, 0xBEEF, 0xCAFE, 0xBABE, 0xF00D];
        let s1 = SubjectId::new();
        let s2 = SubjectId::new();

        assert!(idx.observe(s1, features, at(0)).is_none());
        let obs = idx
            .observe(s2, features, at(1))
            .expect("size 2 should emit");
        assert!(
            (obs.similarity_estimate - 1.0).abs() < f32::EPSILON,
            "identical features → similarity 1.0, got {}",
            obs.similarity_estimate,
        );
    }

    proptest! {
        /// Property: identical feature sets always produce identical
        /// signatures (deterministic MinHash). This is the foundational
        /// guarantee for the LSH banding — without it the cohort
        /// detection is non-reproducible.
        #[test]
        fn identical_features_yield_identical_signatures(
            features in proptest::collection::vec(any::<u64>(), 1..16)
        ) {
            // Two distinct index instances should compute the same
            // signature for the same feature set — the fixed seed is
            // load-bearing.
            let idx_a = MemoryMinhashIndex::new(cfg(64, 16, 4, 3600, 3)).expect("ok");
            let idx_b = MemoryMinhashIndex::new(cfg(64, 16, 4, 3600, 3)).expect("ok");
            let sig_a = idx_a.minhash(&features);
            let sig_b = idx_b.minhash(&features);
            prop_assert_eq!(sig_a, sig_b);
        }

        /// Property: for any pair of accounts with identical feature
        /// sets, the cohort detector eventually emits once
        /// `min_cohort_size` distinct accounts are observed.
        #[test]
        fn identical_features_always_emit_at_threshold(
            features in proptest::collection::vec(any::<u64>(), 1..8),
            min_cohort in 2usize..=4usize,
        ) {
            let mut idx = MemoryMinhashIndex::new(MinhashConfig {
                num_perm: NonZeroU16::new(64).expect("nz"),
                num_bands: NonZeroU16::new(16).expect("nz"),
                band_rows: NonZeroU16::new(4).expect("nz"),
                window: Duration::from_secs(3600),
                min_cohort_size: NonZeroUsize::new(min_cohort).expect("nz"),
            }).expect("ok cfg");
            for i in 0..(min_cohort - 1) {
                #[allow(
                    clippy::cast_possible_wrap,
                    reason = "min_cohort <= 4 fits in i64"
                )]
                let r = idx.observe(SubjectId::new(), &features, at(i as i64));
                prop_assert!(r.is_none(), "early observation should not emit");
            }
            #[allow(
                clippy::cast_possible_wrap,
                reason = "min_cohort <= 4 fits in i64"
            )]
            let r = idx.observe(SubjectId::new(), &features, at(min_cohort as i64));
            prop_assert!(r.is_some(), "crossing min_cohort_size must emit");
            let obs = r.expect("checked some");
            prop_assert_eq!(obs.members.len(), min_cohort);
        }
    }
}
