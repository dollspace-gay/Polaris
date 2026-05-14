//! `ReportVolumeChart` — SVG sparkline + anomaly band.
//!
//! Renders the hourly report-volume buckets from
//! [`crate::api_client::dto::DashboardSnapshot::report_volume`] as a
//! hand-rolled SVG: one bar per bucket, with a shaded rectangle showing
//! the `mean ± k·stddev` anomaly band when stddev is non-zero, and an
//! "▲" glyph beside any bar that escapes the band.
//!
//! Design notes from `design.md` §5.1 + #20 pre-flight:
//!
//! - SVG, not Canvas — Leptos can render SVG declaratively and screen
//!   readers see the embedded `<title>` / `<desc>` elements.
//! - No charting crate — `plotters` / `charming` would pull a non-trivial
//!   transitive set; the chart is small enough to draw by hand.
//! - Anomaly markers are not colour-only: an "▲" glyph appears next to
//!   every escaping bar so the chart reads on monochrome displays and
//!   for colour-blind moderators (§7 accessibility contract).

use leptos::prelude::*;

use crate::api_client::dto::ReportVolumeBucket;

/// Anomaly-band width in standard deviations. The default matches the
/// pattern engine's `ReportVolumeAnomaly` z-score threshold so the band
/// drawn here is the same band the detector uses for the
/// `report_volume_anomaly` observation.
const ANOMALY_K: f64 = 3.0;

/// SVG viewport width, in user units. Picked so the bar width works out
/// to a clean integer at 24 buckets (10 px bar + 2 px gap = 12 px per
/// bucket × 24 = 288 + chart margins).
const SVG_WIDTH: u32 = 320;

/// SVG viewport height. Tall enough to render a 24h sparkline at a
/// glance without crowding the dashboard layout.
const SVG_HEIGHT: u32 = 80;

/// Horizontal margin inside the SVG viewport (room for the y-axis label).
const X_MARGIN: u32 = 16;

/// Vertical margin (room for the "▲" anomaly markers above bars).
const Y_MARGIN: u32 = 12;

/// Bar-rendering shape per bucket.
struct BarLayout {
    /// X coordinate of the bar's left edge.
    x: u32,
    /// Bar width (≥ 1 user unit).
    width: u32,
    /// Y coordinate of the bar's top edge.
    y: u32,
    /// Bar height (≥ 0).
    height: u32,
    /// True when the bar's count is outside the anomaly band.
    is_anomaly: bool,
}

/// SVG sparkline + anomaly-band chart for the report-volume panel.
///
/// # Props
///
/// - `buckets` — the per-hour rows from the snapshot. May be empty (early
///   deployments have no reports); the component renders an inline empty
///   state in that case so the dashboard never shows a blank rectangle.
///
/// # Accessibility
///
/// - The outer `<svg>` carries `role="img"` and `aria-label`.
/// - Embedded `<title>` and `<desc>` elements describe the chart for
///   assistive tech.
/// - Anomaly markers are both a colour change *and* a "▲" glyph.
// Lint allows: `must_use_candidate` is unsatisfiable on `#[component]`
// (see `subject_header::SubjectHeader` for the full rationale).
// `needless_pass_by_value` fires because Leptos props are by-value as
// the API convention; the body consumes via `into_iter` so accepting
// `&[…]` would force an extra clone. `too_many_lines` reflects the
// natural shape of an SVG renderer (layout + bars + band + markers +
// summary) — splitting harms readability without removing complexity.
#[allow(
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::too_many_lines
)]
#[component]
pub fn ReportVolumeChart(
    /// Hourly buckets from the dashboard snapshot.
    buckets: Vec<ReportVolumeBucket>,
) -> impl IntoView {
    let count = buckets.len();
    if count == 0 {
        return view! {
            <section class="report-volume-chart" aria-label="Report volume (24 hours)">
                <h3>"Report volume — 24h"</h3>
                <p class="report-volume-chart__empty" role="status">
                    "No reports recorded in the trailing 24 hours."
                </p>
            </section>
        }
        .into_any();
    }

    let max_count = buckets.iter().map(|b| b.count).max().unwrap_or(0).max(1);
    // The anomaly band may extend above the bars; widen the y-axis so the
    // band shading is fully visible.
    let max_upper = buckets
        .iter()
        .map(|b| upper_band(b.expected_mean, b.expected_stddev))
        .fold(0.0_f64, f64::max);
    #[allow(
        clippy::cast_precision_loss,
        reason = "max_count fits comfortably in f64 mantissa for any realistic bucket count"
    )]
    let y_axis_max = (max_count as f64).max(max_upper).max(1.0);

    let bars: Vec<BarLayout> = buckets
        .iter()
        .enumerate()
        .map(|(idx, b)| layout_bar(idx, count, b, y_axis_max))
        .collect();

    // Band shading: only render when at least one bucket carries a
    // non-zero stddev. For #20 the detector integration is deferred, so
    // this is typically a no-op until #19 is wired in.
    let render_band = buckets.iter().any(|b| b.expected_stddev > 0.0);

    let band_rects = if render_band {
        buckets
            .iter()
            .enumerate()
            .map(|(idx, b)| layout_band_rect(idx, count, b, y_axis_max))
            .collect()
    } else {
        Vec::new()
    };

    let bars_view: Vec<_> = bars
        .iter()
        .map(|bar| {
            let class = if bar.is_anomaly {
                "report-volume-chart__bar report-volume-chart__bar--anomaly"
            } else {
                "report-volume-chart__bar"
            };
            view! {
                <rect
                    class=class
                    x=bar.x
                    y=bar.y
                    width=bar.width.max(1)
                    height=bar.height
                />
            }
        })
        .collect();

    let anomaly_markers: Vec<_> = bars
        .iter()
        .filter(|b| b.is_anomaly)
        .map(|bar| {
            let cx = bar.x + bar.width / 2;
            view! {
                <text
                    class="report-volume-chart__anomaly-marker"
                    x=cx
                    y=Y_MARGIN.saturating_sub(2)
                    text-anchor="middle"
                    aria-hidden="true"
                >
                    "▲"
                </text>
            }
        })
        .collect();

    let band_view: Vec<_> = band_rects
        .iter()
        .map(|r| {
            view! {
                <rect
                    class="report-volume-chart__band"
                    x=r.x
                    y=r.y
                    width=r.width.max(1)
                    height=r.height
                />
            }
        })
        .collect();

    let anomaly_count = bars.iter().filter(|b| b.is_anomaly).count();
    let desc_text = format!(
        "{count} hourly bucket(s), {anomaly_count} anomaly outlier(s) at k={ANOMALY_K:.1} stddev"
    );

    view! {
        <section class="report-volume-chart" aria-label="Report volume (24 hours)">
            <h3>"Report volume — 24h"</h3>
            <svg
                class="report-volume-chart__svg"
                width=SVG_WIDTH
                height=SVG_HEIGHT
                viewBox=format!("0 0 {SVG_WIDTH} {SVG_HEIGHT}")
                role="img"
                aria-label="Hourly report volume over the trailing 24 hours"
            >
                <title>"Report volume — last 24 hours"</title>
                <desc>{desc_text}</desc>
                {band_view}
                {bars_view}
                {anomaly_markers}
            </svg>
            <p class="report-volume-chart__summary" role="status">
                {count}" hour(s) shown"
                {move || if anomaly_count > 0 {
                    format!(", {anomaly_count} anomaly outlier(s) above ±{ANOMALY_K:.1}σ")
                } else {
                    String::new()
                }}
            </p>
        </section>
    }
    .into_any()
}

/// Upper edge of the anomaly band, `mean + k·stddev`.
fn upper_band(mean: f64, stddev: f64) -> f64 {
    mean + ANOMALY_K * stddev
}

/// Lower edge of the anomaly band, clamped to zero (negative counts are
/// nonsensical).
fn lower_band(mean: f64, stddev: f64) -> f64 {
    (mean - ANOMALY_K * stddev).max(0.0)
}

/// True when `count` is outside the `[mean - k·σ, mean + k·σ]` band.
/// Returns false when stddev is zero (no band defined yet).
fn is_outside_band(count: i64, mean: f64, stddev: f64) -> bool {
    if stddev <= 0.0 {
        return false;
    }
    #[allow(
        clippy::cast_precision_loss,
        reason = "report counts are bounded well below the f64 mantissa limit"
    )]
    let c = count as f64;
    c < lower_band(mean, stddev) || c > upper_band(mean, stddev)
}

/// Translate `(bucket index, count)` into pixel-space bar geometry.
fn layout_bar(idx: usize, total: usize, bucket: &ReportVolumeBucket, y_max: f64) -> BarLayout {
    debug_assert!(total > 0, "layout_bar called with empty bucket list");
    let plot_width = SVG_WIDTH.saturating_sub(2 * X_MARGIN);
    let plot_height = SVG_HEIGHT.saturating_sub(2 * Y_MARGIN);

    #[allow(
        clippy::cast_possible_truncation,
        reason = "total ≤ 24 in practice; the division stays well below u32::MAX"
    )]
    let slot_w = (plot_width / total as u32).max(1);
    #[allow(
        clippy::cast_possible_truncation,
        reason = "idx ≤ total - 1, slot_w bounded by plot_width"
    )]
    let x = X_MARGIN + slot_w * idx as u32;
    let bar_w = slot_w.saturating_sub(2).max(1);

    #[allow(
        clippy::cast_precision_loss,
        reason = "count and bucket sizes stay below f64 mantissa"
    )]
    let normalized = (bucket.count as f64 / y_max).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "normalized in [0,1] × plot_height fits cleanly in u32"
    )]
    let bar_h = (normalized * f64::from(plot_height)) as u32;
    let y = SVG_HEIGHT.saturating_sub(Y_MARGIN).saturating_sub(bar_h);

    BarLayout {
        x,
        width: bar_w,
        y,
        height: bar_h,
        is_anomaly: is_outside_band(bucket.count, bucket.expected_mean, bucket.expected_stddev),
    }
}

/// Layout for one bucket's anomaly-band shading. Returns a `BarLayout`
/// repurposed: x/width are the bucket's column, y/height span the band's
/// vertical extent. The shading is rendered behind the bars by drawing it
/// first in the SVG.
fn layout_band_rect(
    idx: usize,
    total: usize,
    bucket: &ReportVolumeBucket,
    y_max: f64,
) -> BarLayout {
    let plot_width = SVG_WIDTH.saturating_sub(2 * X_MARGIN);
    let plot_height = SVG_HEIGHT.saturating_sub(2 * Y_MARGIN);
    #[allow(clippy::cast_possible_truncation, reason = "total ≤ 24 in practice")]
    let slot_w = (plot_width / total.max(1) as u32).max(1);
    #[allow(clippy::cast_possible_truncation, reason = "idx ≤ total - 1")]
    let x = X_MARGIN + slot_w * idx as u32;

    let upper = upper_band(bucket.expected_mean, bucket.expected_stddev);
    let lower = lower_band(bucket.expected_mean, bucket.expected_stddev);
    let upper_norm = (upper / y_max).clamp(0.0, 1.0);
    let lower_norm = (lower / y_max).clamp(0.0, 1.0);
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "normalized fractions × plot_height fit in u32"
    )]
    let upper_h = (upper_norm * f64::from(plot_height)) as u32;
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "see above"
    )]
    let lower_h = (lower_norm * f64::from(plot_height)) as u32;
    let band_h = upper_h.saturating_sub(lower_h);
    let y_top = SVG_HEIGHT.saturating_sub(Y_MARGIN).saturating_sub(upper_h);

    BarLayout {
        x,
        width: slot_w,
        y: y_top,
        height: band_h,
        is_anomaly: false,
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
    use chrono::{TimeZone as _, Utc};

    fn bucket(count: i64, mean: f64, stddev: f64) -> ReportVolumeBucket {
        ReportVolumeBucket {
            bucket_start: Utc.with_ymd_and_hms(2026, 5, 14, 0, 0, 0).unwrap(),
            count,
            expected_mean: mean,
            expected_stddev: stddev,
        }
    }

    #[test]
    fn is_outside_band_is_false_when_stddev_is_zero() {
        assert!(!is_outside_band(100, 0.0, 0.0));
        assert!(!is_outside_band(0, 0.0, 0.0));
    }

    #[test]
    fn is_outside_band_flags_high_outliers() {
        // mean=10, stddev=1, k=3 → band [7,13]; 50 is way outside.
        assert!(is_outside_band(50, 10.0, 1.0));
    }

    #[test]
    fn is_outside_band_flags_low_outliers() {
        // mean=10, stddev=1, k=3 → band [7,13]; 1 is below.
        assert!(is_outside_band(1, 10.0, 1.0));
    }

    #[test]
    fn is_outside_band_inside_band_is_false() {
        assert!(!is_outside_band(10, 10.0, 1.0));
        assert!(!is_outside_band(12, 10.0, 1.0));
    }

    #[test]
    fn layout_bar_normalizes_to_plot_height() {
        let b = bucket(10, 0.0, 0.0);
        let layout = layout_bar(0, 24, &b, 10.0);
        // count == y_max → bar fills the plot region.
        let plot_height = SVG_HEIGHT - 2 * Y_MARGIN;
        assert_eq!(layout.height, plot_height);
    }

    #[test]
    fn layout_bar_zero_count_zero_height() {
        let b = bucket(0, 0.0, 0.0);
        let layout = layout_bar(0, 24, &b, 10.0);
        assert_eq!(layout.height, 0);
    }
}
