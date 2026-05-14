//! Wellness exposure HTTP surface (issue #23).
//!
//! Three endpoints, all under the auth-gated `/api/wellness/exposure/me`
//! subtree:
//!
//! - `GET  /api/wellness/exposure/me`                  — self-view.
//! - `PUT  /api/wellness/exposure/me/cap`              — set daily cap.
//! - `PUT  /api/wellness/exposure/me/share-with-manager` — toggle consent.
//!
//! # Why "me"-only
//!
//! The moderator id always comes from `Extension<ModeratorAuthCtx>` (the
//! authenticated caller), never from the URL or request body. This is the
//! load-bearing privacy invariant: a moderator can only query / mutate
//! their own exposure data. A manager-view endpoint would require a
//! senior-role gate plus the consent check from
//! [`crate::wellness::exposure::ExposureTracker::aggregate_for_manager`];
//! deliberately deferred to M3 integration. The library function is
//! ready for that wiring.

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::auth::ModeratorAuthCtx;
use crate::wellness::WellnessError;
use crate::wellness::exposure::{ExposureStatus, ExposureTracker};

/// Request body for `PUT /api/wellness/exposure/me/cap`.
///
/// `daily_cap` is a `u32` per the issue's "no f64 in payload" rule. The
/// migration's `CHECK (daily_cap > 0)` rejects zero at the DB layer; we
/// preempt that with an explicit `BadRequest` so the client sees a
/// readable error rather than a generic 500.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetDailyCapBody {
    /// Requested daily exposure cap. Must be `> 0`.
    pub daily_cap: u32,
}

/// Request body for `PUT /api/wellness/exposure/me/share-with-manager`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SetShareWithManagerBody {
    /// `true` to opt in to manager-visible aggregate exposure, `false` to
    /// opt out. Default on a fresh moderator is `false`; toggling here
    /// flips the flag.
    pub share: bool,
}

/// `GET /api/wellness/exposure/me` — moderator's own exposure status.
///
/// Returns a single [`ExposureStatus`] for `current_date` covering the
/// moderator extracted from the auth extension. Never reads or accepts a
/// moderator id from the request — passing one in the URL would be a
/// privacy regression.
pub async fn get_my_exposure(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
) -> Result<Json<ExposureStatus>, ApiError> {
    let tracker = ExposureTracker::new(state.pool.clone());
    let moderator_id = polaris_types::ModeratorId(ctx.moderator_id.0);
    let status = tracker
        .status_for_me(moderator_id)
        .await
        .map_err(map_wellness_err)?;
    Ok(Json(status))
}

/// `PUT /api/wellness/exposure/me/cap` — update the caller's daily cap.
pub async fn set_my_cap(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<SetDailyCapBody>,
) -> Result<Json<ExposureStatus>, ApiError> {
    if body.daily_cap == 0 {
        return Err(ApiError::BadRequest("daily_cap must be greater than zero"));
    }
    let tracker = ExposureTracker::new(state.pool.clone());
    let moderator_id = polaris_types::ModeratorId(ctx.moderator_id.0);
    tracker
        .set_daily_cap(moderator_id, body.daily_cap)
        .await
        .map_err(map_wellness_err)?;
    let status = tracker
        .status_for_me(moderator_id)
        .await
        .map_err(map_wellness_err)?;
    Ok(Json(status))
}

/// `PUT /api/wellness/exposure/me/share-with-manager` — toggle consent.
pub async fn set_my_share_with_manager(
    State(state): State<ApiState>,
    Extension(ctx): Extension<ModeratorAuthCtx>,
    Json(body): Json<SetShareWithManagerBody>,
) -> Result<Json<ExposureStatus>, ApiError> {
    let tracker = ExposureTracker::new(state.pool.clone());
    let moderator_id = polaris_types::ModeratorId(ctx.moderator_id.0);
    tracker
        .set_share_with_manager(moderator_id, body.share)
        .await
        .map_err(map_wellness_err)?;
    let status = tracker
        .status_for_me(moderator_id)
        .await
        .map_err(map_wellness_err)?;
    Ok(Json(status))
}

/// Translate [`WellnessError`] to [`ApiError`].
///
/// `Database` surfaces as `Internal` so the cause chain is preserved for
/// operator logs; `NotFound` surfaces as `404 NotFound`. The two-error
/// surface is deliberate — every wellness method either succeeds or hits
/// one of these two failure modes.
fn map_wellness_err(err: WellnessError) -> ApiError {
    match err {
        WellnessError::Database(source) => ApiError::Internal(anyhow::Error::new(source)),
        WellnessError::NotFound => ApiError::NotFound,
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
    fn set_daily_cap_body_round_trips_through_serde() {
        let body = SetDailyCapBody { daily_cap: 25 };
        let json = serde_json::to_string(&body).expect("serialize");
        assert_eq!(json, r#"{"daily_cap":25}"#);
        let back: SetDailyCapBody = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.daily_cap, 25);
    }

    #[test]
    fn set_share_body_round_trips_through_serde() {
        let body = SetShareWithManagerBody { share: true };
        let json = serde_json::to_string(&body).expect("serialize");
        assert_eq!(json, r#"{"share":true}"#);
        let back: SetShareWithManagerBody = serde_json::from_str(&json).expect("deserialize");
        assert!(back.share);
    }

    #[test]
    fn map_wellness_err_routes_not_found_to_404() {
        let err = map_wellness_err(WellnessError::NotFound);
        assert!(matches!(err, ApiError::NotFound));
    }

    #[test]
    fn map_wellness_err_routes_database_to_internal() {
        let sqlx_err = sqlx::Error::RowNotFound;
        let err = map_wellness_err(WellnessError::Database(sqlx_err));
        assert!(matches!(err, ApiError::Internal(_)));
    }
}
