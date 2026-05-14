//! Routing I/O wrapper: builds a [`super::RoutingSnapshot`] and calls
//! [`super::route`].
//!
//! The pure routing function is in [`super`]; this module is the thin
//! "service" layer that gathers the inputs from the DB and hands the
//! snapshot to the rule cascade. Per the issue #22 pre-flight, the split
//! exists so the rule cascade is unit-testable in isolation without a
//! Postgres fixture; the I/O lives here.
//!
//! # Trait shape
//!
//! [`ModeratorDirectory`] is the abstraction the service consumes — a
//! single async method that returns the routing-relevant projection of
//! every moderator eligible for a given category. The split (rather than a
//! generic "list all moderators" method) keeps the directory free to
//! pre-filter at the SQL layer once issue #23's specialty + exposure
//! tables land.
//!
//! The trait uses `async fn in trait` (AFIT), stable since Rust 1.75 and
//! used elsewhere in this crate (`crate::repo`). It is not dyn-compatible
//! by default; callers parametrise [`RoutingService`] over the concrete
//! impl.

use std::collections::HashSet;

use polaris_types::{IncidentId, ModeratorId, RoutingCategory};
use sqlx::PgPool;

use super::{IncidentForRouting, ModeratorForRouting, RoutingDecision, RoutingSnapshot, route};
use crate::repo::{IncidentRepo, RepoError};
use crate::wellness::WellnessError;
use crate::wellness::exposure::ExposureTracker;

/// Error type for [`RoutingService`].
///
/// Library-grade enum (per the rust-quality `thiserror` rule). Variants are
/// the two failure modes the service can actually hit: a repo-layer error
/// (DB outage / decode mismatch / not found) or a not-found incident.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// The incident id passed to [`RoutingService::assign`] did not match a
    /// row in the `incidents` table.
    #[error("incident not found")]
    IncidentNotFound,
    /// The repository layer raised a typed error while building the
    /// snapshot.
    #[error("repository failure")]
    Repo(#[from] RepoError),
}

/// Directory of moderators the router may consider.
///
/// Implementations project the `moderators` row (and, post-#23, the
/// specialty / exposure side tables) into a [`ModeratorForRouting`] vector
/// that the pure routing function consumes. Filtering at this layer is
/// permitted as a SQL-side optimisation (e.g. "exclude moderators marked
/// inactive") but the routing-time rules (csam-trained, calibration,
/// exposure budget, load cap) **must** be enforced inside
/// [`super::route`] — that is the contract that keeps the rules auditable.
pub trait ModeratorDirectory: Send + Sync {
    /// Return every moderator the directory considers in-scope for an
    /// incident of `category`. Implementations may narrow the result set
    /// at the SQL layer (e.g. omit inactive accounts) but must include
    /// every moderator the router could conceivably pick, including
    /// non-specialists and non-calibrated moderators — the routing cascade
    /// performs the §5.4 filters itself.
    fn list_eligible(
        &self,
        category: RoutingCategory,
    ) -> impl std::future::Future<Output = Result<Vec<ModeratorForRouting>, RepoError>> + Send;
}

/// Service that builds a [`RoutingSnapshot`] and runs [`super::route`].
///
/// Generic over the [`IncidentRepo`] and [`ModeratorDirectory`] implementations
/// so the binary wires the Postgres-backed types and tests can substitute
/// in-memory fakes.
#[derive(Debug, Clone)]
pub struct RoutingService<I, M>
where
    I: IncidentRepo,
    M: ModeratorDirectory,
{
    incidents: I,
    moderators: M,
}

impl<I, M> RoutingService<I, M>
where
    I: IncidentRepo,
    M: ModeratorDirectory,
{
    /// Construct a [`RoutingService`] over a repo + directory.
    #[must_use]
    pub fn new(incidents: I, moderators: M) -> Self {
        Self {
            incidents,
            moderators,
        }
    }

    /// Decide an assignment for `incident_id`.
    ///
    /// Builds the [`RoutingSnapshot`] via the repo + directory, then hands it
    /// to the pure [`super::route`] function. The caller persists / acts on
    /// the returned [`RoutingDecision`] (typically by setting
    /// `incidents.assigned_to`, opening a shadow-review row, or firing
    /// external-forward events).
    ///
    /// # Errors
    ///
    /// Returns [`ServiceError::IncidentNotFound`] if the incident id has no
    /// matching row, or [`ServiceError::Repo`] on any repo-layer failure.
    pub async fn assign(&self, incident_id: IncidentId) -> Result<RoutingDecision, ServiceError> {
        let snapshot = self.build_snapshot(incident_id).await?;
        Ok(route(&snapshot))
    }

    /// Internal: hydrate the [`RoutingSnapshot`] for an incident id.
    ///
    /// Two queries: one for the incident bare row, one for the moderator
    /// directory. The map-to-routing-category fallback (`Other`) is
    /// explicit so a future unknown category does not silently bypass
    /// routing.
    async fn build_snapshot(
        &self,
        incident_id: IncidentId,
    ) -> Result<RoutingSnapshot, ServiceError> {
        let incident = self
            .incidents
            .get(incident_id)
            .await?
            .ok_or(ServiceError::IncidentNotFound)?;

        // The bare `Incident` row does not carry a routing-time category
        // (categories live on attached `Report`s). For now we route on
        // severity tier: Critical → Csam-class, otherwise Other. This is a
        // conservative fallback that ensures a Critical incident always
        // hits the CSAM-routing rule; refining this requires the
        // hydration helper that joins `reports.category` (downstream work
        // beyond #22's scope).
        let category = if incident.severity == polaris_types::Severity::Critical {
            RoutingCategory::Csam
        } else {
            RoutingCategory::Other
        };

        let eligible_moderators = self.moderators.list_eligible(category).await?;

        Ok(RoutingSnapshot {
            incident: IncidentForRouting {
                id: incident.id,
                primary_subject: incident.primary_subject,
                category,
                severity: incident.severity,
                // Ordinary incident routing has no per-call exclusion;
                // the appeals workflow (#24) builds its own snapshot via a
                // separate path and supplies `Some(original_author)`.
                exclude_moderator: None,
            },
            eligible_moderators,
        })
    }
}

/// Postgres-backed [`ModeratorDirectory`] (issue #23 deliverable 23d).
///
/// Selects the routing-relevant projection of every moderator row and
/// joins the live exposure data from the wellness layer to produce the
/// `exposure_budget_remaining` field. Previously this field was hard-coded
/// to [`u32::MAX`] (the `ExposureBudget::UNLIMITED` placeholder from
/// `polaris-types::routing`); after #23 the value is the moderator's real
/// remaining budget so the routing cascade respects §5.7 caps.
///
/// # Specialty pool
///
/// The `moderators` table does not yet carry a specialty column — that
/// schema extension is queued for a later issue. Today the directory
/// returns every moderator with an empty `specialties` set; the routing
/// cascade falls back to the generalist branch and the cost is one
/// extra candidate scan per call. When the specialty column lands, this
/// is the single line that needs to change.
#[derive(Debug, Clone)]
pub struct PgModeratorDirectory {
    pool: PgPool,
    exposure: ExposureTracker,
}

impl PgModeratorDirectory {
    /// Construct a directory over the given pool. The
    /// [`ExposureTracker`] is built against the same pool internally so
    /// the routing-time budget query reuses the existing connection
    /// pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        let exposure = ExposureTracker::new(pool.clone());
        Self { pool, exposure }
    }
}

impl ModeratorDirectory for PgModeratorDirectory {
    async fn list_eligible(
        &self,
        _category: RoutingCategory,
    ) -> Result<Vec<ModeratorForRouting>, RepoError> {
        // Pull every moderator's routing-time bits in one query. The
        // current-load count joins `incidents` filtered on the two
        // open-status values; the LEFT JOIN over `incidents` is correlated
        // via a subquery so the result has exactly one row per moderator
        // even when they hold zero open cases.
        let rows = sqlx::query!(
            r#"
            SELECT
                m.id                                  AS "id!: uuid::Uuid",
                m.csam_trained                        AS "csam_trained!: bool",
                m.calibration_complete                AS "calibration_complete!: bool",
                COALESCE((
                    SELECT COUNT(*)::bigint
                    FROM incidents i
                    WHERE i.assigned_to = m.id
                      AND i.status IN ('open', 'in_review')
                ), 0)                                 AS "current_load!: i64"
            FROM moderators m
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(RepoError::from)?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let moderator_id = ModeratorId(row.id);
            // Translate `WellnessError` to `RepoError` so the directory's
            // signature stays inside the repo's typed error contract; a
            // wellness DB failure is operationally a repo failure from
            // the routing caller's standpoint.
            let exposure_budget_remaining = self
                .exposure
                .remaining_budget(moderator_id)
                .await
                .map_err(wellness_to_repo)?;

            // `current_load` SUM-of-bool returns i64; saturate to u32 so
            // the routing snapshot's `u32` field accepts it. A moderator
            // holding more than 4 billion open cases is not a state we
            // need to model.
            let current_load: u32 = u32::try_from(row.current_load).unwrap_or(u32::MAX);

            out.push(ModeratorForRouting {
                id: moderator_id,
                csam_trained: row.csam_trained,
                calibration_complete: row.calibration_complete,
                specialties: HashSet::new(),
                current_load,
                exposure_budget_remaining,
                agreement_with_senior_rate: 0.0,
            });
        }
        Ok(out)
    }
}

/// Convert a [`WellnessError`] into the typed [`RepoError`] surface so
/// [`PgModeratorDirectory`]'s public signature stays inside the repo
/// contract. `Database` flows through verbatim; `NotFound` collapses
/// onto `Database(Error::RowNotFound)` since the directory does not have
/// a separate `NotFound` channel.
fn wellness_to_repo(err: WellnessError) -> RepoError {
    match err {
        WellnessError::Database(source) => RepoError::Database(source),
        WellnessError::NotFound => RepoError::NotFound,
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
    use polaris_types::{Incident, IncidentStatus, ModeratorId, Severity, SubjectId};

    /// In-memory fake `IncidentRepo` that holds at most one incident.
    struct FakeIncidentRepo {
        incident: Option<Incident>,
    }

    impl IncidentRepo for FakeIncidentRepo {
        async fn insert(
            &self,
            _new: crate::repo::incident::NewIncident,
        ) -> Result<Incident, RepoError> {
            unreachable!("not used by RoutingService tests");
        }

        async fn get(&self, _id: polaris_types::IncidentId) -> Result<Option<Incident>, RepoError> {
            Ok(self.incident.clone())
        }

        async fn list_by_status(
            &self,
            _status: Option<IncidentStatus>,
            _limit: i64,
        ) -> Result<Vec<Incident>, RepoError> {
            unreachable!("not used by RoutingService tests");
        }

        async fn update_status(
            &self,
            _id: polaris_types::IncidentId,
            _new_status: IncidentStatus,
        ) -> Result<Incident, RepoError> {
            unreachable!("not used by RoutingService tests");
        }
    }

    struct FakeDirectory {
        mods: Vec<ModeratorForRouting>,
    }

    impl ModeratorDirectory for FakeDirectory {
        async fn list_eligible(
            &self,
            _category: RoutingCategory,
        ) -> Result<Vec<ModeratorForRouting>, RepoError> {
            Ok(self.mods.clone())
        }
    }

    #[tokio::test]
    async fn assign_returns_no_eligible_when_directory_empty() {
        let incident = Incident::new_bare(
            polaris_types::IncidentId::new(),
            SubjectId::new(),
            Severity::Medium,
            IncidentStatus::Open,
            None,
            None,
            chrono::Utc::now(),
            None,
        );
        let svc = RoutingService::new(
            FakeIncidentRepo {
                incident: Some(incident.clone()),
            },
            FakeDirectory { mods: vec![] },
        );
        let decision = svc.assign(incident.id).await.expect("ok");
        assert_eq!(
            decision,
            RoutingDecision::NoEligibleModerator {
                reason: "no moderators available",
            }
        );
    }

    #[tokio::test]
    async fn assign_returns_incident_not_found_when_repo_yields_none() {
        let svc = RoutingService::new(
            FakeIncidentRepo { incident: None },
            FakeDirectory { mods: vec![] },
        );
        let err = svc
            .assign(polaris_types::IncidentId::new())
            .await
            .expect_err("must be IncidentNotFound");
        assert!(matches!(err, ServiceError::IncidentNotFound));
    }

    #[tokio::test]
    async fn critical_severity_routes_through_csam_branch() {
        // A Critical-severity incident with no CSAM-trained mods in the
        // directory must yield `ForwardExternally` (the §5.4 hard rule).
        let incident = Incident::new_bare(
            polaris_types::IncidentId::new(),
            SubjectId::new(),
            Severity::Critical,
            IncidentStatus::Open,
            None,
            None,
            chrono::Utc::now(),
            None,
        );
        let svc = RoutingService::new(
            FakeIncidentRepo {
                incident: Some(incident.clone()),
            },
            FakeDirectory {
                mods: vec![ModeratorForRouting {
                    id: ModeratorId::new(),
                    csam_trained: false,
                    calibration_complete: true,
                    specialties: std::collections::HashSet::new(),
                    current_load: 0,
                    exposure_budget_remaining: u32::MAX,
                    agreement_with_senior_rate: 0.0,
                }],
            },
        );
        let decision = svc.assign(incident.id).await.expect("ok");
        assert_eq!(
            decision,
            RoutingDecision::ForwardExternally {
                ncmec: true,
                bluesky: true,
                reason: super::super::ForwardReason::CsamNoTrainedModerators,
            }
        );
    }
}
