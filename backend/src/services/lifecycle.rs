//! Finding lifecycle state machine with RBAC-enforced transitions.
//!
//! Validates that state transitions follow the allowed graph,
//! actors have the required role, and mandatory fields are present.
//! Every transition is recorded in finding_history and audit_log.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::finding::FindingStatus;
use crate::models::user::UserRole;

/// Request to transition a finding's status.
#[derive(Debug, Deserialize)]
pub struct TransitionRequest {
    pub finding_id: Uuid,
    pub new_status: FindingStatus,
    pub justification: Option<String>,
    /// Required for Deferred_Remediation: when remediation is committed.
    pub committed_date: Option<DateTime<Utc>>,
    /// Required for Risk_Accepted: when the acceptance expires.
    pub expiry_date: Option<DateTime<Utc>>,
}

/// Actor performing a transition.
#[derive(Debug, Clone)]
pub struct TransitionActor {
    pub id: Uuid,
    pub username: String,
    pub role: UserRole,
}

/// Result of a successful transition.
#[derive(Debug, Serialize)]
pub struct TransitionResult {
    pub finding_id: Uuid,
    pub previous_status: FindingStatus,
    pub new_status: FindingStatus,
}

/// Check whether a status transition is valid per the state machine graph.
pub fn is_valid_transition(from: &FindingStatus, to: &FindingStatus) -> bool {
    matches!(
        (from, to),
        (FindingStatus::New, FindingStatus::Confirmed)
            | (FindingStatus::Confirmed, FindingStatus::InRemediation)
            | (FindingStatus::Confirmed, FindingStatus::FalsePositive)
            | (FindingStatus::Confirmed, FindingStatus::FalsePositiveRequested)
            | (FindingStatus::Confirmed, FindingStatus::RiskAccepted)
            | (FindingStatus::Confirmed, FindingStatus::DeferredRemediation)
            | (FindingStatus::FalsePositiveRequested, FindingStatus::FalsePositive)
            | (FindingStatus::FalsePositiveRequested, FindingStatus::Confirmed)
            | (FindingStatus::DeferredRemediation, FindingStatus::InRemediation)
            | (FindingStatus::InRemediation, FindingStatus::Mitigated)
            | (FindingStatus::Mitigated, FindingStatus::Verified)
            | (FindingStatus::Verified, FindingStatus::Closed)
            | (FindingStatus::RiskAccepted, FindingStatus::Confirmed)
            | (FindingStatus::Closed, FindingStatus::New)
            // Invalidated can come from any state (admin only)
            | (_, FindingStatus::Invalidated)
    )
}

/// Roles allowed to perform a transition to a given target status.
pub fn required_roles(to: &FindingStatus) -> Vec<UserRole> {
    match to {
        FindingStatus::RiskAccepted => {
            vec![UserRole::AppSecManager, UserRole::PlatformAdmin]
        }
        FindingStatus::DeferredRemediation => {
            vec![UserRole::AppSecManager, UserRole::PlatformAdmin]
        }
        FindingStatus::Invalidated => vec![UserRole::PlatformAdmin],
        FindingStatus::FalsePositiveRequested => vec![
            UserRole::Developer,
            UserRole::AppSecAnalyst,
            UserRole::AppSecManager,
            UserRole::PlatformAdmin,
        ],
        FindingStatus::Mitigated => vec![
            UserRole::Developer,
            UserRole::AppSecAnalyst,
            UserRole::AppSecManager,
            UserRole::PlatformAdmin,
        ],
        _ => vec![
            UserRole::AppSecAnalyst,
            UserRole::AppSecManager,
            UserRole::PlatformAdmin,
        ],
    }
}

/// Check whether an actor's role is permitted for a transition.
pub fn has_required_role(actor_role: &UserRole, target_status: &FindingStatus) -> bool {
    required_roles(target_status).contains(actor_role)
}

/// Statuses that cannot be targeted via bulk operations.
pub fn is_bulk_allowed(to: &FindingStatus) -> bool {
    !matches!(
        to,
        FindingStatus::RiskAccepted
            | FindingStatus::DeferredRemediation
            | FindingStatus::Invalidated
    )
}

/// Validate all preconditions for a transition, returning an error message if invalid.
pub fn validate_transition(
    from: &FindingStatus,
    to: &FindingStatus,
    actor_role: &UserRole,
    justification: &Option<String>,
    committed_date: &Option<DateTime<Utc>>,
    expiry_date: &Option<DateTime<Utc>>,
) -> Result<(), AppError> {
    // 1. Check valid graph edge
    if !is_valid_transition(from, to) {
        return Err(AppError::InvalidTransition(format!(
            "Cannot transition from {from:?} to {to:?}"
        )));
    }

    // 2. Check RBAC
    if !has_required_role(actor_role, to) {
        return Err(AppError::Forbidden(format!(
            "Role {actor_role:?} cannot transition to {to:?}"
        )));
    }

    // 3. Check required fields
    if *to == FindingStatus::RiskAccepted {
        if justification.as_ref().map_or(true, |j| j.trim().is_empty()) {
            return Err(AppError::Validation(
                "Risk acceptance requires justification".to_string(),
            ));
        }
        if expiry_date.is_none() {
            return Err(AppError::Validation(
                "Risk acceptance requires an expiry date".to_string(),
            ));
        }
    }

    if *to == FindingStatus::DeferredRemediation && committed_date.is_none() {
        return Err(AppError::Validation(
            "Deferred remediation requires a committed date".to_string(),
        ));
    }

    if *to == FindingStatus::FalsePositive
        && justification.as_ref().map_or(true, |j| j.trim().is_empty())
    {
        return Err(AppError::Validation(
            "False positive requires justification".to_string(),
        ));
    }

    Ok(())
}

/// Execute a full status transition: validate, update DB, log history + audit.
pub async fn transition(
    pool: &PgPool,
    request: &TransitionRequest,
    actor: &TransitionActor,
) -> Result<TransitionResult, AppError> {
    // Load current finding status
    let current_status = sqlx::query_scalar::<_, FindingStatus>(
        "SELECT status FROM findings WHERE id = $1",
    )
    .bind(request.finding_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

    // Validate
    validate_transition(
        &current_status,
        &request.new_status,
        &actor.role,
        &request.justification,
        &request.committed_date,
        &request.expiry_date,
    )?;

    // Apply in transaction
    let mut tx = pool.begin().await?;

    sqlx::query(
        "UPDATE findings SET status = $1, status_changed_at = NOW(), updated_at = NOW() WHERE id = $2",
    )
    .bind(&request.new_status)
    .bind(request.finding_id)
    .execute(&mut *tx)
    .await?;

    // Log to finding_history
    let old_str = format!("{:?}", current_status);
    let new_str = format!("{:?}", request.new_status);

    sqlx::query(
        r#"
        INSERT INTO finding_history (finding_id, action, field_changed, old_value, new_value, actor_id, actor_name, justification)
        VALUES ($1, 'status_change', 'status', $2, $3, $4, $5, $6)
        "#,
    )
    .bind(request.finding_id)
    .bind(&old_str)
    .bind(&new_str)
    .bind(actor.id)
    .bind(&actor.username)
    .bind(&request.justification)
    .execute(&mut *tx)
    .await?;

    // Log to audit_log
    sqlx::query(
        r#"
        INSERT INTO audit_log (entity_type, entity_id, action, actor_id, actor_name, details)
        VALUES ('finding', $1, 'status_change', $2, $3, $4)
        "#,
    )
    .bind(request.finding_id)
    .bind(actor.id)
    .bind(&actor.username)
    .bind(serde_json::json!({
        "previous_status": old_str,
        "new_status": new_str,
        "justification": request.justification,
    }))
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(TransitionResult {
        finding_id: request.finding_id,
        previous_status: current_status,
        new_status: request.new_status.clone(),
    })
}

/// Evaluate triage rules to determine if a finding should be held in New status.
///
/// Returns `true` if the finding should stay in New (held for manual triage),
/// `false` if it should be auto-confirmed.
pub async fn should_hold_for_triage(
    pool: &PgPool,
    _finding: &crate::models::finding::CreateFinding,
    _application: Option<&crate::models::application::Application>,
) -> Result<bool, AppError> {
    // Check if auto-confirm is enabled
    let auto_confirm = sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_config WHERE key = 'auto_confirm_enabled'",
    )
    .fetch_optional(pool)
    .await?
    .and_then(|v| v.as_bool())
    .unwrap_or(true);

    if !auto_confirm {
        return Ok(true); // Hold for triage when auto-confirm disabled
    }

    // TODO: Evaluate active triage_rules conditions against finding + application.
    // For now, default to auto-confirm (don't hold).
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Valid transitions --

    #[test]
    fn new_to_confirmed() {
        assert!(is_valid_transition(
            &FindingStatus::New,
            &FindingStatus::Confirmed
        ));
    }

    #[test]
    fn confirmed_to_in_remediation() {
        assert!(is_valid_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::InRemediation
        ));
    }

    #[test]
    fn confirmed_to_false_positive() {
        assert!(is_valid_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::FalsePositive
        ));
    }

    #[test]
    fn confirmed_to_false_positive_requested() {
        assert!(is_valid_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::FalsePositiveRequested
        ));
    }

    #[test]
    fn fp_requested_to_false_positive() {
        assert!(is_valid_transition(
            &FindingStatus::FalsePositiveRequested,
            &FindingStatus::FalsePositive
        ));
    }

    #[test]
    fn fp_requested_to_confirmed() {
        assert!(is_valid_transition(
            &FindingStatus::FalsePositiveRequested,
            &FindingStatus::Confirmed
        ));
    }

    #[test]
    fn confirmed_to_risk_accepted() {
        assert!(is_valid_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::RiskAccepted
        ));
    }

    #[test]
    fn confirmed_to_deferred_remediation() {
        assert!(is_valid_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::DeferredRemediation
        ));
    }

    #[test]
    fn deferred_to_in_remediation() {
        assert!(is_valid_transition(
            &FindingStatus::DeferredRemediation,
            &FindingStatus::InRemediation
        ));
    }

    #[test]
    fn in_remediation_to_mitigated() {
        assert!(is_valid_transition(
            &FindingStatus::InRemediation,
            &FindingStatus::Mitigated
        ));
    }

    #[test]
    fn mitigated_to_verified() {
        assert!(is_valid_transition(
            &FindingStatus::Mitigated,
            &FindingStatus::Verified
        ));
    }

    #[test]
    fn verified_to_closed() {
        assert!(is_valid_transition(
            &FindingStatus::Verified,
            &FindingStatus::Closed
        ));
    }

    #[test]
    fn closed_to_new_on_redetection() {
        assert!(is_valid_transition(
            &FindingStatus::Closed,
            &FindingStatus::New
        ));
    }

    #[test]
    fn risk_accepted_to_confirmed_on_expiry() {
        assert!(is_valid_transition(
            &FindingStatus::RiskAccepted,
            &FindingStatus::Confirmed
        ));
    }

    #[test]
    fn any_to_invalidated() {
        for status in [
            FindingStatus::New,
            FindingStatus::Confirmed,
            FindingStatus::InRemediation,
            FindingStatus::Closed,
            FindingStatus::RiskAccepted,
        ] {
            assert!(
                is_valid_transition(&status, &FindingStatus::Invalidated),
                "Expected {status:?} → Invalidated to be valid"
            );
        }
    }

    // -- Invalid transitions --

    #[test]
    fn new_to_closed_invalid() {
        assert!(!is_valid_transition(
            &FindingStatus::New,
            &FindingStatus::Closed
        ));
    }

    #[test]
    fn new_to_mitigated_invalid() {
        assert!(!is_valid_transition(
            &FindingStatus::New,
            &FindingStatus::Mitigated
        ));
    }

    #[test]
    fn closed_to_confirmed_invalid() {
        assert!(!is_valid_transition(
            &FindingStatus::Closed,
            &FindingStatus::Confirmed
        ));
    }

    // -- RBAC checks --

    #[test]
    fn developer_cannot_mark_false_positive() {
        assert!(!has_required_role(
            &UserRole::Developer,
            &FindingStatus::FalsePositive
        ));
    }

    #[test]
    fn developer_can_request_false_positive() {
        assert!(has_required_role(
            &UserRole::Developer,
            &FindingStatus::FalsePositiveRequested
        ));
    }

    #[test]
    fn developer_can_mark_mitigated() {
        assert!(has_required_role(
            &UserRole::Developer,
            &FindingStatus::Mitigated
        ));
    }

    #[test]
    fn analyst_can_confirm() {
        assert!(has_required_role(
            &UserRole::AppSecAnalyst,
            &FindingStatus::Confirmed
        ));
    }

    #[test]
    fn analyst_cannot_risk_accept() {
        assert!(!has_required_role(
            &UserRole::AppSecAnalyst,
            &FindingStatus::RiskAccepted
        ));
    }

    #[test]
    fn manager_can_risk_accept() {
        assert!(has_required_role(
            &UserRole::AppSecManager,
            &FindingStatus::RiskAccepted
        ));
    }

    #[test]
    fn only_admin_can_invalidate() {
        assert!(has_required_role(
            &UserRole::PlatformAdmin,
            &FindingStatus::Invalidated
        ));
        assert!(!has_required_role(
            &UserRole::AppSecManager,
            &FindingStatus::Invalidated
        ));
        assert!(!has_required_role(
            &UserRole::AppSecAnalyst,
            &FindingStatus::Invalidated
        ));
    }

    // -- Validation checks --

    #[test]
    fn risk_accepted_requires_justification() {
        let result = validate_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::RiskAccepted,
            &UserRole::AppSecManager,
            &None,
            &None,
            &Some(Utc::now()),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("justification"));
    }

    #[test]
    fn risk_accepted_requires_expiry_date() {
        let result = validate_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::RiskAccepted,
            &UserRole::AppSecManager,
            &Some("Business need".to_string()),
            &None,
            &None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expiry"));
    }

    #[test]
    fn risk_accepted_valid_with_all_fields() {
        let result = validate_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::RiskAccepted,
            &UserRole::AppSecManager,
            &Some("Business need".to_string()),
            &None,
            &Some(Utc::now()),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn deferred_remediation_requires_committed_date() {
        let result = validate_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::DeferredRemediation,
            &UserRole::AppSecManager,
            &None,
            &None,
            &None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("committed"));
    }

    #[test]
    fn false_positive_requires_justification() {
        let result = validate_transition(
            &FindingStatus::Confirmed,
            &FindingStatus::FalsePositive,
            &UserRole::AppSecAnalyst,
            &None,
            &None,
            &None,
        );
        assert!(result.is_err());
    }

    // -- Bulk operation checks --

    #[test]
    fn bulk_excludes_risk_accepted() {
        assert!(!is_bulk_allowed(&FindingStatus::RiskAccepted));
        assert!(!is_bulk_allowed(&FindingStatus::DeferredRemediation));
        assert!(!is_bulk_allowed(&FindingStatus::Invalidated));
    }

    #[test]
    fn bulk_allows_standard_transitions() {
        assert!(is_bulk_allowed(&FindingStatus::Confirmed));
        assert!(is_bulk_allowed(&FindingStatus::InRemediation));
        assert!(is_bulk_allowed(&FindingStatus::Closed));
    }
}
