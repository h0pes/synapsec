//! Intra-tool deduplication via fingerprint matching.
//!
//! Checks incoming findings against existing records by fingerprint,
//! updating last_seen timestamps for duplicates and reopening closed findings.

use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::finding::{Finding, FindingStatus};

/// Outcome of a deduplication check.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum DedupResult {
    /// No matching fingerprint — finding is new.
    New,
    /// Matched an existing open finding — updated last_seen.
    Updated(Uuid),
    /// Matched a closed finding — reopened as New.
    Reopened(Uuid),
}

/// Check a fingerprint against existing findings and apply dedup logic.
///
/// Returns `DedupResult::New` when no match exists, `Updated` when the
/// existing finding is still open, or `Reopened` when a closed finding
/// is redetected.
pub async fn check_and_apply(
    pool: &PgPool,
    fingerprint: &str,
    acted_by: Uuid,
) -> Result<DedupResult, AppError> {
    let existing = sqlx::query_as::<_, Finding>(
        "SELECT * FROM findings WHERE fingerprint = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(fingerprint)
    .fetch_optional(pool)
    .await?;

    let Some(finding) = existing else {
        return Ok(DedupResult::New);
    };

    if finding.status == FindingStatus::Closed {
        // Reopen closed finding
        reopen_finding(pool, finding.id, acted_by).await?;
        return Ok(DedupResult::Reopened(finding.id));
    }

    // Update last_seen on the existing open finding
    touch_last_seen(pool, finding.id).await?;
    Ok(DedupResult::Updated(finding.id))
}

/// Update last_seen timestamp on an existing finding.
async fn touch_last_seen(pool: &PgPool, finding_id: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE findings SET last_seen = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(finding_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Reopen a closed finding: set status back to New, update last_seen, and log history.
async fn reopen_finding(pool: &PgPool, finding_id: Uuid, acted_by: Uuid) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    sqlx::query(
        r#"
        UPDATE findings
        SET status = $1, last_seen = NOW(), updated_at = NOW()
        WHERE id = $2
        "#,
    )
    .bind(FindingStatus::New)
    .bind(finding_id)
    .execute(&mut *tx)
    .await?;

    sqlx::query(
        r#"
        INSERT INTO finding_history (finding_id, action, field_changed, old_value, new_value, actor_id, actor_name, justification)
        VALUES ($1, 'status_change', 'status', $2, $3, $4, $5, $6)
        "#,
    )
    .bind(finding_id)
    .bind("Closed")
    .bind("New")
    .bind(acted_by)
    .bind("system")
    .bind("Automatically reopened: fingerprint redetected in new scan")
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_result_serialization() {
        let new = DedupResult::New;
        let json = serde_json::to_value(&new).unwrap();
        assert_eq!(json, "New");

        let id = Uuid::nil();
        let updated = DedupResult::Updated(id);
        let json = serde_json::to_value(&updated).unwrap();
        assert!(json["Updated"].is_string());
    }

    #[test]
    fn dedup_result_equality() {
        assert_eq!(DedupResult::New, DedupResult::New);

        let id = Uuid::nil();
        assert_eq!(DedupResult::Updated(id), DedupResult::Updated(id));
        assert_ne!(DedupResult::New, DedupResult::Updated(id));
        assert_ne!(DedupResult::Updated(id), DedupResult::Reopened(id));
    }
}
