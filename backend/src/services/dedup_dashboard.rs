//! Deduplication dashboard service for reviewing cross-tool duplicate pairs.
//!
//! Provides statistics, pending-review listings, decision history, and
//! confirm/reject actions for finding relationships flagged as duplicates.
//! Kept separate from `deduplication.rs` which handles intra-tool dedup.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::pagination::{PagedResult, Pagination};

/// Aggregate statistics for the deduplication dashboard.
#[derive(Debug, Serialize)]
pub struct DedupStats {
    pub total_duplicate_relationships: i64,
    pub pending_review: i64,
    pub confirmed: i64,
    pub rejected: i64,
    pub total_ingestions: i64,
    pub last_ingestion_at: Option<DateTime<Utc>>,
}

/// A duplicate-pair awaiting analyst review.
#[derive(Debug, Serialize, FromRow)]
pub struct PendingReview {
    pub relationship_id: Uuid,
    pub source_finding_id: Uuid,
    pub source_title: String,
    pub source_tool: String,
    pub target_finding_id: Uuid,
    pub target_title: String,
    pub target_tool: String,
    pub confidence: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Audit trail entry for a confirm or reject decision.
#[derive(Debug, Serialize, FromRow)]
pub struct DedupDecision {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub action: String,
    pub field_changed: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub actor_name: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Fetch aggregated deduplication statistics.
pub async fn get_stats(pool: &PgPool) -> Result<DedupStats, AppError> {
    let (total, pending, confirmed, rejected, ingestions, last_ingestion) = tokio::try_join!(
        fetch_total_duplicates(pool),
        fetch_pending_count(pool),
        fetch_confirmed_count(pool),
        fetch_rejected_count(pool),
        fetch_total_ingestions(pool),
        fetch_last_ingestion_at(pool),
    )?;

    Ok(DedupStats {
        total_duplicate_relationships: total,
        pending_review: pending,
        confirmed,
        rejected,
        total_ingestions: ingestions,
        last_ingestion_at: last_ingestion,
    })
}

/// List duplicate pairs pending analyst review, paginated.
pub async fn list_pending(
    pool: &PgPool,
    pagination: &Pagination,
) -> Result<PagedResult<PendingReview>, AppError> {
    let total = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM finding_relationships
        WHERE relationship_type = 'duplicate_of'
          AND (confidence::text IN ('Low', 'Medium') OR confidence IS NULL)
        "#,
    )
    .fetch_one(pool)
    .await?;

    let items = sqlx::query_as::<_, PendingReview>(
        r#"
        SELECT
            fr.id           AS relationship_id,
            fr.source_finding_id,
            sf.title        AS source_title,
            sf.source_tool  AS source_tool,
            fr.target_finding_id,
            tf.title        AS target_title,
            tf.source_tool  AS target_tool,
            fr.confidence::text AS confidence,
            fr.created_at
        FROM finding_relationships fr
        INNER JOIN findings sf ON sf.id = fr.source_finding_id
        INNER JOIN findings tf ON tf.id = fr.target_finding_id
        WHERE fr.relationship_type = 'duplicate_of'
          AND (fr.confidence::text IN ('Low', 'Medium') OR fr.confidence IS NULL)
        ORDER BY fr.created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(pagination.limit())
    .bind(pagination.offset())
    .fetch_all(pool)
    .await?;

    Ok(PagedResult::new(items, total, pagination))
}

/// List recent deduplication decisions (confirm/reject), paginated.
pub async fn list_history(
    pool: &PgPool,
    pagination: &Pagination,
) -> Result<PagedResult<DedupDecision>, AppError> {
    let total = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM finding_history
        WHERE action IN ('relationship_confirmed', 'relationship_rejected')
        "#,
    )
    .fetch_one(pool)
    .await?;

    let items = sqlx::query_as::<_, DedupDecision>(
        r#"
        SELECT id, finding_id, action, field_changed, old_value, new_value, actor_name, created_at
        FROM finding_history
        WHERE action IN ('relationship_confirmed', 'relationship_rejected')
        ORDER BY created_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(pagination.limit())
    .bind(pagination.offset())
    .fetch_all(pool)
    .await?;

    Ok(PagedResult::new(items, total, pagination))
}

/// Confirm a duplicate relationship by promoting confidence to High.
///
/// Wraps the update and audit-trail insert in a single transaction.
pub async fn confirm(
    pool: &PgPool,
    relationship_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    // Fetch the relationship to record audit info.
    let rel = sqlx::query_as::<_, RelRow>(
        r#"
        SELECT id, source_finding_id, confidence::text AS confidence
        FROM finding_relationships
        WHERE id = $1 AND relationship_type = 'duplicate_of'
        "#,
    )
    .bind(relationship_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("relationship {relationship_id}")))?;

    sqlx::query(
        "UPDATE finding_relationships SET confidence = 'High' WHERE id = $1",
    )
    .bind(relationship_id)
    .execute(&mut *tx)
    .await?;

    // Fetch actor name for the audit trail.
    let actor_name = fetch_actor_name(&mut tx, user_id).await?;

    sqlx::query(
        r#"
        INSERT INTO finding_history
            (finding_id, action, field_changed, old_value, new_value, actor_id, actor_name, justification)
        VALUES ($1, 'relationship_confirmed', 'confidence', $2, 'High', $3, $4, 'Analyst confirmed duplicate relationship')
        "#,
    )
    .bind(rel.source_finding_id)
    .bind(rel.confidence.as_deref().unwrap_or("Unknown"))
    .bind(user_id)
    .bind(&actor_name)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Reject a duplicate relationship by deleting it.
///
/// Wraps the delete and audit-trail insert in a single transaction.
pub async fn reject(
    pool: &PgPool,
    relationship_id: Uuid,
    user_id: Uuid,
) -> Result<(), AppError> {
    let mut tx = pool.begin().await?;

    // Fetch the relationship before deletion for audit info.
    let rel = sqlx::query_as::<_, RelRow>(
        r#"
        SELECT id, source_finding_id, confidence::text AS confidence
        FROM finding_relationships
        WHERE id = $1 AND relationship_type = 'duplicate_of'
        "#,
    )
    .bind(relationship_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("relationship {relationship_id}")))?;

    sqlx::query("DELETE FROM finding_relationships WHERE id = $1")
        .bind(relationship_id)
        .execute(&mut *tx)
        .await?;

    let actor_name = fetch_actor_name(&mut tx, user_id).await?;

    sqlx::query(
        r#"
        INSERT INTO finding_history
            (finding_id, action, field_changed, old_value, new_value, actor_id, actor_name, justification)
        VALUES ($1, 'relationship_rejected', 'relationship', $2, NULL, $3, $4, 'Analyst rejected duplicate relationship')
        "#,
    )
    .bind(rel.source_finding_id)
    .bind(rel.confidence.as_deref().unwrap_or("Unknown"))
    .bind(user_id)
    .bind(&actor_name)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

// -- Private helpers ----------------------------------------------------------

/// Minimal row for reading a relationship before mutation.
#[derive(Debug, FromRow)]
struct RelRow {
    #[expect(dead_code, reason = "selected for completeness but only source_finding_id / confidence are used")]
    id: Uuid,
    source_finding_id: Uuid,
    confidence: Option<String>,
}

/// Resolve a user ID to their username for audit trail entries.
async fn fetch_actor_name(
    tx: &mut sqlx::PgConnection,
    user_id: Uuid,
) -> Result<String, AppError> {
    let name = sqlx::query_scalar::<_, String>(
        "SELECT username FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or_else(|| "unknown".to_string());
    Ok(name)
}

/// Count all duplicate_of relationships.
async fn fetch_total_duplicates(pool: &PgPool) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM finding_relationships WHERE relationship_type = 'duplicate_of'",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Count duplicates pending review (Low/Medium confidence or NULL).
async fn fetch_pending_count(pool: &PgPool) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM finding_relationships
        WHERE relationship_type = 'duplicate_of'
          AND (confidence::text IN ('Low', 'Medium') OR confidence IS NULL)
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Count confirmed duplicates (High confidence).
async fn fetch_confirmed_count(pool: &PgPool) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM finding_relationships
        WHERE relationship_type = 'duplicate_of'
          AND confidence::text = 'High'
        "#,
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Count rejected duplicates from the audit trail.
async fn fetch_rejected_count(pool: &PgPool) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM finding_history WHERE action = 'relationship_rejected'",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Count all ingestion log entries.
async fn fetch_total_ingestions(pool: &PgPool) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM ingestion_logs",
    )
    .fetch_one(pool)
    .await?;
    Ok(count)
}

/// Fetch the most recent ingestion completion timestamp.
async fn fetch_last_ingestion_at(pool: &PgPool) -> Result<Option<DateTime<Utc>>, AppError> {
    let ts = sqlx::query_scalar::<_, Option<DateTime<Utc>>>(
        "SELECT MAX(completed_at) FROM ingestion_logs",
    )
    .fetch_one(pool)
    .await?;
    Ok(ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedup_stats_serialization() {
        let stats = DedupStats {
            total_duplicate_relationships: 42,
            pending_review: 10,
            confirmed: 30,
            rejected: 2,
            total_ingestions: 5,
            last_ingestion_at: None,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["total_duplicate_relationships"], 42);
        assert_eq!(json["pending_review"], 10);
        assert_eq!(json["confirmed"], 30);
        assert_eq!(json["rejected"], 2);
        assert_eq!(json["total_ingestions"], 5);
        assert!(json["last_ingestion_at"].is_null());
    }

    #[test]
    fn dedup_stats_with_timestamp() {
        let ts = Utc::now();
        let stats = DedupStats {
            total_duplicate_relationships: 1,
            pending_review: 0,
            confirmed: 1,
            rejected: 0,
            total_ingestions: 1,
            last_ingestion_at: Some(ts),
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert!(json["last_ingestion_at"].is_string());
    }

    #[test]
    fn dedup_decision_serialization() {
        let decision = DedupDecision {
            id: Uuid::nil(),
            finding_id: Uuid::nil(),
            action: "relationship_confirmed".to_string(),
            field_changed: Some("confidence".to_string()),
            old_value: Some("Low".to_string()),
            new_value: Some("High".to_string()),
            actor_name: Some("analyst1".to_string()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["action"], "relationship_confirmed");
        assert_eq!(json["field_changed"], "confidence");
    }

    #[test]
    fn pending_review_serialization() {
        let review = PendingReview {
            relationship_id: Uuid::nil(),
            source_finding_id: Uuid::nil(),
            source_title: "SQL Injection".to_string(),
            source_tool: "sonarqube".to_string(),
            target_finding_id: Uuid::nil(),
            target_title: "SQL Injection in login".to_string(),
            target_tool: "semgrep".to_string(),
            confidence: Some("Medium".to_string()),
            created_at: Utc::now(),
        };
        let json = serde_json::to_value(&review).unwrap();
        assert_eq!(json["source_title"], "SQL Injection");
        assert_eq!(json["target_tool"], "semgrep");
        assert_eq!(json["confidence"], "Medium");
    }
}
