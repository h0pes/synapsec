//! Dashboard statistics aggregation queries.

use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;

/// Aggregated dashboard statistics for the main overview page.
#[derive(Debug, Serialize)]
pub struct DashboardStats {
    pub triage_count: i64,
    pub unmapped_apps_count: i64,
    pub severity_counts: SeverityCounts,
    pub sla_summary: SlaSummary,
    pub recent_ingestions: Vec<RecentIngestion>,
    pub top_risky_apps: Vec<TopRiskyApp>,
    pub findings_by_source: Vec<SourceToolCount>,
}

/// Open finding counts grouped by normalized severity.
#[derive(Debug, Serialize)]
pub struct SeverityCounts {
    pub critical: i64,
    pub high: i64,
    pub medium: i64,
    pub low: i64,
    pub info: i64,
}

/// Finding counts grouped by SLA status.
#[derive(Debug, Serialize)]
pub struct SlaSummary {
    pub on_track: i64,
    pub at_risk: i64,
    pub breached: i64,
}

/// Recent ingestion log entry for the dashboard feed.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct RecentIngestion {
    pub id: Uuid,
    pub source_tool: String,
    pub file_name: Option<String>,
    pub total_records: i32,
    pub new_findings: i32,
    pub status: String,
    pub completed_at: Option<DateTime<Utc>>,
}

/// Open finding count for a single source tool (scanner).
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct SourceToolCount {
    pub source_tool: String,
    pub count: i64,
}

/// Application with highest open finding counts.
#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct TopRiskyApp {
    pub id: Uuid,
    pub app_name: String,
    pub app_code: String,
    pub finding_count: i64,
    pub critical_count: i64,
    pub high_count: i64,
}

/// Fetch all dashboard statistics in parallel queries.
pub async fn get_stats(pool: &PgPool) -> Result<DashboardStats, AppError> {
    let (triage_count, unmapped_apps_count, severity_counts, sla_summary, recent_ingestions, top_risky_apps, findings_by_source) = tokio::try_join!(
        fetch_triage_count(pool),
        fetch_unmapped_apps_count(pool),
        fetch_severity_counts(pool),
        fetch_sla_summary(pool),
        fetch_recent_ingestions(pool),
        fetch_top_risky_apps(pool),
        fetch_findings_by_source(pool),
    )?;

    Ok(DashboardStats {
        triage_count,
        unmapped_apps_count,
        severity_counts,
        sla_summary,
        recent_ingestions,
        top_risky_apps,
        findings_by_source,
    })
}

/// Count findings awaiting triage (status = 'New').
async fn fetch_triage_count(pool: &PgPool) -> Result<i64, AppError> {
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM findings WHERE status = 'New'",
    )
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Count applications not yet verified by APM enrichment.
async fn fetch_unmapped_apps_count(pool: &PgPool) -> Result<i64, AppError> {
    let row = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM applications WHERE is_verified = false",
    )
    .fetch_one(pool)
    .await?;
    Ok(row)
}

/// Count open findings grouped by normalized severity.
async fn fetch_severity_counts(pool: &PgPool) -> Result<SeverityCounts, AppError> {
    // Use conditional aggregation in a single query for efficiency.
    let row = sqlx::query_as::<_, SeverityRow>(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN normalized_severity = 'Critical' THEN 1 ELSE 0 END), 0) AS critical,
            COALESCE(SUM(CASE WHEN normalized_severity = 'High'     THEN 1 ELSE 0 END), 0) AS high,
            COALESCE(SUM(CASE WHEN normalized_severity = 'Medium'   THEN 1 ELSE 0 END), 0) AS medium,
            COALESCE(SUM(CASE WHEN normalized_severity = 'Low'      THEN 1 ELSE 0 END), 0) AS low,
            COALESCE(SUM(CASE WHEN normalized_severity = 'Info'     THEN 1 ELSE 0 END), 0) AS info
        FROM findings
        WHERE status NOT IN ('Closed', 'Invalidated', 'False_Positive')
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(SeverityCounts {
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low,
        info: row.info,
    })
}

/// Intermediate row for severity conditional aggregation.
#[derive(Debug, sqlx::FromRow)]
struct SeverityRow {
    critical: i64,
    high: i64,
    medium: i64,
    low: i64,
    info: i64,
}

/// Count findings grouped by SLA status.
async fn fetch_sla_summary(pool: &PgPool) -> Result<SlaSummary, AppError> {
    let row = sqlx::query_as::<_, SlaRow>(
        r#"
        SELECT
            COALESCE(SUM(CASE WHEN sla_status = 'On_Track' THEN 1 ELSE 0 END), 0) AS on_track,
            COALESCE(SUM(CASE WHEN sla_status = 'At_Risk'  THEN 1 ELSE 0 END), 0) AS at_risk,
            COALESCE(SUM(CASE WHEN sla_status = 'Breached'  THEN 1 ELSE 0 END), 0) AS breached
        FROM findings
        WHERE sla_status IS NOT NULL
        "#,
    )
    .fetch_one(pool)
    .await?;

    Ok(SlaSummary {
        on_track: row.on_track,
        at_risk: row.at_risk,
        breached: row.breached,
    })
}

/// Intermediate row for SLA conditional aggregation.
#[derive(Debug, sqlx::FromRow)]
struct SlaRow {
    on_track: i64,
    at_risk: i64,
    breached: i64,
}

/// Fetch the 5 most recent ingestion log entries.
async fn fetch_recent_ingestions(pool: &PgPool) -> Result<Vec<RecentIngestion>, AppError> {
    let rows = sqlx::query_as::<_, RecentIngestion>(
        r#"
        SELECT id, source_tool, file_name, total_records, new_findings, status, completed_at
        FROM ingestion_logs
        ORDER BY started_at DESC
        LIMIT 5
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Fetch top 5 applications by open finding count.
async fn fetch_top_risky_apps(pool: &PgPool) -> Result<Vec<TopRiskyApp>, AppError> {
    let rows = sqlx::query_as::<_, TopRiskyApp>(
        r#"
        SELECT
            a.id,
            a.app_name,
            a.app_code,
            COUNT(f.id) AS finding_count,
            COALESCE(SUM(CASE WHEN f.normalized_severity = 'Critical' THEN 1 ELSE 0 END), 0) AS critical_count,
            COALESCE(SUM(CASE WHEN f.normalized_severity = 'High'     THEN 1 ELSE 0 END), 0) AS high_count
        FROM applications a
        INNER JOIN findings f ON f.application_id = a.id
        WHERE f.status NOT IN ('Closed', 'Invalidated', 'False_Positive')
        GROUP BY a.id, a.app_name, a.app_code
        ORDER BY COUNT(f.id) DESC
        LIMIT 5
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Count open findings grouped by source tool (scanner).
async fn fetch_findings_by_source(pool: &PgPool) -> Result<Vec<SourceToolCount>, AppError> {
    let rows = sqlx::query_as::<_, SourceToolCount>(
        r#"
        SELECT source_tool, COUNT(*) AS count
        FROM findings
        WHERE status NOT IN ('Closed', 'False_Positive', 'Invalidated')
        GROUP BY source_tool
        ORDER BY count DESC
        "#,
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}
