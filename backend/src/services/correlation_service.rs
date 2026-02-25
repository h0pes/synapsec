//! Database-backed correlation service for groups, rules, and relationships.
//!
//! Separates DB-dependent operations from the pure correlation logic in
//! [`crate::services::correlation`]. Handles CRUD for correlation rules,
//! relationship management, and orchestrating correlation runs.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::correlation_rule::{CorrelationRule, CreateCorrelationRule, UpdateCorrelationRule};
use crate::models::finding::{
    ConfidenceLevel, FindingCategory, FindingRelationship, FindingSummary, RelationshipType,
};
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::correlation::{self, CorrelationCandidate};

// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

/// Summary of a correlation group (related findings clustered together).
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationGroup {
    pub id: Uuid,
    pub primary_finding_id: Uuid,
    pub member_count: i64,
    pub tool_coverage: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// A correlation group with its full member finding list.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationGroupDetail {
    pub group: CorrelationGroup,
    pub members: Vec<FindingSummary>,
}

/// Result of a correlation run for an application.
#[derive(Debug, Clone, Serialize)]
pub struct CorrelationRunResult {
    pub new_relationships: usize,
    pub total_findings_analyzed: usize,
}

/// Request body for manually creating a finding relationship.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateRelationshipRequest {
    pub source_finding_id: Uuid,
    pub target_finding_id: Uuid,
    pub relationship_type: RelationshipType,
    pub confidence: Option<ConfidenceLevel>,
    pub notes: Option<String>,
}

/// Filters for listing correlation groups.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CorrelationGroupFilters {
    pub application_id: Option<Uuid>,
}

// ---------------------------------------------------------------------------
// Internal row types for sqlx queries
// ---------------------------------------------------------------------------

/// Row returned by the group list query.
#[derive(Debug, sqlx::FromRow)]
struct GroupRow {
    source_finding_id: Uuid,
    member_count: i64,
    tools: Option<String>,
    created_at: DateTime<Utc>,
}

/// Row returned by the group member query.
#[derive(Debug, sqlx::FromRow)]
struct MemberIdRow {
    finding_id: Uuid,
}

/// Row for building a [`CorrelationCandidate`] from joined finding data.
#[derive(Debug, sqlx::FromRow)]
struct CandidateRow {
    id: Uuid,
    finding_category: FindingCategory,
    application_id: Option<Uuid>,
    source_tool: String,
    cve_ids: serde_json::Value,
    cwe_ids: serde_json::Value,
    rule_id: Option<String>,
    file_path: Option<String>,
    branch: Option<String>,
    target_url: Option<String>,
    parameter: Option<String>,
    package_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Correlation groups
// ---------------------------------------------------------------------------

/// List correlation groups with pagination and optional application filter.
pub async fn list_groups(
    pool: &PgPool,
    filters: &CorrelationGroupFilters,
    pagination: &Pagination,
) -> Result<PagedResult<CorrelationGroup>, AppError> {
    // Count total groups
    let count_row = if let Some(app_id) = filters.application_id {
        sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(DISTINCT fr.source_finding_id)
            FROM finding_relationships fr
            JOIN findings f ON f.id = fr.source_finding_id
            WHERE f.application_id = $1
            "#,
        )
        .bind(app_id)
        .fetch_one(pool)
        .await?
    } else {
        sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(DISTINCT source_finding_id) FROM finding_relationships",
        )
        .fetch_one(pool)
        .await?
    };

    // Fetch groups with member counts and tool coverage
    let rows = if let Some(app_id) = filters.application_id {
        sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT
                fr.source_finding_id,
                COUNT(DISTINCT fr.target_finding_id) + 1 AS member_count,
                STRING_AGG(DISTINCT f2.source_tool, ',') AS tools,
                MIN(fr.created_at) AS created_at
            FROM finding_relationships fr
            JOIN findings f ON f.id = fr.source_finding_id
            JOIN findings f2 ON f2.id = fr.target_finding_id OR f2.id = fr.source_finding_id
            WHERE f.application_id = $1
            GROUP BY fr.source_finding_id
            ORDER BY MIN(fr.created_at) DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(app_id)
        .bind(pagination.limit())
        .bind(pagination.offset())
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as::<_, GroupRow>(
            r#"
            SELECT
                fr.source_finding_id,
                COUNT(DISTINCT fr.target_finding_id) + 1 AS member_count,
                STRING_AGG(DISTINCT f2.source_tool, ',') AS tools,
                MIN(fr.created_at) AS created_at
            FROM finding_relationships fr
            JOIN findings f2 ON f2.id = fr.target_finding_id OR f2.id = fr.source_finding_id
            GROUP BY fr.source_finding_id
            ORDER BY MIN(fr.created_at) DESC
            LIMIT $1 OFFSET $2
            "#,
        )
        .bind(pagination.limit())
        .bind(pagination.offset())
        .fetch_all(pool)
        .await?
    };

    let groups = rows
        .into_iter()
        .map(|row| CorrelationGroup {
            id: row.source_finding_id,
            primary_finding_id: row.source_finding_id,
            member_count: row.member_count,
            tool_coverage: row
                .tools
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
            created_at: row.created_at,
        })
        .collect();

    Ok(PagedResult::new(groups, count_row, pagination))
}

/// Get a single correlation group with its member findings.
pub async fn get_group(pool: &PgPool, group_id: Uuid) -> Result<CorrelationGroupDetail, AppError> {
    // Collect all finding IDs reachable from the group root
    let member_ids = sqlx::query_as::<_, MemberIdRow>(
        r#"
        SELECT DISTINCT finding_id FROM (
            SELECT source_finding_id AS finding_id
            FROM finding_relationships
            WHERE source_finding_id = $1 OR target_finding_id = $1
            UNION
            SELECT target_finding_id AS finding_id
            FROM finding_relationships
            WHERE source_finding_id = $1 OR target_finding_id = $1
        ) sub
        "#,
    )
    .bind(group_id)
    .fetch_all(pool)
    .await?;

    if member_ids.is_empty() {
        return Err(AppError::NotFound(format!(
            "Correlation group {group_id} not found"
        )));
    }

    let ids: Vec<Uuid> = member_ids.iter().map(|r| r.finding_id).collect();

    let members = sqlx::query_as::<_, FindingSummary>(
        r#"
        SELECT
            id, source_tool, finding_category, title,
            normalized_severity, status, composite_risk_score,
            fingerprint, application_id, first_seen, last_seen,
            sla_status
        FROM findings
        WHERE id = ANY($1)
        ORDER BY first_seen ASC
        "#,
    )
    .bind(&ids)
    .fetch_all(pool)
    .await?;

    let tool_coverage: Vec<String> = members
        .iter()
        .map(|m| m.source_tool.clone())
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();

    let earliest = members
        .iter()
        .map(|m| m.first_seen)
        .min()
        .unwrap_or_else(Utc::now);

    let group = CorrelationGroup {
        id: group_id,
        primary_finding_id: group_id,
        member_count: members.len() as i64,
        tool_coverage,
        created_at: earliest,
    };

    Ok(CorrelationGroupDetail { group, members })
}

// ---------------------------------------------------------------------------
// Correlation rules CRUD
// ---------------------------------------------------------------------------

/// List all correlation rules ordered by priority descending.
pub async fn list_rules(pool: &PgPool) -> Result<Vec<CorrelationRule>, AppError> {
    let rules = sqlx::query_as::<_, CorrelationRule>(
        "SELECT * FROM correlation_rules ORDER BY priority DESC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rules)
}

/// Create a new correlation rule.
pub async fn create_rule(
    pool: &PgPool,
    input: &CreateCorrelationRule,
    user_id: Uuid,
) -> Result<CorrelationRule, AppError> {
    let confidence = input.confidence.clone().unwrap_or(ConfidenceLevel::Medium);
    let priority = input.priority.unwrap_or(0);

    let rule = sqlx::query_as::<_, CorrelationRule>(
        r#"
        INSERT INTO correlation_rules (name, description, rule_type, conditions, confidence, priority, created_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING *
        "#,
    )
    .bind(&input.name)
    .bind(&input.description)
    .bind(&input.rule_type)
    .bind(&input.conditions)
    .bind(&confidence)
    .bind(priority)
    .bind(user_id)
    .fetch_one(pool)
    .await?;

    Ok(rule)
}

/// Update an existing correlation rule.
pub async fn update_rule(
    pool: &PgPool,
    id: Uuid,
    input: &UpdateCorrelationRule,
) -> Result<CorrelationRule, AppError> {
    let existing = sqlx::query_as::<_, CorrelationRule>(
        "SELECT * FROM correlation_rules WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Correlation rule {id} not found")))?;

    let name = input.name.as_deref().unwrap_or(&existing.name);
    let description = input.description.as_deref().or(existing.description.as_deref());
    let rule_type = input.rule_type.as_deref().unwrap_or(&existing.rule_type);
    let conditions = input.conditions.as_ref().unwrap_or(&existing.conditions);
    let confidence = input.confidence.as_ref().unwrap_or(&existing.confidence);
    let is_active = input.is_active.unwrap_or(existing.is_active);
    let priority = input.priority.unwrap_or(existing.priority);

    let rule = sqlx::query_as::<_, CorrelationRule>(
        r#"
        UPDATE correlation_rules
        SET name = $1, description = $2, rule_type = $3, conditions = $4,
            confidence = $5, is_active = $6, priority = $7
        WHERE id = $8
        RETURNING *
        "#,
    )
    .bind(name)
    .bind(description)
    .bind(rule_type)
    .bind(conditions)
    .bind(confidence)
    .bind(is_active)
    .bind(priority)
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(rule)
}

// ---------------------------------------------------------------------------
// Correlation run
// ---------------------------------------------------------------------------

/// Run correlation engine for all findings in an application.
///
/// Loads findings, converts to candidates, runs the pure correlation logic,
/// and inserts any new relationships that do not already exist.
pub async fn run_for_application(
    pool: &PgPool,
    app_id: Uuid,
    user_id: Uuid,
) -> Result<CorrelationRunResult, AppError> {
    // Load all findings for the application with category-specific fields
    let rows = sqlx::query_as::<_, CandidateRow>(
        r#"
        SELECT
            f.id,
            f.finding_category,
            f.application_id,
            f.source_tool,
            f.cve_ids,
            f.cwe_ids,
            fs.rule_id,
            COALESCE(fs.file_path, NULL) AS file_path,
            fs.branch,
            fd.target_url,
            fd.parameter,
            fc.package_name
        FROM findings f
        LEFT JOIN findings_sast fs ON fs.finding_id = f.id
        LEFT JOIN findings_dast fd ON fd.finding_id = f.id
        LEFT JOIN findings_sca fc ON fc.finding_id = f.id
        WHERE f.application_id = $1
        "#,
    )
    .bind(app_id)
    .fetch_all(pool)
    .await?;

    let total_findings_analyzed = rows.len();
    let candidates: Vec<CorrelationCandidate> = rows.iter().map(row_to_candidate).collect();

    let mut new_relationships = 0usize;

    for (i, candidate) in candidates.iter().enumerate() {
        let others: Vec<CorrelationCandidate> = candidates
            .iter()
            .enumerate()
            .filter(|(j, _)| *j != i)
            .map(|(_, c)| c.clone())
            .collect();

        let matches = correlation::correlate_finding(candidate, &others);

        for m in matches {
            // Insert only if the relationship does not already exist
            let inserted = sqlx::query_scalar::<_, bool>(
                r#"
                INSERT INTO finding_relationships (source_finding_id, target_finding_id, relationship_type, confidence, created_by, notes)
                VALUES ($1, $2, $3, $4, $5, $6)
                ON CONFLICT (source_finding_id, target_finding_id, relationship_type) DO NOTHING
                RETURNING true
                "#,
            )
            .bind(candidate.id)
            .bind(m.existing_finding_id)
            .bind(&m.relationship_type)
            .bind(&m.confidence)
            .bind(user_id)
            .bind(&m.match_reason)
            .fetch_optional(pool)
            .await?;

            if inserted.is_some() {
                new_relationships += 1;
            }
        }
    }

    Ok(CorrelationRunResult {
        new_relationships,
        total_findings_analyzed,
    })
}

// ---------------------------------------------------------------------------
// Manual relationship management
// ---------------------------------------------------------------------------

/// Create a manual finding relationship.
pub async fn create_relationship(
    pool: &PgPool,
    input: &CreateRelationshipRequest,
    user_id: Uuid,
) -> Result<FindingRelationship, AppError> {
    // Verify both findings exist
    let source_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM findings WHERE id = $1)",
    )
    .bind(input.source_finding_id)
    .fetch_one(pool)
    .await?;

    if !source_exists {
        return Err(AppError::NotFound(format!(
            "Source finding {} not found",
            input.source_finding_id
        )));
    }

    let target_exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM findings WHERE id = $1)",
    )
    .bind(input.target_finding_id)
    .fetch_one(pool)
    .await?;

    if !target_exists {
        return Err(AppError::NotFound(format!(
            "Target finding {} not found",
            input.target_finding_id
        )));
    }

    let relationship = sqlx::query_as::<_, FindingRelationship>(
        r#"
        INSERT INTO finding_relationships (source_finding_id, target_finding_id, relationship_type, confidence, created_by, notes)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *
        "#,
    )
    .bind(input.source_finding_id)
    .bind(input.target_finding_id)
    .bind(&input.relationship_type)
    .bind(&input.confidence)
    .bind(user_id)
    .bind(&input.notes)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
            AppError::Conflict("Relationship already exists".to_string())
        }
        other => AppError::Database(other),
    })?;

    Ok(relationship)
}

/// Delete a finding relationship by ID.
pub async fn delete_relationship(pool: &PgPool, relationship_id: Uuid) -> Result<(), AppError> {
    let result = sqlx::query("DELETE FROM finding_relationships WHERE id = $1")
        .bind(relationship_id)
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Relationship {relationship_id} not found"
        )));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert a database row into a [`CorrelationCandidate`].
fn row_to_candidate(row: &CandidateRow) -> CorrelationCandidate {
    let cve_ids = json_array_to_strings(&row.cve_ids);
    let cwe_ids = json_array_to_strings(&row.cwe_ids);

    CorrelationCandidate {
        id: row.id,
        category: row.finding_category.clone(),
        application_id: row.application_id,
        source_tool: row.source_tool.clone(),
        cve_ids,
        cwe_ids,
        rule_id: row.rule_id.clone(),
        file_path: row.file_path.clone(),
        branch: row.branch.clone(),
        target_url: row.target_url.clone(),
        parameter: row.parameter.clone(),
        package_name: row.package_name.clone(),
    }
}

/// Extract strings from a JSON array value (e.g. `["CWE-89","CWE-79"]`).
fn json_array_to_strings(value: &serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        _ => Vec::new(),
    }
}
