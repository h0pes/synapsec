//! Finding service: CRUD, search, status transitions, comments, and history.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::finding::{
    CreateComment, CreateFinding, Finding, FindingCategory, FindingComment, FindingHistory,
    FindingStatus, FindingSummary, SeverityLevel, SlaStatus, UpdateFinding,
};
use crate::models::finding_dast::CreateFindingDast;
use crate::models::finding_sast::CreateFindingSast;
use crate::models::finding_sca::CreateFindingSca;
use crate::models::pagination::{PagedResult, Pagination};

/// Category-specific data for finding creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "category")]
pub enum CategoryData {
    Sast(CreateFindingSast),
    Sca(CreateFindingSca),
    Dast(CreateFindingDast),
}

/// Combined finding with category-specific details for detail views.
#[derive(Debug, Clone, Serialize)]
pub struct FindingWithDetails {
    #[serde(flatten)]
    pub finding: Finding,
    pub sast: Option<crate::models::finding_sast::FindingSast>,
    pub sca: Option<crate::models::finding_sca::FindingSca>,
    pub dast: Option<crate::models::finding_dast::FindingDast>,
}

/// Filters for listing findings.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct FindingFilters {
    pub severity: Option<SeverityLevel>,
    pub status: Option<FindingStatus>,
    pub category: Option<FindingCategory>,
    pub application_id: Option<Uuid>,
    pub source_tool: Option<String>,
    pub sla_status: Option<SlaStatus>,
    pub search: Option<String>,
}

/// Request body for status update.
#[derive(Debug, Deserialize)]
pub struct StatusUpdateRequest {
    pub status: FindingStatus,
    pub justification: Option<String>,
}

/// Request for bulk status update.
#[derive(Debug, Deserialize)]
pub struct BulkStatusUpdate {
    pub finding_ids: Vec<Uuid>,
    pub status: FindingStatus,
    pub justification: Option<String>,
}

/// Request for bulk assignment.
#[derive(Debug, Deserialize)]
pub struct BulkAssign {
    pub finding_ids: Vec<Uuid>,
    pub remediation_owner: String,
}

/// Request for bulk tagging.
#[derive(Debug, Deserialize)]
pub struct BulkTag {
    pub finding_ids: Vec<Uuid>,
    pub tags: Vec<String>,
}

/// Result of a bulk operation.
#[derive(Debug, Serialize)]
pub struct BulkResult {
    pub updated: usize,
    pub total: usize,
}

/// Create a finding with category-specific data in a transaction.
pub async fn create(
    pool: &PgPool,
    input: &CreateFinding,
    category_data: &CategoryData,
) -> Result<Finding, AppError> {
    let mut tx = pool.begin().await?;

    let finding = sqlx::query_as::<_, Finding>(
        r#"
        INSERT INTO findings (
            source_tool, source_tool_version, source_finding_id,
            finding_category, title, description,
            normalized_severity, original_severity,
            cvss_score, cvss_vector, cwe_ids, cve_ids, owasp_category,
            confidence, fingerprint, application_id,
            tags, remediation_guidance, raw_finding, metadata
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
        RETURNING *
        "#,
    )
    .bind(&input.source_tool)
    .bind(&input.source_tool_version)
    .bind(&input.source_finding_id)
    .bind(&input.finding_category)
    .bind(&input.title)
    .bind(&input.description)
    .bind(&input.normalized_severity)
    .bind(&input.original_severity)
    .bind(input.cvss_score)
    .bind(&input.cvss_vector)
    .bind(serde_json::to_value(&input.cwe_ids).unwrap_or_default())
    .bind(serde_json::to_value(&input.cve_ids).unwrap_or_default())
    .bind(&input.owasp_category)
    .bind(&input.confidence)
    .bind(&input.fingerprint)
    .bind(input.application_id)
    .bind(serde_json::to_value(&input.tags).unwrap_or_default())
    .bind(&input.remediation_guidance)
    .bind(&input.raw_finding)
    .bind(&input.metadata)
    .fetch_one(&mut *tx)
    .await?;

    // Insert category-specific data
    match category_data {
        CategoryData::Sast(sast) => {
            sqlx::query(
                r#"
                INSERT INTO finding_sast (
                    finding_id, file_path, line_number_start, line_number_end,
                    project, rule_name, rule_id, issue_type, branch, source_url,
                    scanner_creation_date, baseline_date, last_analysis_date,
                    code_snippet, taint_source, taint_sink, language, framework,
                    scanner_description, scanner_tags, quality_gate
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                        $14, $15, $16, $17, $18, $19, $20, $21)
                "#,
            )
            .bind(finding.id)
            .bind(&sast.file_path)
            .bind(sast.line_number_start)
            .bind(sast.line_number_end)
            .bind(&sast.project)
            .bind(&sast.rule_name)
            .bind(&sast.rule_id)
            .bind(&sast.issue_type)
            .bind(&sast.branch)
            .bind(&sast.source_url)
            .bind(sast.scanner_creation_date)
            .bind(sast.baseline_date)
            .bind(sast.last_analysis_date)
            .bind(&sast.code_snippet)
            .bind(&sast.taint_source)
            .bind(&sast.taint_sink)
            .bind(&sast.language)
            .bind(&sast.framework)
            .bind(&sast.scanner_description)
            .bind(serde_json::to_value(&sast.scanner_tags).unwrap_or_default())
            .bind(&sast.quality_gate)
            .execute(&mut *tx)
            .await?;
        }
        CategoryData::Sca(sca) => {
            sqlx::query(
                r#"
                INSERT INTO finding_sca (
                    finding_id, package_name, package_version, package_type,
                    fixed_version, dependency_type, dependency_path, license,
                    license_risk, sbom_reference, epss_score, known_exploited,
                    exploit_maturity, affected_artifact, build_project
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
                "#,
            )
            .bind(finding.id)
            .bind(&sca.package_name)
            .bind(&sca.package_version)
            .bind(&sca.package_type)
            .bind(&sca.fixed_version)
            .bind(&sca.dependency_type)
            .bind(&sca.dependency_path)
            .bind(&sca.license)
            .bind(&sca.license_risk)
            .bind(&sca.sbom_reference)
            .bind(sca.epss_score)
            .bind(sca.known_exploited)
            .bind(&sca.exploit_maturity)
            .bind(&sca.affected_artifact)
            .bind(&sca.build_project)
            .execute(&mut *tx)
            .await?;
        }
        CategoryData::Dast(dast) => {
            sqlx::query(
                r#"
                INSERT INTO finding_dast (
                    finding_id, target_url, http_method, parameter,
                    attack_vector, request_evidence, response_evidence,
                    authentication_required, authentication_context,
                    web_application_name, scan_policy
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                "#,
            )
            .bind(finding.id)
            .bind(&dast.target_url)
            .bind(&dast.http_method)
            .bind(&dast.parameter)
            .bind(&dast.attack_vector)
            .bind(&dast.request_evidence)
            .bind(&dast.response_evidence)
            .bind(dast.authentication_required)
            .bind(&dast.authentication_context)
            .bind(&dast.web_application_name)
            .bind(&dast.scan_policy)
            .execute(&mut *tx)
            .await?;
        }
    }

    tx.commit().await?;
    Ok(finding)
}

/// Find a finding by ID with category-specific details.
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<FindingWithDetails, AppError> {
    let finding = sqlx::query_as::<_, Finding>("SELECT * FROM findings WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

    let sast = match finding.finding_category {
        FindingCategory::Sast => {
            sqlx::query_as::<_, crate::models::finding_sast::FindingSast>(
                "SELECT * FROM finding_sast WHERE finding_id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
        _ => None,
    };

    let sca = match finding.finding_category {
        FindingCategory::Sca => {
            sqlx::query_as::<_, crate::models::finding_sca::FindingSca>(
                "SELECT * FROM finding_sca WHERE finding_id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
        _ => None,
    };

    let dast = match finding.finding_category {
        FindingCategory::Dast => {
            sqlx::query_as::<_, crate::models::finding_dast::FindingDast>(
                "SELECT * FROM finding_dast WHERE finding_id = $1",
            )
            .bind(id)
            .fetch_optional(pool)
            .await?
        }
        _ => None,
    };

    Ok(FindingWithDetails {
        finding,
        sast,
        sca,
        dast,
    })
}

/// Find a finding by fingerprint (for deduplication).
pub async fn find_by_fingerprint(
    pool: &PgPool,
    fingerprint: &str,
) -> Result<Option<Finding>, AppError> {
    let finding =
        sqlx::query_as::<_, Finding>("SELECT * FROM findings WHERE fingerprint = $1")
            .bind(fingerprint)
            .fetch_optional(pool)
            .await?;
    Ok(finding)
}

/// List findings with filters, pagination, and optional full-text search.
pub async fn list(
    pool: &PgPool,
    filters: &FindingFilters,
    pagination: &Pagination,
) -> Result<PagedResult<FindingSummary>, AppError> {
    let mut conditions: Vec<String> = Vec::new();
    let mut param_index = 0u32;

    if filters.severity.is_some() {
        param_index += 1;
        conditions.push(format!("normalized_severity = ${param_index}"));
    }
    if filters.status.is_some() {
        param_index += 1;
        conditions.push(format!("status = ${param_index}"));
    }
    if filters.category.is_some() {
        param_index += 1;
        conditions.push(format!("finding_category = ${param_index}"));
    }
    if filters.application_id.is_some() {
        param_index += 1;
        conditions.push(format!("application_id = ${param_index}"));
    }
    if filters.source_tool.is_some() {
        param_index += 1;
        conditions.push(format!("source_tool = ${param_index}"));
    }
    if filters.sla_status.is_some() {
        param_index += 1;
        conditions.push(format!("sla_status = ${param_index}"));
    }
    if filters.search.is_some() {
        param_index += 1;
        conditions.push(format!(
            "search_vector @@ plainto_tsquery('english', ${param_index})"
        ));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let count_sql = format!("SELECT COUNT(*) FROM findings {where_clause}");
    let data_sql = format!(
        "SELECT id, source_tool, finding_category, title, normalized_severity, status, \
         composite_risk_score, fingerprint, application_id, first_seen, last_seen, sla_status \
         FROM findings {where_clause} \
         ORDER BY composite_risk_score DESC NULLS LAST, normalized_severity ASC, first_seen DESC \
         LIMIT {} OFFSET {}",
        pagination.limit(),
        pagination.offset()
    );

    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    let mut data_query = sqlx::query_as::<_, FindingSummary>(&data_sql);

    macro_rules! bind_both {
        ($val:expr) => {
            count_query = count_query.bind($val);
            data_query = data_query.bind($val);
        };
    }

    if let Some(ref severity) = filters.severity {
        bind_both!(severity);
    }
    if let Some(ref status) = filters.status {
        bind_both!(status);
    }
    if let Some(ref category) = filters.category {
        bind_both!(category);
    }
    if let Some(ref app_id) = filters.application_id {
        bind_both!(app_id);
    }
    if let Some(ref tool) = filters.source_tool {
        bind_both!(tool);
    }
    if let Some(ref sla) = filters.sla_status {
        bind_both!(sla);
    }
    if let Some(ref search) = filters.search {
        bind_both!(search);
    }

    let total = count_query.fetch_one(pool).await?;
    let items = data_query.fetch_all(pool).await?;

    Ok(PagedResult::new(items, total, pagination))
}

/// Update the status of a finding with history tracking.
pub async fn update_status(
    pool: &PgPool,
    id: Uuid,
    new_status: &FindingStatus,
    actor_id: Option<Uuid>,
    actor_name: &str,
    justification: Option<&str>,
) -> Result<Finding, AppError> {
    let existing = sqlx::query_as::<_, Finding>("SELECT * FROM findings WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

    let old_status = &existing.status;

    let mut tx = pool.begin().await?;

    let finding = sqlx::query_as::<_, Finding>(
        "UPDATE findings SET status = $2, status_changed_at = NOW(), updated_at = NOW() \
         WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .bind(new_status)
    .fetch_one(&mut *tx)
    .await?;

    // Record history
    sqlx::query(
        "INSERT INTO finding_history (finding_id, action, field_changed, old_value, new_value, \
         actor_id, actor_name, justification) \
         VALUES ($1, 'status_change', 'status', $2, $3, $4, $5, $6)",
    )
    .bind(id)
    .bind(serde_json::to_string(old_status).unwrap_or_default().trim_matches('"'))
    .bind(serde_json::to_string(new_status).unwrap_or_default().trim_matches('"'))
    .bind(actor_id)
    .bind(actor_name)
    .bind(justification)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(finding)
}

/// Update general finding fields.
pub async fn update(pool: &PgPool, id: Uuid, input: &UpdateFinding) -> Result<Finding, AppError> {
    // Verify finding exists
    let _ = sqlx::query_as::<_, Finding>("SELECT id FROM findings WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

    let finding = sqlx::query_as::<_, Finding>(
        r#"
        UPDATE findings SET
            normalized_severity = COALESCE($2, normalized_severity),
            status = COALESCE($3, status),
            application_id = COALESCE($4, application_id),
            remediation_owner = COALESCE($5, remediation_owner),
            office_owner = COALESCE($6, office_owner),
            office_manager = COALESCE($7, office_manager),
            sla_due_date = COALESCE($8, sla_due_date),
            sla_status = COALESCE($9, sla_status),
            tags = COALESCE($10, tags),
            remediation_guidance = COALESCE($11, remediation_guidance),
            metadata = COALESCE($12, metadata),
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(id)
    .bind(&input.normalized_severity)
    .bind(&input.status)
    .bind(input.application_id)
    .bind(&input.remediation_owner)
    .bind(&input.office_owner)
    .bind(&input.office_manager)
    .bind(input.sla_due_date)
    .bind(&input.sla_status)
    .bind(input.tags.as_ref().map(|t| serde_json::to_value(t).unwrap_or_default()))
    .bind(&input.remediation_guidance)
    .bind(&input.metadata)
    .fetch_one(pool)
    .await?;

    Ok(finding)
}

/// Add a comment to a finding.
pub async fn add_comment(
    pool: &PgPool,
    finding_id: Uuid,
    author_id: Uuid,
    author_name: &str,
    input: &CreateComment,
) -> Result<FindingComment, AppError> {
    // Verify finding exists
    let _ = sqlx::query_scalar::<_, Uuid>("SELECT id FROM findings WHERE id = $1")
        .bind(finding_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Finding not found".to_string()))?;

    let comment = sqlx::query_as::<_, FindingComment>(
        "INSERT INTO finding_comments (finding_id, author_id, author_name, content) \
         VALUES ($1, $2, $3, $4) RETURNING *",
    )
    .bind(finding_id)
    .bind(author_id)
    .bind(author_name)
    .bind(&input.content)
    .fetch_one(pool)
    .await?;

    Ok(comment)
}

/// List comments for a finding.
pub async fn list_comments(
    pool: &PgPool,
    finding_id: Uuid,
) -> Result<Vec<FindingComment>, AppError> {
    let comments = sqlx::query_as::<_, FindingComment>(
        "SELECT * FROM finding_comments WHERE finding_id = $1 ORDER BY created_at ASC",
    )
    .bind(finding_id)
    .fetch_all(pool)
    .await?;
    Ok(comments)
}

/// Get the history for a finding.
pub async fn get_history(
    pool: &PgPool,
    finding_id: Uuid,
) -> Result<Vec<FindingHistory>, AppError> {
    let history = sqlx::query_as::<_, FindingHistory>(
        "SELECT * FROM finding_history WHERE finding_id = $1 ORDER BY created_at DESC",
    )
    .bind(finding_id)
    .fetch_all(pool)
    .await?;
    Ok(history)
}

/// Bulk update status for multiple findings.
pub async fn bulk_update_status(
    pool: &PgPool,
    input: &BulkStatusUpdate,
    actor_id: Option<Uuid>,
    actor_name: &str,
) -> Result<BulkResult, AppError> {
    let mut updated = 0usize;
    for &id in &input.finding_ids {
        match update_status(
            pool,
            id,
            &input.status,
            actor_id,
            actor_name,
            input.justification.as_deref(),
        )
        .await
        {
            Ok(_) => updated += 1,
            Err(AppError::NotFound(_)) => {} // Skip missing findings
            Err(e) => return Err(e),
        }
    }
    Ok(BulkResult {
        updated,
        total: input.finding_ids.len(),
    })
}

/// Bulk assign remediation owner for multiple findings.
pub async fn bulk_assign(pool: &PgPool, input: &BulkAssign) -> Result<BulkResult, AppError> {
    let result = sqlx::query(
        "UPDATE findings SET remediation_owner = $1, updated_at = NOW() WHERE id = ANY($2)",
    )
    .bind(&input.remediation_owner)
    .bind(&input.finding_ids)
    .execute(pool)
    .await?;

    Ok(BulkResult {
        updated: result.rows_affected() as usize,
        total: input.finding_ids.len(),
    })
}

/// Bulk add tags to multiple findings.
pub async fn bulk_tag(pool: &PgPool, input: &BulkTag) -> Result<BulkResult, AppError> {
    let tags_json = serde_json::to_value(&input.tags).unwrap_or_default();
    let result = sqlx::query(
        "UPDATE findings SET tags = tags || $1, updated_at = NOW() WHERE id = ANY($2)",
    )
    .bind(&tags_json)
    .bind(&input.finding_ids)
    .execute(pool)
    .await?;

    Ok(BulkResult {
        updated: result.rows_affected() as usize,
        total: input.finding_ids.len(),
    })
}

/// Update last_seen timestamp for a finding (used during re-ingestion).
pub async fn touch_last_seen(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
    sqlx::query("UPDATE findings SET last_seen = NOW(), updated_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
