//! Finding service: CRUD, search, status transitions, comments, and history.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::finding::{
    CreateComment, CreateFinding, Finding, FindingCategory, FindingCategoryData, FindingComment,
    FindingHistory, FindingStatus, FindingSummary, FindingSummaryWithCategory, SeverityLevel,
    SlaStatus, UpdateFinding,
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
    /// When true, LEFT JOINs category tables to include category-specific fields.
    #[serde(default)]
    pub include_category_data: Option<bool>,

    // SAST-specific filters
    pub branch: Option<String>,
    pub rule_id: Option<String>,
    pub project: Option<String>,
    pub issue_type: Option<String>,
    pub quality_gate: Option<String>,
    pub sast_created_from: Option<DateTime<Utc>>,
    pub sast_created_to: Option<DateTime<Utc>>,
    pub baseline_from: Option<DateTime<Utc>>,
    pub baseline_to: Option<DateTime<Utc>>,

    // SCA-specific filters
    pub package_type: Option<String>,
    pub package_name: Option<String>,
    pub has_fix: Option<bool>,
    pub published_from: Option<DateTime<Utc>>,
    pub published_to: Option<DateTime<Utc>>,

    // DAST-specific filters
    pub target_url: Option<String>,
    pub exploitable: Option<bool>,
    pub dns_name: Option<String>,
    pub discovered_from: Option<DateTime<Utc>>,
    pub discovered_to: Option<DateTime<Utc>>,
}

impl FindingFilters {
    /// Whether any SAST-specific filters are active.
    pub fn has_sast_filters(&self) -> bool {
        self.branch.is_some()
            || self.rule_id.is_some()
            || self.project.is_some()
            || self.issue_type.is_some()
            || self.quality_gate.is_some()
            || self.sast_created_from.is_some()
            || self.sast_created_to.is_some()
            || self.baseline_from.is_some()
            || self.baseline_to.is_some()
    }

    /// Whether any SCA-specific filters are active.
    pub fn has_sca_filters(&self) -> bool {
        self.package_type.is_some()
            || self.package_name.is_some()
            || self.has_fix.is_some()
            || self.published_from.is_some()
            || self.published_to.is_some()
    }

    /// Whether any DAST-specific filters are active.
    pub fn has_dast_filters(&self) -> bool {
        self.target_url.is_some()
            || self.exploitable.is_some()
            || self.dns_name.is_some()
            || self.discovered_from.is_some()
            || self.discovered_to.is_some()
    }
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

/// List findings with category-specific data included via LEFT JOINs.
///
/// When a category filter is set, only that category's table is joined.
/// Otherwise all three category tables are joined. Category-specific filters
/// (SAST, SCA, DAST) also force the relevant table join.
pub async fn list_with_category(
    pool: &PgPool,
    filters: &FindingFilters,
    pagination: &Pagination,
) -> Result<PagedResult<FindingSummaryWithCategory>, AppError> {
    // Build WHERE conditions on the findings table (aliased as "f")
    let mut conditions: Vec<String> = Vec::new();
    let mut param_index = 0u32;

    if filters.severity.is_some() {
        param_index += 1;
        conditions.push(format!("f.normalized_severity = ${param_index}"));
    }
    if filters.status.is_some() {
        param_index += 1;
        conditions.push(format!("f.status = ${param_index}"));
    }
    if filters.category.is_some() {
        param_index += 1;
        conditions.push(format!("f.finding_category = ${param_index}"));
    }
    if filters.application_id.is_some() {
        param_index += 1;
        conditions.push(format!("f.application_id = ${param_index}"));
    }
    if filters.source_tool.is_some() {
        param_index += 1;
        conditions.push(format!("f.source_tool = ${param_index}"));
    }
    if filters.sla_status.is_some() {
        param_index += 1;
        conditions.push(format!("f.sla_status = ${param_index}"));
    }
    if filters.search.is_some() {
        param_index += 1;
        conditions.push(format!(
            "f.search_vector @@ plainto_tsquery('english', ${param_index})"
        ));
    }

    // SAST-specific conditions (table alias: s)
    if filters.branch.is_some() {
        param_index += 1;
        conditions.push(format!("s.branch = ${param_index}"));
    }
    if filters.rule_id.is_some() {
        param_index += 1;
        conditions.push(format!("s.rule_id = ${param_index}"));
    }
    if filters.project.is_some() {
        param_index += 1;
        conditions.push(format!("s.project ILIKE ${param_index}"));
    }
    if filters.issue_type.is_some() {
        param_index += 1;
        conditions.push(format!("s.issue_type = ${param_index}"));
    }
    if filters.quality_gate.is_some() {
        param_index += 1;
        conditions.push(format!("s.quality_gate = ${param_index}"));
    }
    if filters.sast_created_from.is_some() {
        param_index += 1;
        conditions.push(format!("s.scanner_creation_date >= ${param_index}"));
    }
    if filters.sast_created_to.is_some() {
        param_index += 1;
        conditions.push(format!("s.scanner_creation_date <= ${param_index}"));
    }
    if filters.baseline_from.is_some() {
        param_index += 1;
        conditions.push(format!("s.baseline_date >= ${param_index}"));
    }
    if filters.baseline_to.is_some() {
        param_index += 1;
        conditions.push(format!("s.baseline_date <= ${param_index}"));
    }

    // SCA-specific conditions (table alias: sc)
    if filters.package_type.is_some() {
        param_index += 1;
        conditions.push(format!("sc.package_type = ${param_index}"));
    }
    if filters.package_name.is_some() {
        param_index += 1;
        conditions.push(format!("sc.package_name ILIKE ${param_index}"));
    }
    if let Some(has_fix) = filters.has_fix {
        if has_fix {
            conditions.push("sc.fixed_version IS NOT NULL".to_string());
        } else {
            conditions.push("sc.fixed_version IS NULL".to_string());
        }
    }
    if filters.published_from.is_some() {
        param_index += 1;
        conditions.push(format!("f.first_seen >= ${param_index}"));
    }
    if filters.published_to.is_some() {
        param_index += 1;
        conditions.push(format!("f.first_seen <= ${param_index}"));
    }

    // DAST-specific conditions (table alias: d)
    if filters.target_url.is_some() {
        param_index += 1;
        conditions.push(format!("d.target_url ILIKE ${param_index}"));
    }
    if let Some(exploitable) = filters.exploitable {
        if exploitable {
            conditions.push(
                "(d.attack_vector IS NOT NULL AND d.attack_vector != '')".to_string(),
            );
        } else {
            conditions.push(
                "(d.attack_vector IS NULL OR d.attack_vector = '')".to_string(),
            );
        }
    }
    if filters.dns_name.is_some() {
        param_index += 1;
        conditions.push(format!("d.web_application_name ILIKE ${param_index}"));
    }
    if filters.discovered_from.is_some() {
        param_index += 1;
        conditions.push(format!("f.first_seen >= ${param_index}"));
    }
    if filters.discovered_to.is_some() {
        param_index += 1;
        conditions.push(format!("f.first_seen <= ${param_index}"));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    // Determine which category tables to JOIN based on the category filter
    // and any active category-specific filters.
    let join_sast = matches!(filters.category, None | Some(FindingCategory::Sast))
        || filters.has_sast_filters();
    let join_sca = matches!(filters.category, None | Some(FindingCategory::Sca))
        || filters.has_sca_filters();
    let join_dast = matches!(filters.category, None | Some(FindingCategory::Dast))
        || filters.has_dast_filters();

    // Build JOIN clauses
    let mut joins = String::new();
    if join_sast {
        joins.push_str(" LEFT JOIN finding_sast s ON s.finding_id = f.id");
    }
    if join_sca {
        joins.push_str(" LEFT JOIN finding_sca sc ON sc.finding_id = f.id");
    }
    if join_dast {
        joins.push_str(" LEFT JOIN finding_dast d ON d.finding_id = f.id");
    }

    // Build SELECT columns for category data
    let mut extra_columns = String::new();
    if join_sast {
        extra_columns.push_str(
            ", s.file_path AS sast_file_path, s.line_number_start AS sast_line_number, \
             s.rule_id AS sast_rule_id, s.project AS sast_project, \
             s.language AS sast_language, s.branch AS sast_branch",
        );
    }
    if join_sca {
        extra_columns.push_str(
            ", sc.package_name AS sca_package_name, sc.package_version AS sca_package_version, \
             sc.fixed_version AS sca_fixed_version, \
             sc.dependency_type::text AS sca_dependency_type, \
             sc.known_exploited AS sca_known_exploited",
        );
    }
    if join_dast {
        extra_columns.push_str(
            ", d.target_url AS dast_target_url, d.parameter AS dast_parameter, \
             d.web_application_name AS dast_web_application_name",
        );
    }

    let count_sql = format!("SELECT COUNT(*) FROM findings f {joins} {where_clause}");
    let data_sql = format!(
        "SELECT f.id, f.source_tool, f.finding_category, f.title, f.normalized_severity, \
         f.status, f.composite_risk_score, f.fingerprint, f.application_id, \
         f.first_seen, f.last_seen, f.sla_status{extra_columns} \
         FROM findings f {joins} {where_clause} \
         ORDER BY f.composite_risk_score DESC NULLS LAST, f.normalized_severity ASC, f.first_seen DESC \
         LIMIT {} OFFSET {}",
        pagination.limit(),
        pagination.offset()
    );

    // Pre-compute ILIKE patterns so they outlive the query bindings.
    let project_pattern = filters.project.as_ref().map(|v| format!("%{v}%"));
    let package_name_pattern = filters.package_name.as_ref().map(|v| format!("%{v}%"));
    let target_url_pattern = filters.target_url.as_ref().map(|v| format!("%{v}%"));
    let dns_name_pattern = filters.dns_name.as_ref().map(|v| format!("%{v}%"));

    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    let mut data_query = sqlx::query(&data_sql);

    macro_rules! bind_both_cat {
        ($val:expr) => {
            count_query = count_query.bind($val);
            data_query = data_query.bind($val);
        };
    }

    // Bind core filters — order must match WHERE clause construction above
    if let Some(ref severity) = filters.severity {
        bind_both_cat!(severity);
    }
    if let Some(ref status) = filters.status {
        bind_both_cat!(status);
    }
    if let Some(ref category) = filters.category {
        bind_both_cat!(category);
    }
    if let Some(ref app_id) = filters.application_id {
        bind_both_cat!(app_id);
    }
    if let Some(ref tool) = filters.source_tool {
        bind_both_cat!(tool);
    }
    if let Some(ref sla) = filters.sla_status {
        bind_both_cat!(sla);
    }
    if let Some(ref search) = filters.search {
        bind_both_cat!(search);
    }

    // Bind SAST-specific filters
    if let Some(ref branch) = filters.branch {
        bind_both_cat!(branch);
    }
    if let Some(ref rule_id) = filters.rule_id {
        bind_both_cat!(rule_id);
    }
    if let Some(ref pattern) = project_pattern {
        bind_both_cat!(pattern);
    }
    if let Some(ref issue_type) = filters.issue_type {
        bind_both_cat!(issue_type);
    }
    if let Some(ref quality_gate) = filters.quality_gate {
        bind_both_cat!(quality_gate);
    }
    if let Some(ref from) = filters.sast_created_from {
        bind_both_cat!(from);
    }
    if let Some(ref to) = filters.sast_created_to {
        bind_both_cat!(to);
    }
    if let Some(ref from) = filters.baseline_from {
        bind_both_cat!(from);
    }
    if let Some(ref to) = filters.baseline_to {
        bind_both_cat!(to);
    }

    // Bind SCA-specific filters (has_fix uses static SQL, no bind needed)
    if let Some(ref package_type) = filters.package_type {
        bind_both_cat!(package_type);
    }
    if let Some(ref pattern) = package_name_pattern {
        bind_both_cat!(pattern);
    }
    if let Some(ref from) = filters.published_from {
        bind_both_cat!(from);
    }
    if let Some(ref to) = filters.published_to {
        bind_both_cat!(to);
    }

    // Bind DAST-specific filters (exploitable uses static SQL, no bind needed)
    if let Some(ref pattern) = target_url_pattern {
        bind_both_cat!(pattern);
    }
    if let Some(ref pattern) = dns_name_pattern {
        bind_both_cat!(pattern);
    }
    if let Some(ref from) = filters.discovered_from {
        bind_both_cat!(from);
    }
    if let Some(ref to) = filters.discovered_to {
        bind_both_cat!(to);
    }

    let total = count_query.fetch_one(pool).await?;
    let rows = data_query.fetch_all(pool).await?;

    let items: Vec<FindingSummaryWithCategory> = rows
        .into_iter()
        .map(|row| {
            let finding_category: FindingCategory = row.get("finding_category");

            let summary = FindingSummary {
                id: row.get("id"),
                source_tool: row.get("source_tool"),
                finding_category: finding_category.clone(),
                title: row.get("title"),
                normalized_severity: row.get("normalized_severity"),
                status: row.get("status"),
                composite_risk_score: row.get("composite_risk_score"),
                fingerprint: row.get("fingerprint"),
                application_id: row.get("application_id"),
                first_seen: row.get("first_seen"),
                last_seen: row.get("last_seen"),
                sla_status: row.get("sla_status"),
            };

            let category_data = match finding_category {
                FindingCategory::Sast if join_sast => {
                    // Only populate if the SAST join actually returned data
                    let file_path: Option<String> = row.get("sast_file_path");
                    if file_path.is_some() {
                        Some(FindingCategoryData {
                            file_path,
                            line_number: row.get("sast_line_number"),
                            rule_id: row.get("sast_rule_id"),
                            project: row.get("sast_project"),
                            language: row.get("sast_language"),
                            branch: row.get("sast_branch"),
                            ..Default::default()
                        })
                    } else {
                        None
                    }
                }
                FindingCategory::Sca if join_sca => {
                    let package_name: Option<String> = row.get("sca_package_name");
                    if package_name.is_some() {
                        Some(FindingCategoryData {
                            package_name,
                            package_version: row.get("sca_package_version"),
                            fixed_version: row.get("sca_fixed_version"),
                            dependency_type: row.get("sca_dependency_type"),
                            known_exploited: row.get("sca_known_exploited"),
                            ..Default::default()
                        })
                    } else {
                        None
                    }
                }
                FindingCategory::Dast if join_dast => {
                    let target_url: Option<String> = row.get("dast_target_url");
                    if target_url.is_some() {
                        Some(FindingCategoryData {
                            target_url,
                            parameter: row.get("dast_parameter"),
                            web_application_name: row.get("dast_web_application_name"),
                            ..Default::default()
                        })
                    } else {
                        None
                    }
                }
                _ => None,
            };

            FindingSummaryWithCategory {
                summary,
                category_data,
            }
        })
        .collect();

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
