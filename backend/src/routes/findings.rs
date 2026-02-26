//! Finding routes: CRUD, status transitions, comments, history, bulk operations, and export.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::middleware::rbac::{RequireAnalyst, RequireManager};
use crate::models::finding::{
    CreateComment, CreateFinding, Finding, FindingComment, FindingHistory,
    FindingSummaryWithCategory, UpdateFinding,
};
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::finding::{
    self as finding_service, BulkAssign, BulkResult, BulkStatusUpdate, BulkTag, CategoryData,
    FindingFilters, FindingWithDetails, StatusUpdateRequest,
};
use crate::AppState;

/// GET /api/v1/findings — list findings with filters, pagination, and search.
///
/// Accepts `?include_category_data=true` to LEFT JOIN category tables
/// (`finding_sast`, `finding_sca`, `finding_dast`) and include category-specific
/// fields in each item. Without this parameter the response is backward-compatible
/// with the original `FindingSummary` shape.
pub async fn list(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
    Query(filters): Query<FindingFilters>,
) -> Result<Json<ApiResponse<PagedResult<FindingSummaryWithCategory>>>, AppError> {
    let include_category = filters.include_category_data.unwrap_or(false);

    let result = if include_category {
        finding_service::list_with_category(&state.db, &filters, &pagination).await?
    } else {
        // Use the lightweight query without JOINs, then wrap results
        let paged = finding_service::list(&state.db, &filters, &pagination).await?;
        PagedResult::new(
            paged
                .items
                .into_iter()
                .map(|summary| FindingSummaryWithCategory {
                    summary,
                    category_data: None,
                })
                .collect(),
            paged.total,
            &pagination,
        )
    };

    Ok(ApiResponse::success(result))
}

/// POST /api/v1/findings — create a finding (analyst+).
pub async fn create(
    State(state): State<AppState>,
    RequireAnalyst(_analyst): RequireAnalyst,
    Json(body): Json<CreateFindingWithCategory>,
) -> Result<Json<ApiResponse<Finding>>, AppError> {
    let finding =
        finding_service::create(&state.db, &body.finding, &body.category_data).await?;
    Ok(ApiResponse::success(finding))
}

/// Combined request body for creating a finding with category data.
#[derive(Debug, serde::Deserialize)]
pub struct CreateFindingWithCategory {
    #[serde(flatten)]
    pub finding: CreateFinding,
    pub category_data: CategoryData,
}

/// GET /api/v1/findings/:id — get finding by ID with category details.
pub async fn get_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<FindingWithDetails>>, AppError> {
    let result = finding_service::find_by_id(&state.db, id).await?;
    Ok(ApiResponse::success(result))
}

/// PUT /api/v1/findings/:id — update finding fields (analyst+).
pub async fn update(
    State(state): State<AppState>,
    RequireAnalyst(_analyst): RequireAnalyst,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateFinding>,
) -> Result<Json<ApiResponse<Finding>>, AppError> {
    let finding = finding_service::update(&state.db, id, &body).await?;
    Ok(ApiResponse::success(finding))
}

/// PATCH /api/v1/findings/:id/status — update finding status with justification (analyst+).
pub async fn update_status(
    State(state): State<AppState>,
    RequireAnalyst(_analyst): RequireAnalyst,
    current_user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(body): Json<StatusUpdateRequest>,
) -> Result<Json<ApiResponse<Finding>>, AppError> {
    let finding = finding_service::update_status(
        &state.db,
        id,
        &body.status,
        Some(current_user.id),
        &current_user.username,
        body.justification.as_deref(),
    )
    .await?;
    Ok(ApiResponse::success(finding))
}

/// POST /api/v1/findings/:id/comments — add a comment (analyst+).
pub async fn add_comment(
    State(state): State<AppState>,
    RequireAnalyst(_analyst): RequireAnalyst,
    current_user: CurrentUser,
    Path(id): Path<Uuid>,
    Json(body): Json<CreateComment>,
) -> Result<Json<ApiResponse<FindingComment>>, AppError> {
    let comment = finding_service::add_comment(
        &state.db,
        id,
        current_user.id,
        &current_user.username,
        &body,
    )
    .await?;
    Ok(ApiResponse::success(comment))
}

/// GET /api/v1/findings/:id/comments — list comments.
pub async fn list_comments(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<FindingComment>>>, AppError> {
    let comments = finding_service::list_comments(&state.db, id).await?;
    Ok(ApiResponse::success(comments))
}

/// GET /api/v1/findings/:id/history — get finding history.
pub async fn get_history(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<FindingHistory>>>, AppError> {
    let history = finding_service::get_history(&state.db, id).await?;
    Ok(ApiResponse::success(history))
}

/// POST /api/v1/findings/bulk/status — bulk status update (manager+).
pub async fn bulk_status(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    current_user: CurrentUser,
    Json(body): Json<BulkStatusUpdate>,
) -> Result<Json<ApiResponse<BulkResult>>, AppError> {
    let result = finding_service::bulk_update_status(
        &state.db,
        &body,
        Some(current_user.id),
        &current_user.username,
    )
    .await?;
    Ok(ApiResponse::success(result))
}

/// POST /api/v1/findings/bulk/assign — bulk assign (manager+).
pub async fn bulk_assign(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    Json(body): Json<BulkAssign>,
) -> Result<Json<ApiResponse<BulkResult>>, AppError> {
    let result = finding_service::bulk_assign(&state.db, &body).await?;
    Ok(ApiResponse::success(result))
}

/// POST /api/v1/findings/bulk/tag — bulk tag (manager+).
pub async fn bulk_tag(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    Json(body): Json<BulkTag>,
) -> Result<Json<ApiResponse<BulkResult>>, AppError> {
    let result = finding_service::bulk_tag(&state.db, &body).await?;
    Ok(ApiResponse::success(result))
}

/// Export format selector for the export endpoint.
#[derive(Debug, Clone, Copy, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    #[default]
    Csv,
    Json,
}

/// Query parameters for the export endpoint.
///
/// Combines the same filter parameters as the list endpoint with an
/// explicit `format` selector (defaults to CSV).
#[derive(Debug, Deserialize, Default)]
pub struct ExportParams {
    pub format: Option<ExportFormat>,
    #[serde(flatten)]
    pub filters: FindingFilters,
}

/// Flat CSV row for export. Flattens `FindingSummaryWithCategory` into a
/// single record suitable for the `csv` crate's `Serializer`.
#[derive(Debug, serde::Serialize)]
struct CsvExportRow {
    id: String,
    source_tool: String,
    finding_category: String,
    title: String,
    normalized_severity: String,
    status: String,
    composite_risk_score: Option<f32>,
    fingerprint: String,
    application_id: String,
    first_seen: String,
    last_seen: String,
    sla_status: String,
    // SAST fields
    file_path: String,
    line_number: String,
    rule_id: String,
    project: String,
    language: String,
    branch: String,
    // SCA fields
    package_name: String,
    package_version: String,
    fixed_version: String,
    dependency_type: String,
    known_exploited: String,
    // DAST fields
    target_url: String,
    parameter: String,
    web_application_name: String,
}

impl CsvExportRow {
    /// Convert a `FindingSummaryWithCategory` to a flat CSV row.
    fn from_finding(f: &FindingSummaryWithCategory) -> Self {
        let s = &f.summary;
        let cat = f.category_data.as_ref();

        Self {
            id: s.id.to_string(),
            source_tool: s.source_tool.clone(),
            finding_category: serde_json::to_string(&s.finding_category)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string(),
            title: s.title.clone(),
            normalized_severity: serde_json::to_string(&s.normalized_severity)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string(),
            status: serde_json::to_string(&s.status)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string(),
            composite_risk_score: s.composite_risk_score,
            fingerprint: s.fingerprint.clone(),
            application_id: s
                .application_id
                .map_or_else(String::new, |id| id.to_string()),
            first_seen: s.first_seen.to_rfc3339(),
            last_seen: s.last_seen.to_rfc3339(),
            sla_status: s
                .sla_status
                .as_ref()
                .map(|v| {
                    serde_json::to_string(v)
                        .unwrap_or_default()
                        .trim_matches('"')
                        .to_string()
                })
                .unwrap_or_default(),
            // SAST
            file_path: cat
                .and_then(|c| c.file_path.as_deref())
                .unwrap_or("")
                .to_string(),
            line_number: cat
                .and_then(|c| c.line_number)
                .map_or_else(String::new, |n| n.to_string()),
            rule_id: cat
                .and_then(|c| c.rule_id.as_deref())
                .unwrap_or("")
                .to_string(),
            project: cat
                .and_then(|c| c.project.as_deref())
                .unwrap_or("")
                .to_string(),
            language: cat
                .and_then(|c| c.language.as_deref())
                .unwrap_or("")
                .to_string(),
            branch: cat
                .and_then(|c| c.branch.as_deref())
                .unwrap_or("")
                .to_string(),
            // SCA
            package_name: cat
                .and_then(|c| c.package_name.as_deref())
                .unwrap_or("")
                .to_string(),
            package_version: cat
                .and_then(|c| c.package_version.as_deref())
                .unwrap_or("")
                .to_string(),
            fixed_version: cat
                .and_then(|c| c.fixed_version.as_deref())
                .unwrap_or("")
                .to_string(),
            dependency_type: cat
                .and_then(|c| c.dependency_type.as_deref())
                .unwrap_or("")
                .to_string(),
            known_exploited: cat
                .and_then(|c| c.known_exploited)
                .map_or_else(String::new, |v| v.to_string()),
            // DAST
            target_url: cat
                .and_then(|c| c.target_url.as_deref())
                .unwrap_or("")
                .to_string(),
            parameter: cat
                .and_then(|c| c.parameter.as_deref())
                .unwrap_or("")
                .to_string(),
            web_application_name: cat
                .and_then(|c| c.web_application_name.as_deref())
                .unwrap_or("")
                .to_string(),
        }
    }
}

/// GET /api/v1/findings/export — export findings as CSV or JSON.
///
/// Accepts the same filter query parameters as the list endpoint plus
/// `format=csv|json` (defaults to CSV). Returns all matching findings
/// without pagination, with `Content-Disposition: attachment` headers.
pub async fn export_findings(
    State(state): State<AppState>,
    _current_user: CurrentUser,
    Query(params): Query<ExportParams>,
) -> Result<Response, AppError> {
    let format = params.format.unwrap_or_default();
    let findings = finding_service::list_all_for_export(&state.db, &params.filters).await?;

    match format {
        ExportFormat::Json => {
            let body = serde_json::to_vec(&findings)
                .map_err(|e| AppError::Internal(format!("JSON serialization failed: {e}")))?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"findings_export.json\"",
                    ),
                ],
                body,
            )
                .into_response())
        }
        ExportFormat::Csv => {
            let mut wtr = csv::Writer::from_writer(Vec::new());

            for finding in &findings {
                let row = CsvExportRow::from_finding(finding);
                wtr.serialize(&row).map_err(|e| {
                    AppError::Internal(format!("CSV serialization failed: {e}"))
                })?;
            }

            let body = wtr.into_inner().map_err(|e| {
                AppError::Internal(format!("CSV flush failed: {e}"))
            })?;

            Ok((
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"findings_export.csv\"",
                    ),
                ],
                body,
            )
                .into_response())
        }
    }
}
