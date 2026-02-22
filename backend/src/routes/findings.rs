//! Finding routes: CRUD, status transitions, comments, history, and bulk operations.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::middleware::rbac::{RequireAnalyst, RequireManager};
use crate::models::finding::{
    CreateComment, CreateFinding, Finding, FindingComment, FindingHistory, FindingSummary,
    UpdateFinding,
};
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::finding::{
    self as finding_service, BulkAssign, BulkResult, BulkStatusUpdate, BulkTag, CategoryData,
    FindingFilters, FindingWithDetails, StatusUpdateRequest,
};
use crate::AppState;

/// GET /api/v1/findings — list findings with filters, pagination, and search.
pub async fn list(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
    Query(filters): Query<FindingFilters>,
) -> Result<Json<ApiResponse<PagedResult<FindingSummary>>>, AppError> {
    let result = finding_service::list(&state.db, &filters, &pagination).await?;
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
