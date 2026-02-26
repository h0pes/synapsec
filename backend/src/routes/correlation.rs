//! Correlation and relationship API routes.
//!
//! Provides endpoints for listing correlation groups, managing correlation
//! rules, triggering correlation runs, and manual relationship CRUD.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::middleware::rbac::{RequireAnalyst, RequireManager};
use crate::models::correlation_rule::CorrelationRule;
use crate::models::correlation_rule::{CreateCorrelationRule, UpdateCorrelationRule};
use crate::models::finding::FindingRelationship;
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::correlation_service::{
    self, CorrelationGroup, CorrelationGroupDetail, CorrelationGroupFilters,
    CorrelationRunResult, CreateRelationshipRequest,
};
use crate::AppState;

/// GET /api/v1/correlations/groups -- list correlation groups with pagination.
pub async fn list_groups(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
    Query(filters): Query<CorrelationGroupFilters>,
) -> Result<Json<ApiResponse<PagedResult<CorrelationGroup>>>, AppError> {
    let result = correlation_service::list_groups(&state.db, &filters, &pagination).await?;
    Ok(ApiResponse::success(result))
}

/// GET /api/v1/correlations/groups/:id -- get a group with member findings.
pub async fn get_group(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<CorrelationGroupDetail>>, AppError> {
    let detail = correlation_service::get_group(&state.db, id).await?;
    Ok(ApiResponse::success(detail))
}

/// GET /api/v1/correlations/rules -- list all correlation rules.
pub async fn list_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<CorrelationRule>>>, AppError> {
    let rules = correlation_service::list_rules(&state.db).await?;
    Ok(ApiResponse::success(rules))
}

/// POST /api/v1/correlations/rules -- create a custom correlation rule (manager+).
pub async fn create_rule(
    State(state): State<AppState>,
    RequireManager(manager): RequireManager,
    Json(body): Json<CreateCorrelationRule>,
) -> Result<Json<ApiResponse<CorrelationRule>>, AppError> {
    let rule = correlation_service::create_rule(&state.db, &body, manager.id).await?;
    Ok(ApiResponse::success(rule))
}

/// PUT /api/v1/correlations/rules/:id -- update a correlation rule (manager+).
pub async fn update_rule(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateCorrelationRule>,
) -> Result<Json<ApiResponse<CorrelationRule>>, AppError> {
    let rule = correlation_service::update_rule(&state.db, id, &body).await?;
    Ok(ApiResponse::success(rule))
}

/// POST /api/v1/correlations/run/:app_id -- trigger correlation for an application (manager+).
pub async fn run_correlation(
    State(state): State<AppState>,
    RequireManager(manager): RequireManager,
    Path(app_id): Path<Uuid>,
) -> Result<Json<ApiResponse<CorrelationRunResult>>, AppError> {
    let result =
        correlation_service::run_for_application(&state.db, app_id, manager.id).await?;
    Ok(ApiResponse::success(result))
}

/// POST /api/v1/relationships -- manually create a finding relationship (analyst+).
pub async fn create_relationship(
    State(state): State<AppState>,
    RequireAnalyst(_analyst): RequireAnalyst,
    current_user: CurrentUser,
    Json(body): Json<CreateRelationshipRequest>,
) -> Result<Json<ApiResponse<FindingRelationship>>, AppError> {
    let relationship =
        correlation_service::create_relationship(&state.db, &body, current_user.id).await?;
    Ok(ApiResponse::success(relationship))
}

/// DELETE /api/v1/relationships/:id -- remove a finding relationship (analyst+).
pub async fn delete_relationship(
    State(state): State<AppState>,
    RequireAnalyst(_analyst): RequireAnalyst,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    correlation_service::delete_relationship(&state.db, id).await?;
    Ok(ApiResponse::success(()))
}
