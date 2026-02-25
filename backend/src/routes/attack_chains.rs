//! Attack chain API routes.
//!
//! Provides endpoints for viewing per-application correlation group
//! summaries and detailed attack chain breakdowns.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::attack_chains::{
    self, AppAttackChainDetail, AppAttackChainSummary, AttackChainFilters,
};
use crate::AppState;

/// GET /api/v1/attack-chains -- list applications with attack chain summaries.
pub async fn list(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(pagination): Query<Pagination>,
    Query(filters): Query<AttackChainFilters>,
) -> Result<Json<ApiResponse<PagedResult<AppAttackChainSummary>>>, AppError> {
    let result = attack_chains::list_summaries(&state.db, &filters, &pagination).await?;
    Ok(ApiResponse::success(result))
}

/// GET /api/v1/attack-chains/:app_id -- get attack chains for one application.
pub async fn get_by_app(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(app_id): Path<Uuid>,
    Query(filters): Query<AttackChainFilters>,
) -> Result<Json<ApiResponse<AppAttackChainDetail>>, AppError> {
    let detail = attack_chains::get_by_app(&state.db, app_id, &filters).await?;
    Ok(ApiResponse::success(detail))
}
