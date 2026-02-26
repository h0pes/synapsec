//! Deduplication dashboard API routes.
//!
//! Provides endpoints for viewing duplicate-pair statistics, pending reviews,
//! decision history, and confirming or rejecting duplicate relationships.

use axum::{
    extract::{Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::middleware::rbac::RequireAnalyst;
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::dedup_dashboard::{self, DedupDecision, DedupStats, PendingReview};
use crate::AppState;

/// GET /api/v1/deduplication/stats -- aggregated dedup statistics.
pub async fn stats(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Json<ApiResponse<DedupStats>>, AppError> {
    let result = dedup_dashboard::get_stats(&state.db).await?;
    Ok(ApiResponse::success(result))
}

/// GET /api/v1/deduplication/pending -- paginated pending duplicate pairs.
pub async fn pending(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ApiResponse<PagedResult<PendingReview>>>, AppError> {
    let result = dedup_dashboard::list_pending(&state.db, &pagination).await?;
    Ok(ApiResponse::success(result))
}

/// GET /api/v1/deduplication/history -- paginated decision history.
pub async fn history(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ApiResponse<PagedResult<DedupDecision>>>, AppError> {
    let result = dedup_dashboard::list_history(&state.db, &pagination).await?;
    Ok(ApiResponse::success(result))
}

/// POST /api/v1/deduplication/{relationship_id}/confirm -- analyst confirms a duplicate.
pub async fn confirm(
    State(state): State<AppState>,
    RequireAnalyst(analyst): RequireAnalyst,
    Path(relationship_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    dedup_dashboard::confirm(&state.db, relationship_id, analyst.id).await?;
    Ok(ApiResponse::success(()))
}

/// POST /api/v1/deduplication/{relationship_id}/reject -- analyst rejects a duplicate.
pub async fn reject(
    State(state): State<AppState>,
    RequireAnalyst(analyst): RequireAnalyst,
    Path(relationship_id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    dedup_dashboard::reject(&state.db, relationship_id, analyst.id).await?;
    Ok(ApiResponse::success(()))
}
