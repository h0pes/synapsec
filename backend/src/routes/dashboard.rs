//! Dashboard routes: aggregated statistics for the overview page.

use axum::{extract::State, Json};

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::services::dashboard::{self, DashboardStats};
use crate::AppState;

/// GET /api/v1/dashboard/stats — aggregated dashboard statistics.
pub async fn stats(
    State(state): State<AppState>,
    _user: CurrentUser,
) -> Result<Json<ApiResponse<DashboardStats>>, AppError> {
    let stats = dashboard::get_stats(&state.db).await?;
    Ok(ApiResponse::success(stats))
}
