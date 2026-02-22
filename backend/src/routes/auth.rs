//! Authentication routes: login, refresh, logout, user creation, profile.

use axum::{extract::State, Json};
use serde::Deserialize;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::middleware::rbac::RequireAdmin;
use crate::models::user::{CreateUser, UserResponse};
use crate::services::auth as auth_service;
use crate::services::auth::TokenPair;
use crate::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// POST /api/v1/auth/login
pub async fn login(
    State(state): State<AppState>,
    Json(body): Json<LoginRequest>,
) -> Result<Json<ApiResponse<TokenPair>>, AppError> {
    let tokens = auth_service::login(
        &state.db,
        &body.username,
        &body.password,
        &state.config.jwt_secret,
        state.config.jwt_access_token_expiry_secs,
        state.config.jwt_refresh_token_expiry_secs,
    )
    .await?;

    Ok(ApiResponse::success(tokens))
}

/// POST /api/v1/auth/refresh
pub async fn refresh(
    State(state): State<AppState>,
    Json(body): Json<RefreshRequest>,
) -> Result<Json<ApiResponse<TokenPair>>, AppError> {
    let tokens = auth_service::refresh_token(
        &state.db,
        &body.refresh_token,
        &state.config.jwt_secret,
        state.config.jwt_access_token_expiry_secs,
        state.config.jwt_refresh_token_expiry_secs,
    )
    .await?;

    Ok(ApiResponse::success(tokens))
}

/// POST /api/v1/auth/logout — client-side token discard (stateless JWT)
pub async fn logout() -> Json<ApiResponse<&'static str>> {
    // With stateless JWT, logout is handled client-side by discarding tokens.
    // A token blocklist could be added via Redis if needed.
    ApiResponse::success("Logged out successfully")
}

/// POST /api/v1/auth/users — admin-only user creation
pub async fn create_user(
    State(state): State<AppState>,
    RequireAdmin(_admin): RequireAdmin,
    Json(body): Json<CreateUser>,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    let user = auth_service::create_user(&state.db, &body).await?;
    Ok(ApiResponse::success(UserResponse::from(user)))
}

/// GET /api/v1/auth/me — current user profile
pub async fn me(
    State(state): State<AppState>,
    current_user: CurrentUser,
) -> Result<Json<ApiResponse<UserResponse>>, AppError> {
    let user = auth_service::find_user_by_id(&state.db, current_user.id).await?;
    Ok(ApiResponse::success(UserResponse::from(user)))
}
