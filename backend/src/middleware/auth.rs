//! JWT authentication extractor for Axum handlers.

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::user::UserRole;
use crate::services::auth as auth_service;
use crate::AppState;

/// Authenticated user extracted from JWT Bearer token.
///
/// Use as an Axum extractor in handlers that require authentication:
/// ```ignore
/// async fn handler(current_user: CurrentUser) -> impl IntoResponse { ... }
/// ```
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: Uuid,
    pub username: String,
    pub role: UserRole,
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AppError::Unauthorized)?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AppError::Unauthorized)?;

        let claims = auth_service::validate_token(token, &state.config.jwt_secret)?;

        if claims.token_type != "access" {
            return Err(AppError::Unauthorized);
        }

        let user_id: Uuid = claims
            .user_id
            .parse()
            .map_err(|_| AppError::Unauthorized)?;

        let role: UserRole =
            serde_json::from_str(&format!("\"{}\"", claims.role)).map_err(|_| {
                AppError::Internal(format!("Invalid role in token: {}", claims.role))
            })?;

        Ok(CurrentUser {
            id: user_id,
            username: claims.sub,
            role,
        })
    }
}
