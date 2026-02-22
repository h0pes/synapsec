//! Role-based access control extractor for Axum handlers.

use axum::{
    extract::FromRequestParts,
    http::request::Parts,
};

use crate::errors::AppError;
use crate::middleware::auth::CurrentUser;
use crate::models::user::UserRole;
use crate::AppState;

/// Extractor that requires the user to have Platform_Admin role.
#[derive(Debug, Clone)]
pub struct RequireAdmin(pub CurrentUser);

impl FromRequestParts<AppState> for RequireAdmin {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        if user.role != UserRole::PlatformAdmin {
            return Err(AppError::Forbidden(
                "Platform admin access required".to_string(),
            ));
        }
        Ok(RequireAdmin(user))
    }
}

/// Extractor that requires Platform_Admin or AppSec_Manager role.
#[derive(Debug, Clone)]
pub struct RequireManager(pub CurrentUser);

impl FromRequestParts<AppState> for RequireManager {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        match user.role {
            UserRole::PlatformAdmin | UserRole::AppSecManager => Ok(RequireManager(user)),
            _ => Err(AppError::Forbidden(
                "Manager or admin access required".to_string(),
            )),
        }
    }
}

/// Extractor that requires Platform_Admin, AppSec_Manager, or AppSec_Analyst role.
#[derive(Debug, Clone)]
pub struct RequireAnalyst(pub CurrentUser);

impl FromRequestParts<AppState> for RequireAnalyst {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let user = CurrentUser::from_request_parts(parts, state).await?;
        match user.role {
            UserRole::PlatformAdmin | UserRole::AppSecManager | UserRole::AppSecAnalyst => {
                Ok(RequireAnalyst(user))
            }
            _ => Err(AppError::Forbidden(
                "Analyst, manager, or admin access required".to_string(),
            )),
        }
    }
}
