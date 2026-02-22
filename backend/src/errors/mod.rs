//! Unified error handling with consistent API response envelope.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// Error detail in the API response envelope.
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: String,
    pub message: String,
}

/// Consistent JSON envelope for all API responses.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: Option<T>,
    pub error: Option<ApiError>,
}

impl<T: Serialize> ApiResponse<T> {
    /// Wrap a successful result in the envelope.
    pub fn success(data: T) -> Json<Self> {
        Json(Self {
            data: Some(data),
            error: None,
        })
    }

    /// Wrap an error in the envelope.
    pub fn error(code: &str, message: &str) -> Json<Self> {
        Json(Self {
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message: message.to_string(),
            }),
        })
    }
}

/// Application error type mapping to HTTP status codes.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Validation error: {0}")]
    Validation(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Invalid state transition: {0}")]
    InvalidTransition(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl AppError {
    /// Check if this error represents a not-found condition.
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound(_))
    }

    /// Check if this error represents an auth failure.
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, "NOT_FOUND", msg.clone()),
            AppError::Validation(msg) => {
                (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone())
            }
            AppError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHORIZED",
                "Authentication required".to_string(),
            ),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, "FORBIDDEN", msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, "CONFLICT", msg.clone()),
            AppError::InvalidTransition(msg) => {
                (StatusCode::BAD_REQUEST, "INVALID_TRANSITION", msg.clone())
            }
            AppError::Database(e) => {
                tracing::error!(error = %e, "Database error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An internal error occurred".to_string(),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!(error = %msg, "Internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An internal error occurred".to_string(),
                )
            }
        };

        let body = ApiResponse::<()> {
            data: None,
            error: Some(ApiError {
                code: code.to_string(),
                message,
            }),
        };

        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_response_success() {
        let response = ApiResponse::success("hello");
        let json = serde_json::to_value(&response.0).unwrap();
        assert_eq!(json["data"], "hello");
        assert!(json["error"].is_null());
    }

    #[test]
    fn api_response_error() {
        let response = ApiResponse::<()>::error("NOT_FOUND", "Item not found");
        let json = serde_json::to_value(&response.0).unwrap();
        assert!(json["data"].is_null());
        assert_eq!(json["error"]["code"], "NOT_FOUND");
        assert_eq!(json["error"]["message"], "Item not found");
    }

    #[test]
    fn app_error_is_not_found() {
        let err = AppError::NotFound("user".to_string());
        assert!(err.is_not_found());
        assert!(!err.is_unauthorized());
    }

    #[test]
    fn app_error_display() {
        let err = AppError::Validation("email is required".to_string());
        assert_eq!(err.to_string(), "Validation error: email is required");
    }

    #[test]
    fn app_error_from_sqlx() {
        let sqlx_err = sqlx::Error::RowNotFound;
        let err: AppError = sqlx_err.into();
        assert!(matches!(err, AppError::Database(_)));
    }
}
