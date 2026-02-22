//! Health check endpoints for liveness and readiness probes.

use axum::{extract::State, Json};
use serde::Serialize;

use crate::errors::ApiResponse;
use crate::AppState;

/// Readiness probe detail.
#[derive(Debug, Serialize)]
pub struct HealthStatus {
    pub status: String,
    pub database: String,
    pub redis: String,
}

/// Liveness probe — always returns OK if the process is running.
pub async fn live() -> &'static str {
    "OK"
}

/// Readiness probe — checks database and Redis connectivity.
pub async fn ready(State(state): State<AppState>) -> Json<ApiResponse<HealthStatus>> {
    let db_status = match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => "connected".to_string(),
        Err(e) => {
            tracing::warn!(error = %e, "Database health check failed");
            format!("error: {e}")
        }
    };

    let redis_status = match redis::Client::open(state.config.redis_url.as_str()) {
        Ok(client) => match client.get_multiplexed_async_connection().await {
            Ok(_) => "connected".to_string(),
            Err(e) => {
                tracing::warn!(error = %e, "Redis health check failed");
                format!("error: {e}")
            }
        },
        Err(e) => {
            tracing::warn!(error = %e, "Redis client creation failed");
            format!("error: {e}")
        }
    };

    ApiResponse::success(HealthStatus {
        status: "ok".to_string(),
        database: db_status,
        redis: redis_status,
    })
}
