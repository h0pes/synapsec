pub mod config;
pub mod db;
pub mod errors;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod services;

// These modules will be added as we build them:
// pub mod parsers;

use sqlx::PgPool;

/// Shared application state passed to all Axum handlers.
#[derive(Debug, Clone)]
pub struct AppState {
    pub db: PgPool,
    pub config: config::AppConfig,
}
