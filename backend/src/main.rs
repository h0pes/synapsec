use std::net::SocketAddr;

use axum::{routing::get, Router};
use mimalloc::MiMalloc;
use synapsec::{config::AppConfig, db, routes, AppState};
use tower_http::{
    compression::CompressionLayer,
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// M-MIMALLOC-APP: Use mimalloc as global allocator for improved performance.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "synapsec=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().json())
        .init();

    let config = AppConfig::from_env().expect("Failed to load configuration");

    // Database pool
    let pool = db::create_pool(&config.database_url, config.database_max_connections).await?;
    tracing::info!("Database connection pool created");

    // Run migrations
    sqlx::migrate!("./migrations").run(&pool).await?;
    tracing::info!("Database migrations applied");

    // CORS
    let cors = CorsLayer::new()
        .allow_origin(
            config
                .frontend_url
                .parse::<axum::http::HeaderValue>()
                .expect("Invalid FRONTEND_URL"),
        )
        .allow_methods(Any)
        .allow_headers(Any)
        .allow_credentials(true);

    let state = AppState {
        db: pool,
        config: config.clone(),
    };

    let app = Router::new()
        // Health endpoints (no auth required)
        .route("/health/live", get(routes::health::live))
        .route("/health/ready", get(routes::health::ready))
        // API v1 routes will be nested here:
        // .nest("/api/v1", api_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!(host = %addr, "Starting SynApSec API server");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
