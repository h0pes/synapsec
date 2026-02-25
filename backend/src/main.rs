use std::net::SocketAddr;

use axum::{
    routing::{delete, get, patch, post, put},
    Router,
};
use mimalloc::MiMalloc;
use synapsec::{config::AppConfig, db, routes, AppState};
use axum::http::header;
use tower_http::{
    compression::CompressionLayer,
    cors::CorsLayer,
    trace::TraceLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

// M-MIMALLOC-APP: Use mimalloc as global allocator for improved performance.
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install rustls crypto provider (required for rustls 0.23+)
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

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
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
        ])
        .allow_credentials(true);

    let state = AppState {
        db: pool,
        config: config.clone(),
    };

    // API v1 auth routes
    let auth_routes = Router::new()
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/refresh", post(routes::auth::refresh))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/users", post(routes::auth::create_user))
        .route("/auth/me", get(routes::auth::me));

    // API v1 application routes
    let app_routes = Router::new()
        .route("/applications", get(routes::applications::list).post(routes::applications::create))
        .route("/applications/unverified", get(routes::applications::list_unverified))
        .route("/applications/import", post(routes::applications::import_bulk))
        .route("/applications/import/apm", post(routes::applications::import_apm))
        .route("/applications/code/{code}", get(routes::applications::get_by_code))
        .route("/applications/{id}", get(routes::applications::get_by_id).put(routes::applications::update));

    // API v1 finding routes
    let finding_routes = Router::new()
        .route("/findings", get(routes::findings::list).post(routes::findings::create))
        .route("/findings/bulk/status", post(routes::findings::bulk_status))
        .route("/findings/bulk/assign", post(routes::findings::bulk_assign))
        .route("/findings/bulk/tag", post(routes::findings::bulk_tag))
        .route("/findings/{id}", get(routes::findings::get_by_id).put(routes::findings::update))
        .route("/findings/{id}/status", patch(routes::findings::update_status))
        .route("/findings/{id}/comments", get(routes::findings::list_comments).post(routes::findings::add_comment))
        .route("/findings/{id}/history", get(routes::findings::get_history));

    // API v1 ingestion routes
    let ingestion_routes = Router::new()
        .route("/ingestion/upload", post(routes::ingestion::upload))
        .route("/ingestion/history", get(routes::ingestion::history))
        .route("/ingestion/{id}", get(routes::ingestion::get_log));

    // API v1 correlation routes
    let correlation_routes = Router::new()
        .route("/correlations/groups", get(routes::correlation::list_groups))
        .route("/correlations/groups/{id}", get(routes::correlation::get_group))
        .route("/correlations/rules", get(routes::correlation::list_rules).post(routes::correlation::create_rule))
        .route("/correlations/rules/{id}", put(routes::correlation::update_rule))
        .route("/correlations/run/{app_id}", post(routes::correlation::run_correlation))
        .route("/relationships", post(routes::correlation::create_relationship))
        .route("/relationships/{id}", delete(routes::correlation::delete_relationship));

    // API v1 dashboard routes
    let dashboard_routes = Router::new()
        .route("/dashboard/stats", get(routes::dashboard::stats));

    let app = Router::new()
        // Health endpoints (no auth required)
        .route("/health/live", get(routes::health::live))
        .route("/health/ready", get(routes::health::ready))
        // API v1
        .nest("/api/v1", auth_routes)
        .nest("/api/v1", app_routes)
        .nest("/api/v1", finding_routes)
        .nest("/api/v1", ingestion_routes)
        .nest("/api/v1", correlation_routes)
        .nest("/api/v1", dashboard_routes)
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));

    match (&config.tls_cert_path, &config.tls_key_path) {
        (Some(cert), Some(key)) => {
            let cert_path = std::path::PathBuf::from(cert);
            let key_path = std::path::PathBuf::from(key);

            tracing::info!("TLS enabled — loading certificates...");
            tracing::info!(path = %cert_path.display(), "Certificate");
            tracing::info!(path = %key_path.display(), "Private key");

            let tls_config =
                axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to load TLS certificates: {e}"))?;

            tracing::info!(host = %addr, "HTTPS server listening");
            axum_server::bind_rustls(addr, tls_config)
                .serve(app.into_make_service())
                .await?;
        }
        _ => {
            tracing::warn!(host = %addr, "Starting HTTP server (TLS not configured)");
            let listener = tokio::net::TcpListener::bind(addr).await?;
            axum::serve(listener, app).await?;
        }
    }

    Ok(())
}
