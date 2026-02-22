use std::net::SocketAddr;

use mimalloc::MiMalloc;
use synapsec::config::AppConfig;
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

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!(host = %addr, "Starting SynApSec API server");

    let app = axum::Router::new()
        .route("/health/live", axum::routing::get(|| async { "OK" }));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
