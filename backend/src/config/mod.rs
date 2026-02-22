use std::env;

/// Application configuration loaded from environment variables.
#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub database_max_connections: u32,
    pub redis_url: String,
    pub host: String,
    pub port: u16,
    pub jwt_secret: String,
    pub jwt_access_token_expiry_secs: i64,
    pub jwt_refresh_token_expiry_secs: i64,
    pub frontend_url: String,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, env::VarError> {
        Ok(Self {
            database_url: env::var("DATABASE_URL")?,
            database_max_connections: env::var("DATABASE_MAX_CONNECTIONS")
                .unwrap_or_else(|_| "10".to_string())
                .parse()
                .unwrap_or(10),
            redis_url: env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            host: env::var("BACKEND_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("BACKEND_PORT")
                .unwrap_or_else(|_| "3000".to_string())
                .parse()
                .unwrap_or(3000),
            jwt_secret: env::var("JWT_SECRET")?,
            jwt_access_token_expiry_secs: env::var("JWT_ACCESS_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "900".to_string())
                .parse()
                .unwrap_or(900),
            jwt_refresh_token_expiry_secs: env::var("JWT_REFRESH_TOKEN_EXPIRY_SECS")
                .unwrap_or_else(|_| "604800".to_string())
                .parse()
                .unwrap_or(604800),
            frontend_url: env::var("FRONTEND_URL")
                .unwrap_or_else(|_| "https://localhost:5173".to_string()),
        })
    }
}
