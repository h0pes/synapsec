//! Seed script for development — populates a fresh database with sample data.
//!
//! Usage: `cargo run --bin seed`
//!
//! Requires `DATABASE_URL` and `JWT_SECRET` environment variables (reads .env).

use sqlx::PgPool;

const ADMIN_PASSWORD: &str = "Test123!";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await?;

    // Run migrations first
    sqlx::migrate!("./migrations").run(&pool).await?;

    println!("=== SynApSec Seed Script ===");

    seed_admin_user(&pool).await?;
    seed_applications(&pool).await?;
    seed_system_config(&pool).await?;
    seed_sample_findings(&pool).await?;
    seed_sca_findings(&pool).await?;
    seed_dast_findings(&pool).await?;

    println!("\n=== Seed complete! ===");
    println!("Admin login: admin / {ADMIN_PASSWORD}");

    Ok(())
}

async fn seed_admin_user(pool: &PgPool) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = 'admin')")
        .fetch_one(pool)
        .await?;

    let hash = synapsec::services::auth::hash_password(ADMIN_PASSWORD)?;

    if exists {
        // Update password for existing admin user
        sqlx::query("UPDATE users SET password_hash = $1 WHERE username = 'admin'")
            .bind(&hash)
            .execute(pool)
            .await?;
        println!("[done] Updated admin password");
        return Ok(());
    }

    sqlx::query(
        "INSERT INTO users (username, email, password_hash, display_name, role)
         VALUES ('admin', 'admin@synapsec.local', $1, 'Platform Administrator', 'Platform_Admin')",
    )
    .bind(&hash)
    .execute(pool)
    .await?;

    // Also create an analyst user for testing
    let analyst_hash = synapsec::services::auth::hash_password("analyst123")?;
    sqlx::query(
        "INSERT INTO users (username, email, password_hash, display_name, role)
         VALUES ('analyst', 'analyst@synapsec.local', $1, 'AppSec Analyst', 'AppSec_Analyst')",
    )
    .bind(&analyst_hash)
    .execute(pool)
    .await?;

    println!("[done] Created admin and analyst users");
    Ok(())
}

async fn seed_applications(pool: &PgPool) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM applications")
        .fetch_one(pool)
        .await?;

    if count > 0 {
        println!("[skip] Applications already exist ({count})");
        return Ok(());
    }

    let apps = vec![
        ("PAYM1", "Payment Service", "Very_High", "Payments", "Internet_Facing", "Restricted"),
        ("USRP1", "User Portal", "High", "Digital Banking", "Internet_Facing", "Confidential"),
        ("MOBK1", "Mobile Backend", "High", "Mobile", "Internet_Facing", "Confidential"),
        ("INTG1", "Integration Gateway", "Medium_High", "Integration", "Internal", "Internal"),
        ("RPTG1", "Reporting Engine", "Medium", "Operations", "Internal", "Internal"),
    ];

    for (code, name, criticality, bu, exposure, data_class) in apps {
        sqlx::query(
            "INSERT INTO applications (app_name, app_code, description, criticality, business_unit,
             exposure, data_classification, is_verified)
             VALUES ($1, $2, $3, $4::asset_criticality, $5, $6::exposure_level, $7::data_classification, true)",
        )
        .bind(name)
        .bind(code)
        .bind(format!("{name} — core banking application"))
        .bind(criticality)
        .bind(bu)
        .bind(exposure)
        .bind(data_class)
        .execute(pool)
        .await?;
    }

    println!("[done] Created 5 sample applications");
    Ok(())
}

async fn seed_system_config(pool: &PgPool) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO system_config (key, value) VALUES ('auto_confirm_enabled', '\"true\"')
         ON CONFLICT (key) DO NOTHING",
    )
    .execute(pool)
    .await?;

    println!("[done] System config set (auto_confirm_enabled=true)");
    Ok(())
}

async fn seed_sample_findings(pool: &PgPool) -> anyhow::Result<()> {
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM findings")
        .fetch_one(pool)
        .await?;

    if count > 0 {
        println!("[skip] Findings already exist ({count})");
        return Ok(());
    }

    // Read the fixture file and ingest via the pipeline
    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/sonarqube_sample.json");

    if !fixture_path.exists() {
        println!("[skip] Fixture file not found at {}", fixture_path.display());
        return Ok(());
    }

    let data = std::fs::read(&fixture_path)?;

    // Get admin user ID for initiated_by
    let admin_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = 'admin'")
            .fetch_optional(pool)
            .await?;

    let result = synapsec::services::ingestion::ingest_file(
        pool,
        &data,
        "sonarqube_sample.json",
        &synapsec::services::ingestion::ParserType::Sonarqube,
        &synapsec::parsers::InputFormat::Json,
        admin_id.unwrap_or_default(),
    )
    .await?;

    println!(
        "[done] Ingested SonarQube sample: {} parsed, {} new, {} updated",
        result.total_parsed, result.new_findings, result.updated_findings
    );

    Ok(())
}

async fn seed_sca_findings(pool: &PgPool) -> anyhow::Result<()> {
    let already_seeded: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ingestion_logs WHERE source_tool = $1)",
    )
    .bind("JFrog Xray")
    .fetch_one(pool)
    .await?;

    if already_seeded {
        println!("[skip] SCA findings already seeded");
        return Ok(());
    }

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/jfrog_xray_seed.json");

    if !fixture_path.exists() {
        println!(
            "[skip] SCA fixture file not found at {}",
            fixture_path.display()
        );
        return Ok(());
    }

    let data = std::fs::read(&fixture_path)?;

    let admin_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = 'admin'")
            .fetch_optional(pool)
            .await?;

    let result = synapsec::services::ingestion::ingest_file(
        pool,
        &data,
        "jfrog_xray_seed.json",
        &synapsec::services::ingestion::ParserType::JfrogXray,
        &synapsec::parsers::InputFormat::Json,
        admin_id.unwrap_or_default(),
    )
    .await?;

    println!(
        "[done] Ingested JFrog Xray sample: {} parsed, {} new, {} updated",
        result.total_parsed, result.new_findings, result.updated_findings
    );

    Ok(())
}

async fn seed_dast_findings(pool: &PgPool) -> anyhow::Result<()> {
    let already_seeded: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ingestion_logs WHERE source_tool = $1)",
    )
    .bind("Tenable WAS")
    .fetch_one(pool)
    .await?;

    if already_seeded {
        println!("[skip] DAST findings already seeded");
        return Ok(());
    }

    let fixture_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/tenable_was_seed.csv");

    if !fixture_path.exists() {
        println!(
            "[skip] DAST fixture file not found at {}",
            fixture_path.display()
        );
        return Ok(());
    }

    let data = std::fs::read(&fixture_path)?;

    let admin_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = 'admin'")
            .fetch_optional(pool)
            .await?;

    let result = synapsec::services::ingestion::ingest_file(
        pool,
        &data,
        "tenable_was_seed.csv",
        &synapsec::services::ingestion::ParserType::TenableWas,
        &synapsec::parsers::InputFormat::Csv,
        admin_id.unwrap_or_default(),
    )
    .await?;

    println!(
        "[done] Ingested Tenable WAS sample: {} parsed, {} new, {} updated",
        result.total_parsed, result.new_findings, result.updated_findings
    );

    Ok(())
}
