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
    seed_correlation_findings(&pool).await?;

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

/// Ingest correlation-ready fixtures (SAST, SCA, DAST) for PAYM1 and run correlation.
///
/// These fixtures share CVE/CWE identifiers across scanner types so the
/// correlation engine can build cross-tool relationships for the attack
/// chain graph visualization.
async fn seed_correlation_findings(pool: &PgPool) -> anyhow::Result<()> {
    // Idempotency: skip if already ingested
    let already_seeded: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ingestion_logs WHERE file_name = $1)",
    )
    .bind("correlation_sast_seed.csv")
    .fetch_one(pool)
    .await?;

    if already_seeded {
        println!("[skip] Correlation fixtures already seeded");
        return Ok(());
    }

    // Ensure lowercase app_code_patterns exist for Tenable WAS metadata keys.
    // The parser stores metadata with lowercase keys (dns_name, url) but the
    // default patterns use display-style names (DNS Name, URL). Insert
    // lowercase variants so the resolver can match DAST findings.
    seed_lowercase_dast_patterns(pool).await?;

    // Admin must exist — seeded by seed_admin_user() which runs first.
    let admin_id: uuid::Uuid = sqlx::query_scalar("SELECT id FROM users WHERE username = 'admin'")
        .fetch_optional(pool)
        .await?
        .unwrap_or_default();

    let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

    // --- SAST correlation fixture (SonarQube CSV) ---
    let sast_path = fixtures_dir.join("correlation_sast_seed.csv");
    let sast_data = std::fs::read(&sast_path)?;
    let sast_result = synapsec::services::ingestion::ingest_file(
        pool,
        &sast_data,
        "correlation_sast_seed.csv",
        &synapsec::services::ingestion::ParserType::Sonarqube,
        &synapsec::parsers::InputFormat::Csv,
        admin_id,
    )
    .await?;
    println!(
        "[done] Correlation SAST: {} parsed, {} new, {} errors",
        sast_result.total_parsed, sast_result.new_findings, sast_result.error_count
    );

    // --- SCA correlation fixture (JFrog Xray JSON) ---
    let sca_path = fixtures_dir.join("correlation_sca_seed.json");
    let sca_data = std::fs::read(&sca_path)?;
    let sca_result = synapsec::services::ingestion::ingest_file(
        pool,
        &sca_data,
        "correlation_sca_seed.json",
        &synapsec::services::ingestion::ParserType::JfrogXray,
        &synapsec::parsers::InputFormat::Json,
        admin_id,
    )
    .await?;
    println!(
        "[done] Correlation SCA: {} parsed, {} new, {} errors",
        sca_result.total_parsed, sca_result.new_findings, sca_result.error_count
    );

    // --- DAST correlation fixture (Tenable WAS CSV) ---
    let dast_path = fixtures_dir.join("correlation_dast_seed.csv");
    let dast_data = std::fs::read(&dast_path)?;
    let dast_result = synapsec::services::ingestion::ingest_file(
        pool,
        &dast_data,
        "correlation_dast_seed.csv",
        &synapsec::services::ingestion::ParserType::TenableWas,
        &synapsec::parsers::InputFormat::Csv,
        admin_id,
    )
    .await?;
    println!(
        "[done] Correlation DAST: {} parsed, {} new, {} errors",
        dast_result.total_parsed, dast_result.new_findings, dast_result.error_count
    );

    // --- Run correlation engine for PAYM1 ---
    let paym1_id: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM applications WHERE app_code = 'PAYM1'")
            .fetch_optional(pool)
            .await?;

    if let Some(app_id) = paym1_id {
        let corr_result =
            synapsec::services::correlation_service::run_for_application(pool, app_id, admin_id)
                .await?;
        println!(
            "[done] Correlation engine: {} findings analyzed, {} new relationships",
            corr_result.total_findings_analyzed, corr_result.new_relationships
        );
    } else {
        println!("[warn] PAYM1 application not found — skipping correlation");
    }

    Ok(())
}

/// Insert lowercase app_code_patterns for Tenable WAS metadata keys.
///
/// The Tenable WAS parser stores metadata with lowercase underscore keys
/// (`dns_name`, `url`) but the default seed patterns from the migration
/// use display-style field names (`DNS Name`, `URL`). This adds matching
/// lowercase patterns so the app code resolver works for DAST findings.
async fn seed_lowercase_dast_patterns(pool: &PgPool) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM app_code_patterns WHERE source_tool = 'Tenable WAS' AND field_name = 'dns_name')",
    )
    .fetch_one(pool)
    .await?;

    if exists {
        return Ok(());
    }

    sqlx::query(
        r#"INSERT INTO app_code_patterns (source_tool, field_name, regex_pattern, priority, description) VALUES
           ('Tenable WAS', 'dns_name', '^[st](?P<app_code>[^.]+)\.', 10, 'Strip s/t env prefix from metadata dns_name'),
           ('Tenable WAS', 'dns_name', '^(?P<app_code>[^.]+)\.', 5, 'Full first subdomain from metadata dns_name (fallback)'),
           ('Tenable WAS', 'url', 'https?://[st](?P<app_code>[^.]+)\.', 10, 'Strip s/t env prefix from metadata url'),
           ('Tenable WAS', 'url', 'https?://(?P<app_code>[^.]+)\.', 5, 'Full subdomain from metadata url (fallback)')"#,
    )
    .execute(pool)
    .await?;

    println!("[done] Added lowercase app_code_patterns for Tenable WAS");
    Ok(())
}
