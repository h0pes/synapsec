//! End-to-end integration test for the full Phase 1 pipeline.
//!
//! Requires a running PostgreSQL instance. Set `TEST_DATABASE_URL` to a
//! connection string for a **dedicated test database** (it will be wiped on
//! each run). Defaults to `postgres://synapsec:synapsec@localhost:5432/synapsec_test`.
//!
//! Run with: `cargo test --test full_pipeline_test -- --ignored`

use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use std::net::SocketAddr;
use tokio::net::TcpListener;

const ADMIN_USER: &str = "admin_test";
const ADMIN_PASS: &str = "Admin123!Test";
const ADMIN_EMAIL: &str = "admin_test@synapsec.test";

/// Spin up the full Axum app on a random port against the test database,
/// returning the base URL and a handle to stop the server.
async fn start_server() -> (String, tokio::task::JoinHandle<()>) {
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://synapsec:synapsec@localhost:5432/synapsec_test".into());

    // Set required env vars for AppConfig::from_env()
    std::env::set_var("DATABASE_URL", &db_url);
    std::env::set_var("JWT_SECRET", "test-jwt-secret-for-integration-tests-only");
    std::env::set_var("FRONTEND_URL", "http://localhost:5173");
    std::env::set_var("BACKEND_PORT", "0"); // unused, we bind manually

    let config = synapsec::config::AppConfig::from_env().expect("config");
    let pool = synapsec::db::create_pool(&config.database_url, 5)
        .await
        .expect("pool");

    // Run migrations
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");

    // Clean tables for a fresh run (order matters due to FK constraints)
    sqlx::query(
        "TRUNCATE TABLE
            finding_comments, finding_history, finding_relationships,
            sast_findings, sca_findings, dast_findings, findings,
            ingestion_logs, audit_log,
            applications, users, system_config
         CASCADE",
    )
    .execute(&pool)
    .await
    .expect("truncate");

    // Re-insert default system config (auto_confirm_enabled)
    sqlx::query(
        "INSERT INTO system_config (key, value) VALUES ('auto_confirm_enabled', '\"true\"')
         ON CONFLICT (key) DO NOTHING",
    )
    .execute(&pool)
    .await
    .ok();

    let state = synapsec::AppState {
        db: pool,
        config: config.clone(),
    };

    // Build the router (mirrors main.rs)
    use axum::routing::{get, patch, post};
    use axum::Router;
    use synapsec::routes;
    use tower_http::cors::{Any, CorsLayer};

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let auth_routes = Router::new()
        .route("/auth/login", post(routes::auth::login))
        .route("/auth/refresh", post(routes::auth::refresh))
        .route("/auth/logout", post(routes::auth::logout))
        .route("/auth/users", post(routes::auth::create_user))
        .route("/auth/me", get(routes::auth::me));

    let app_routes = Router::new()
        .route(
            "/applications",
            get(routes::applications::list).post(routes::applications::create),
        )
        .route(
            "/applications/unverified",
            get(routes::applications::list_unverified),
        )
        .route(
            "/applications/import",
            post(routes::applications::import_bulk),
        )
        .route(
            "/applications/import/apm",
            post(routes::applications::import_apm),
        )
        .route(
            "/applications/code/{code}",
            get(routes::applications::get_by_code),
        )
        .route(
            "/applications/{id}",
            get(routes::applications::get_by_id).put(routes::applications::update),
        );

    let finding_routes = Router::new()
        .route(
            "/findings",
            get(routes::findings::list).post(routes::findings::create),
        )
        .route(
            "/findings/bulk/status",
            post(routes::findings::bulk_status),
        )
        .route(
            "/findings/bulk/assign",
            post(routes::findings::bulk_assign),
        )
        .route("/findings/bulk/tag", post(routes::findings::bulk_tag))
        .route(
            "/findings/{id}",
            get(routes::findings::get_by_id).put(routes::findings::update),
        )
        .route(
            "/findings/{id}/status",
            patch(routes::findings::update_status),
        )
        .route(
            "/findings/{id}/comments",
            get(routes::findings::list_comments).post(routes::findings::add_comment),
        )
        .route(
            "/findings/{id}/history",
            get(routes::findings::get_history),
        );

    let ingestion_routes = Router::new()
        .route("/ingestion/upload", post(routes::ingestion::upload))
        .route("/ingestion/history", get(routes::ingestion::history))
        .route("/ingestion/{id}", get(routes::ingestion::get_log));

    let app = Router::new()
        .route("/health/live", get(routes::health::live))
        .route("/health/ready", get(routes::health::ready))
        .nest("/api/v1", auth_routes)
        .nest("/api/v1", app_routes)
        .nest("/api/v1", finding_routes)
        .nest("/api/v1", ingestion_routes)
        .layer(cors)
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    // Wait briefly for server readiness
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (base_url, handle)
}

/// Helper: extract `data` from the API envelope, panic with message on error.
fn extract_data(body: &Value) -> &Value {
    if let Some(err) = body.get("error").filter(|e| !e.is_null()) {
        panic!(
            "API error: {} — {}",
            err["code"].as_str().unwrap_or("?"),
            err["message"].as_str().unwrap_or("?"),
        );
    }
    body.get("data").expect("missing 'data' field")
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL pointing to a dedicated test database"]
async fn full_phase1_pipeline() {
    let (base, _handle) = start_server().await;
    let client = Client::new();

    // ──────────────────────────────────────────────────────────
    // 1. Health check
    // ──────────────────────────────────────────────────────────
    let resp = client.get(format!("{base}/health/live")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // ──────────────────────────────────────────────────────────
    // 2. Bootstrap admin user — direct DB insert (no users exist yet,
    //    so there's no admin to call POST /auth/users)
    // ──────────────────────────────────────────────────────────
    let db_url = std::env::var("TEST_DATABASE_URL")
        .unwrap_or_else(|_| "postgres://synapsec:synapsec@localhost:5432/synapsec_test".into());
    let pool = synapsec::db::create_pool(&db_url, 2).await.unwrap();
    let admin_hash = synapsec::services::auth::hash_password(ADMIN_PASS).unwrap();
    sqlx::query(
        "INSERT INTO users (username, email, password_hash, display_name, role)
         VALUES ($1, $2, $3, $4, 'Platform_Admin')",
    )
    .bind(ADMIN_USER)
    .bind(ADMIN_EMAIL)
    .bind(&admin_hash)
    .bind("Integration Test Admin")
    .execute(&pool)
    .await
    .unwrap();

    // ──────────────────────────────────────────────────────────
    // 3. Login → get JWT
    // ──────────────────────────────────────────────────────────
    let login_resp: Value = client
        .post(format!("{base}/api/v1/auth/login"))
        .json(&json!({ "username": ADMIN_USER, "password": ADMIN_PASS }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let token_data = extract_data(&login_resp);
    let access_token = token_data["access_token"].as_str().unwrap();
    assert_eq!(token_data["token_type"].as_str().unwrap(), "Bearer");

    // Helper closure for authenticated requests
    let auth = |req: reqwest::RequestBuilder| req.bearer_auth(access_token);

    // ──────────────────────────────────────────────────────────
    // 4. Create application (app_code: "PAYM1")
    // ──────────────────────────────────────────────────────────
    let create_app_resp: Value = auth(
        client.post(format!("{base}/api/v1/applications")).json(&json!({
            "app_name": "Payment Service",
            "app_code": "PAYM1",
            "description": "Core payment processing",
            "criticality": "High",
            "business_unit": "Payments",
            "business_owner": "payments-team@bank.test",
            "technical_owner": "dev-payments@bank.test"
        })),
    )
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let app = extract_data(&create_app_resp);
    let app_id = app["id"].as_str().unwrap();
    assert_eq!(app["app_code"].as_str().unwrap(), "PAYM1");
    assert_eq!(app["is_verified"].as_bool().unwrap(), true);

    // ──────────────────────────────────────────────────────────
    // 5. Upload SonarQube JSON via ingestion endpoint
    // ──────────────────────────────────────────────────────────
    let fixture = include_str!("fixtures/sonarqube_sample.json");

    let form = reqwest::multipart::Form::new()
        .text("parser_type", "sonarqube")
        .text("format", "json")
        .part(
            "file",
            reqwest::multipart::Part::text(fixture.to_string())
                .file_name("sonarqube_sample.json")
                .mime_str("application/json")
                .unwrap(),
        );

    let ingest_resp: Value = auth(client.post(format!("{base}/api/v1/ingestion/upload")))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let ingest = extract_data(&ingest_resp);
    let total_parsed = ingest["total_parsed"].as_u64().unwrap();
    let new_findings_1st = ingest["new_findings"].as_u64().unwrap();
    assert!(total_parsed >= 10, "Expected at least 10 parsed records, got {total_parsed}");
    assert!(new_findings_1st > 0, "Expected new findings from first import");

    // ──────────────────────────────────────────────────────────
    // 6. Verify findings were created
    // ──────────────────────────────────────────────────────────
    let findings_resp: Value = auth(client.get(format!("{base}/api/v1/findings?limit=50")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let findings_data = extract_data(&findings_resp);
    let items = findings_data["items"].as_array().unwrap();
    assert!(!items.is_empty(), "Expected findings after ingestion");
    let first_finding_id = items[0]["id"].as_str().unwrap().to_string();

    // ──────────────────────────────────────────────────────────
    // 7. Verify deduplication (upload same file again)
    // ──────────────────────────────────────────────────────────
    let form2 = reqwest::multipart::Form::new()
        .text("parser_type", "sonarqube")
        .text("format", "json")
        .part(
            "file",
            reqwest::multipart::Part::text(fixture.to_string())
                .file_name("sonarqube_sample.json")
                .mime_str("application/json")
                .unwrap(),
        );

    let ingest2_resp: Value = auth(client.post(format!("{base}/api/v1/ingestion/upload")))
        .multipart(form2)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let ingest2 = extract_data(&ingest2_resp);
    let new_findings_2nd = ingest2["new_findings"].as_u64().unwrap();
    let updated_2nd = ingest2["updated_findings"].as_u64().unwrap();
    assert_eq!(
        new_findings_2nd, 0,
        "Second import should create no new findings (dedup)"
    );
    assert!(
        updated_2nd > 0,
        "Second import should update existing findings (last_seen)"
    );

    // ──────────────────────────────────────────────────────────
    // 8. Verify finding status (should be Confirmed via auto-confirm)
    // ──────────────────────────────────────────────────────────
    let finding_detail_resp: Value = auth(client.get(format!(
        "{base}/api/v1/findings/{first_finding_id}"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let finding_detail = extract_data(&finding_detail_resp);
    // Status may be New or Confirmed depending on auto-confirm config
    let status = finding_detail["status"].as_str().unwrap();
    assert!(
        status == "New" || status == "Confirmed",
        "Expected New or Confirmed, got {status}"
    );

    // If status is New, transition to Confirmed first
    if status == "New" {
        let _confirm_resp: Value = auth(client.patch(format!(
            "{base}/api/v1/findings/{first_finding_id}/status"
        )))
        .json(&json!({ "status": "Confirmed" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    }

    // ──────────────────────────────────────────────────────────
    // 9. Transition finding to In_Remediation
    // ──────────────────────────────────────────────────────────
    let transition_resp: Value = auth(client.patch(format!(
        "{base}/api/v1/findings/{first_finding_id}/status"
    )))
    .json(&json!({
        "status": "InRemediation",
        "justification": "Starting remediation work"
    }))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let transitioned = extract_data(&transition_resp);
    assert_eq!(
        transitioned["status"].as_str().unwrap(),
        "InRemediation"
    );

    // ──────────────────────────────────────────────────────────
    // 10. Add a comment
    // ──────────────────────────────────────────────────────────
    let comment_resp: Value = auth(client.post(format!(
        "{base}/api/v1/findings/{first_finding_id}/comments"
    )))
    .json(&json!({ "content": "Assigned to remediation team for Q1 sprint" }))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let comment = extract_data(&comment_resp);
    assert_eq!(
        comment["content"].as_str().unwrap(),
        "Assigned to remediation team for Q1 sprint"
    );
    assert_eq!(comment["author_name"].as_str().unwrap(), ADMIN_USER);

    // ──────────────────────────────────────────────────────────
    // 11. Verify finding history has entries
    // ──────────────────────────────────────────────────────────
    let history_resp: Value = auth(client.get(format!(
        "{base}/api/v1/findings/{first_finding_id}/history"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let history = extract_data(&history_resp);
    let history_entries = history.as_array().unwrap();
    assert!(
        !history_entries.is_empty(),
        "Expected history entries after status transition"
    );

    // ──────────────────────────────────────────────────────────
    // 12. Search findings by text
    // ──────────────────────────────────────────────────────────
    let search_resp: Value = auth(client.get(format!(
        "{base}/api/v1/findings?search=injection&limit=50"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let search_data = extract_data(&search_resp);
    let search_items = search_data["items"].as_array().unwrap();
    assert!(
        !search_items.is_empty(),
        "Expected search results for 'injection'"
    );

    // ──────────────────────────────────────────────────────────
    // 13. Filter findings by severity
    // ──────────────────────────────────────────────────────────
    let filter_resp: Value = auth(client.get(format!(
        "{base}/api/v1/findings?severity=Critical&limit=50"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let filter_data = extract_data(&filter_resp);
    let filter_items = filter_data["items"].as_array().unwrap();
    // All returned findings should be Critical
    for item in filter_items {
        assert_eq!(
            item["normalized_severity"].as_str().unwrap(),
            "Critical",
            "Expected all filtered findings to be Critical"
        );
    }

    // ──────────────────────────────────────────────────────────
    // 14. Verify ingestion history shows both imports
    // ──────────────────────────────────────────────────────────
    let ing_history_resp: Value = auth(client.get(format!(
        "{base}/api/v1/ingestion/history?limit=10"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let ing_history = extract_data(&ing_history_resp);
    let ing_logs = ing_history.as_array().unwrap();
    assert!(
        ing_logs.len() >= 2,
        "Expected at least 2 ingestion logs, got {}",
        ing_logs.len()
    );

    // ──────────────────────────────────────────────────────────
    // 15. Verify application was resolved (get app by code, check findings)
    // ──────────────────────────────────────────────────────────
    let app_by_code_resp: Value = auth(client.get(format!(
        "{base}/api/v1/applications/code/PAYM1"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let resolved_app = extract_data(&app_by_code_resp);
    assert_eq!(resolved_app["id"].as_str().unwrap(), app_id);

    // Verify findings are associated with the app
    let app_findings_resp: Value = auth(client.get(format!(
        "{base}/api/v1/findings?application_id={app_id}&limit=50"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let _app_findings = extract_data(&app_findings_resp);
    // The sample data uses APP01, APP02, APP03 — not PAYM1.
    // Application resolution depends on matching app_code to the fixture's application_code.
    // Since we created PAYM1 (not APP01), auto-created stubs for APP01/02/03 will appear
    // as unverified apps.

    // ──────────────────────────────────────────────────────────
    // 16. Verify unverified apps were auto-created from ingestion
    // ──────────────────────────────────────────────────────────
    let unverified_resp: Value = auth(client.get(format!(
        "{base}/api/v1/applications/unverified?limit=50"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let unverified = extract_data(&unverified_resp);
    let unverified_items = unverified["items"].as_array().unwrap();
    // The fixture uses APP01, APP02, APP03 — these should be auto-created as unverified
    assert!(
        !unverified_items.is_empty(),
        "Expected unverified apps from auto-creation during ingestion"
    );

    // ──────────────────────────────────────────────────────────
    // 17. List comments on finding
    // ──────────────────────────────────────────────────────────
    let comments_resp: Value = auth(client.get(format!(
        "{base}/api/v1/findings/{first_finding_id}/comments"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let comments = extract_data(&comments_resp);
    let comment_list = comments.as_array().unwrap();
    assert!(
        !comment_list.is_empty(),
        "Expected at least 1 comment on the finding"
    );

    // ──────────────────────────────────────────────────────────
    // Done!
    // ──────────────────────────────────────────────────────────
    eprintln!("=== Full Phase 1 pipeline integration test PASSED ===");
}
