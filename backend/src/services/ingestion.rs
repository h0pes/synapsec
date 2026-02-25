//! Ingestion pipeline orchestrating parsing, app resolution, dedup, and finding creation.
//!
//! Accepts scanner output files, selects the appropriate parser, normalizes
//! findings, resolves applications, applies deduplication, creates findings,
//! and logs the ingestion event.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

use crate::errors::AppError;
use crate::parsers::sarif::SarifParser;
use crate::parsers::sonarqube::SonarQubeParser;
use crate::parsers::{InputFormat, Parser};
use crate::services::{app_code_resolver, application, deduplication, finding};

/// Summary of an ingestion run.
#[derive(Debug, Serialize)]
pub struct IngestionResult {
    #[serde(rename = "ingestion_log_id")]
    pub ingestion_id: Uuid,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    pub total_parsed: usize,
    pub new_findings: usize,
    pub updated_findings: usize,
    pub reopened_findings: usize,
    pub duplicates: usize,
    pub quarantined: usize,
    #[serde(rename = "errors")]
    pub error_count: usize,
    pub error_details: Vec<IngestionError>,
}

/// Error during ingestion of a single record.
#[derive(Debug, Serialize)]
pub struct IngestionError {
    pub record_index: usize,
    pub stage: String,
    pub message: String,
}

/// Parameters for an ingestion upload.
#[derive(Debug, Deserialize)]
pub struct IngestionUpload {
    pub parser_type: ParserType,
    pub format: InputFormat,
}

/// Supported parser types.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ParserType {
    Sonarqube,
    Sarif,
    #[serde(rename = "jfrog_xray")]
    JfrogXray,
    #[serde(rename = "tenable_was")]
    TenableWas,
}

impl std::fmt::Display for ParserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sonarqube => write!(f, "sonarqube"),
            Self::Sarif => write!(f, "sarif"),
            Self::JfrogXray => write!(f, "jfrog_xray"),
            Self::TenableWas => write!(f, "tenable_was"),
        }
    }
}

/// Ingestion log entry stored in the database.
///
/// Maps to the `ingestion_logs` table in the initial schema.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct IngestionLog {
    pub id: Uuid,
    pub source_tool: String,
    pub ingestion_type: String,
    pub file_name: Option<String>,
    pub total_records: i32,
    pub new_findings: i32,
    pub updated_findings: i32,
    pub duplicates: i32,
    pub errors: i32,
    pub quarantined: i32,
    pub status: String,
    pub error_details: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub initiated_by: Option<Uuid>,
}

/// Ingestion log summary for history listing.
#[derive(Debug, Clone, Serialize, FromRow)]
pub struct IngestionLogSummary {
    pub id: Uuid,
    pub source_tool: String,
    pub ingestion_type: String,
    pub file_name: Option<String>,
    pub total_records: i32,
    pub new_findings: i32,
    pub updated_findings: i32,
    pub duplicates: i32,
    pub errors: i32,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub initiated_by: Option<Uuid>,
}

/// Run the full ingestion pipeline for an uploaded file.
pub async fn ingest_file(
    pool: &PgPool,
    file_data: &[u8],
    file_name: &str,
    parser_type: &ParserType,
    format: &InputFormat,
    initiated_by: Uuid,
) -> Result<IngestionResult, AppError> {
    // 1. Select parser
    let parser: Box<dyn Parser> = match parser_type {
        ParserType::Sonarqube => Box::new(SonarQubeParser::new()),
        ParserType::Sarif => Box::new(SarifParser::new()),
        ParserType::JfrogXray => Box::new(crate::parsers::jfrog_xray::JfrogXrayParser::new()),
        ParserType::TenableWas => Box::new(crate::parsers::tenable_was::TenableWasParser::new()),
    };

    // 2. Parse raw data
    let parse_result = parser.parse(file_data, format.clone()).map_err(|e| {
        AppError::Validation(format!("Failed to parse file: {e}"))
    })?;

    let mut new_findings = 0usize;
    let mut updated_findings = 0usize;
    let mut reopened_findings = 0usize;
    let mut errors: Vec<IngestionError> = Vec::new();

    // Collect parse errors
    for err in &parse_result.errors {
        errors.push(IngestionError {
            record_index: err.record_index,
            stage: "parse".to_string(),
            message: format!("{}: {}", err.field, err.message),
        });
    }

    let total_parsed = parse_result.findings.len();

    // 3. Process each parsed finding through the pipeline
    for (i, parsed) in parse_result.findings.iter().enumerate() {
        match process_finding(pool, parsed, initiated_by).await {
            Ok(outcome) => match outcome {
                ProcessOutcome::Created => new_findings += 1,
                ProcessOutcome::Deduplicated => updated_findings += 1,
                ProcessOutcome::Reopened => reopened_findings += 1,
            },
            Err(e) => {
                errors.push(IngestionError {
                    record_index: i,
                    stage: "ingest".to_string(),
                    message: e.to_string(),
                });
            }
        }
    }

    // 4. Log ingestion event
    let ingestion_id = log_ingestion(
        pool,
        &IngestionLogInput {
            file_name,
            parser_type,
            source_tool: &parse_result.source_tool,
            total_parsed,
            new_findings,
            updated_findings: updated_findings + reopened_findings,
            duplicates: updated_findings,
            errors: &errors,
            initiated_by,
        },
    )
    .await?;

    let error_count = errors.len();
    let duplicates = updated_findings;

    Ok(IngestionResult {
        ingestion_id,
        source_tool: parse_result.source_tool,
        source_tool_version: parse_result.source_tool_version,
        total_parsed,
        new_findings,
        updated_findings,
        reopened_findings,
        duplicates,
        quarantined: 0,
        error_count,
        error_details: errors,
    })
}

enum ProcessOutcome {
    Created,
    Deduplicated,
    Reopened,
}

/// Extract all string-valued fields from metadata as `(field_name, field_value)` pairs.
///
/// Non-string and null values are skipped. Returns an empty vec for non-object
/// metadata (e.g. `null`, arrays).
fn extract_resolver_fields(metadata: &serde_json::Value) -> Vec<(String, String)> {
    let Some(obj) = metadata.as_object() else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(key, val)| val.as_str().map(|s| (key.clone(), s.to_string())))
        .collect()
}

/// Load active app code patterns for a source tool, ordered by priority descending.
async fn load_patterns(
    pool: &PgPool,
    source_tool: &str,
) -> Result<Vec<app_code_resolver::PatternEntry>, AppError> {
    let rows = sqlx::query_as::<_, (String, String, i32)>(
        r#"
        SELECT field_name, regex_pattern, priority
        FROM app_code_patterns
        WHERE source_tool = $1 AND is_active = true
        ORDER BY priority DESC
        "#,
    )
    .bind(source_tool)
    .fetch_all(pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|(field_name, regex_pattern, priority)| app_code_resolver::PatternEntry {
            field_name,
            regex_pattern,
            priority,
        })
        .collect())
}

/// Process a single parsed finding: resolve app, check dedup, create if new.
async fn process_finding(
    pool: &PgPool,
    parsed: &crate::parsers::ParsedFinding,
    initiated_by: Uuid,
) -> Result<ProcessOutcome, AppError> {
    // a. Resolve application: try explicit app_code first, then pattern resolver
    let explicit_app_code = parsed
        .core
        .metadata
        .get("app_code")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let mut core = parsed.core.clone();

    let resolved_app_code = if !explicit_app_code.is_empty() {
        Some(explicit_app_code)
    } else {
        let patterns = load_patterns(pool, &core.source_tool).await?;
        if patterns.is_empty() {
            None
        } else {
            let fields = extract_resolver_fields(&core.metadata);
            app_code_resolver::resolve(&patterns, &fields)
        }
    };

    if let Some(app_code) = &resolved_app_code {
        let app =
            application::find_or_create_stub(pool, app_code, &core.source_tool).await?;
        core.application_id = Some(app.id);
    }

    // b. Check deduplication by fingerprint
    let dedup_result =
        deduplication::check_and_apply(pool, &core.fingerprint, initiated_by).await?;

    match dedup_result {
        deduplication::DedupResult::New => {
            // c. Create finding
            let _created = finding::create(pool, &core, &parsed.category_data).await?;
            Ok(ProcessOutcome::Created)
        }
        deduplication::DedupResult::Updated(_) => Ok(ProcessOutcome::Deduplicated),
        deduplication::DedupResult::Reopened(_) => Ok(ProcessOutcome::Reopened),
    }
}

/// Data needed to insert an ingestion log entry.
struct IngestionLogInput<'a> {
    file_name: &'a str,
    parser_type: &'a ParserType,
    source_tool: &'a str,
    total_parsed: usize,
    new_findings: usize,
    updated_findings: usize,
    duplicates: usize,
    errors: &'a [IngestionError],
    initiated_by: Uuid,
}

/// Insert an ingestion log entry matching the `ingestion_logs` table schema.
async fn log_ingestion(pool: &PgPool, input: &IngestionLogInput<'_>) -> Result<Uuid, AppError> {
    let errors_json = serde_json::to_value(input.errors).unwrap_or_default();

    let row = sqlx::query_scalar::<_, Uuid>(
        r#"
        INSERT INTO ingestion_logs (
            source_tool, ingestion_type, file_name,
            total_records, new_findings, updated_findings, duplicates,
            errors, quarantined, status, error_details,
            started_at, completed_at, initiated_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 'Completed', $9, NOW(), NOW(), $10)
        RETURNING id
        "#,
    )
    .bind(input.source_tool)
    .bind(input.parser_type.to_string())
    .bind(input.file_name)
    .bind(input.total_parsed as i32)
    .bind(input.new_findings as i32)
    .bind(input.updated_findings as i32)
    .bind(input.duplicates as i32)
    .bind(input.errors.len() as i32)
    .bind(&errors_json)
    .bind(input.initiated_by)
    .fetch_one(pool)
    .await?;

    Ok(row)
}

/// Count total ingestion log entries.
pub async fn count_history(pool: &PgPool) -> Result<i64, AppError> {
    let count = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM ingestion_logs")
        .fetch_one(pool)
        .await?;
    Ok(count)
}

/// Get ingestion history with pagination.
pub async fn list_history(
    pool: &PgPool,
    limit: i64,
    offset: i64,
) -> Result<Vec<IngestionLogSummary>, AppError> {
    let logs = sqlx::query_as::<_, IngestionLogSummary>(
        r#"
        SELECT id, source_tool, ingestion_type, file_name,
               total_records, new_findings, updated_findings, duplicates,
               errors, status, started_at, completed_at, initiated_by
        FROM ingestion_logs
        ORDER BY started_at DESC
        LIMIT $1 OFFSET $2
        "#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    Ok(logs)
}

/// Get full ingestion log details by ID.
pub async fn get_log(pool: &PgPool, id: Uuid) -> Result<IngestionLog, AppError> {
    let log = sqlx::query_as::<_, IngestionLog>(
        "SELECT * FROM ingestion_logs WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| AppError::NotFound("Ingestion log not found".to_string()))?;
    Ok(log)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_type_display() {
        assert_eq!(ParserType::Sonarqube.to_string(), "sonarqube");
        assert_eq!(ParserType::Sarif.to_string(), "sarif");
    }

    #[test]
    fn parser_type_deserialization() {
        let sq: ParserType = serde_json::from_str("\"sonarqube\"").unwrap();
        assert_eq!(sq, ParserType::Sonarqube);

        let sarif: ParserType = serde_json::from_str("\"sarif\"").unwrap();
        assert_eq!(sarif, ParserType::Sarif);
    }

    #[test]
    fn parser_type_jfrog_xray() {
        let pt: ParserType = serde_json::from_str("\"jfrog_xray\"").unwrap();
        assert_eq!(pt, ParserType::JfrogXray);
        assert_eq!(pt.to_string(), "jfrog_xray");
    }

    #[test]
    fn parser_type_tenable_was() {
        let pt: ParserType = serde_json::from_str("\"tenable_was\"").unwrap();
        assert_eq!(pt, ParserType::TenableWas);
        assert_eq!(pt.to_string(), "tenable_was");
    }

    #[test]
    fn ingestion_error_serialization() {
        let err = IngestionError {
            record_index: 5,
            stage: "parse".to_string(),
            message: "Invalid field".to_string(),
        };
        let json = serde_json::to_value(&err).unwrap();
        assert_eq!(json["record_index"], 5);
        assert_eq!(json["stage"], "parse");
        assert_eq!(json["message"], "Invalid field");
    }

    #[test]
    fn ingestion_result_serialization() {
        let result = IngestionResult {
            ingestion_id: Uuid::nil(),
            source_tool: "SonarQube".to_string(),
            source_tool_version: Some("10.0".to_string()),
            total_parsed: 10,
            new_findings: 7,
            updated_findings: 2,
            reopened_findings: 1,
            duplicates: 3,
            quarantined: 0,
            error_count: 0,
            error_details: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["ingestion_log_id"], Uuid::nil().to_string());
        assert_eq!(json["total_parsed"], 10);
        assert_eq!(json["new_findings"], 7);
        assert_eq!(json["updated_findings"], 2);
        assert_eq!(json["reopened_findings"], 1);
        assert_eq!(json["duplicates"], 3);
        assert_eq!(json["quarantined"], 0);
        assert_eq!(json["errors"], 0);
    }

    #[test]
    fn resolver_fields_extracted_from_xray_metadata() {
        let metadata = serde_json::json!({
            "impacted_artifact": "gav://com.ourcompany.gpe30:set-ear:0.0.1",
            "path": "prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear",
            "component_physical_path": "default/prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear"
        });
        let fields = extract_resolver_fields(&metadata);
        assert_eq!(fields.len(), 3);

        let field_map: std::collections::HashMap<_, _> =
            fields.into_iter().collect();
        assert_eq!(
            field_map["impacted_artifact"],
            "gav://com.ourcompany.gpe30:set-ear:0.0.1"
        );
        assert_eq!(
            field_map["path"],
            "prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear"
        );
        assert_eq!(
            field_map["component_physical_path"],
            "default/prod-release-local/gpe30/gpe30-set/v1.2.0-rc1/set-ear.ear"
        );
    }

    #[test]
    fn resolver_fields_extracted_from_dast_metadata() {
        let metadata = serde_json::json!({
            "dns_name": "sacronym.environment.env.domain.com",
            "url": "https://sacronym.environment.env.domain.com/path",
            "ip_address": "10.0.0.1",
            "port": "443",
            "first_discovered": null,
            "last_observed": null
        });
        let fields = extract_resolver_fields(&metadata);

        // Only string values are extracted; null values are skipped
        let field_map: std::collections::HashMap<_, _> =
            fields.into_iter().collect();
        assert_eq!(
            field_map["dns_name"],
            "sacronym.environment.env.domain.com"
        );
        assert_eq!(
            field_map["url"],
            "https://sacronym.environment.env.domain.com/path"
        );
        assert_eq!(field_map["ip_address"], "10.0.0.1");
        assert_eq!(field_map["port"], "443");
        // Null fields should not be present
        assert!(!field_map.contains_key("first_discovered"));
        assert!(!field_map.contains_key("last_observed"));
    }

    #[test]
    fn resolver_fields_handles_empty_metadata() {
        let metadata = serde_json::json!({});
        let fields = extract_resolver_fields(&metadata);
        assert!(fields.is_empty());
    }
}
