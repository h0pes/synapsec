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
use crate::services::{application, deduplication, finding};

/// Summary of an ingestion run.
#[derive(Debug, Serialize)]
pub struct IngestionResult {
    pub ingestion_id: Uuid,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    pub total_parsed: usize,
    pub new_findings: usize,
    pub updated_findings: usize,
    pub reopened_findings: usize,
    pub errors: Vec<IngestionError>,
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
}

impl std::fmt::Display for ParserType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sonarqube => write!(f, "sonarqube"),
            Self::Sarif => write!(f, "sarif"),
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

    Ok(IngestionResult {
        ingestion_id,
        source_tool: parse_result.source_tool,
        source_tool_version: parse_result.source_tool_version,
        total_parsed,
        new_findings,
        updated_findings,
        reopened_findings,
        errors,
    })
}

enum ProcessOutcome {
    Created,
    Deduplicated,
    Reopened,
}

/// Process a single parsed finding: resolve app, check dedup, create if new.
async fn process_finding(
    pool: &PgPool,
    parsed: &crate::parsers::ParsedFinding,
    initiated_by: Uuid,
) -> Result<ProcessOutcome, AppError> {
    // a. Resolve application from app_code in metadata
    let app_code = parsed
        .core
        .metadata
        .get("app_code")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let mut core = parsed.core.clone();

    if !app_code.is_empty() {
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
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0, 'completed', $9, NOW(), NOW(), $10)
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
            errors: vec![],
        };
        let json = serde_json::to_value(&result).unwrap();
        assert_eq!(json["total_parsed"], 10);
        assert_eq!(json["new_findings"], 7);
        assert_eq!(json["updated_findings"], 2);
        assert_eq!(json["reopened_findings"], 1);
    }
}
