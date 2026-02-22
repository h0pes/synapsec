//! SAST-specific finding layer model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingSast {
    pub finding_id: Uuid,
    pub file_path: String,
    pub line_number_start: Option<i32>,
    pub line_number_end: Option<i32>,
    pub project: String,
    pub rule_name: String,
    pub rule_id: String,
    pub issue_type: Option<String>,
    pub branch: Option<String>,
    pub source_url: Option<String>,
    pub scanner_creation_date: Option<DateTime<Utc>>,
    pub baseline_date: Option<DateTime<Utc>>,
    pub last_analysis_date: Option<DateTime<Utc>>,
    pub code_snippet: Option<String>,
    pub taint_source: Option<String>,
    pub taint_sink: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub scanner_description: Option<String>,
    pub scanner_tags: serde_json::Value,
    pub quality_gate: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFindingSast {
    pub file_path: String,
    pub line_number_start: Option<i32>,
    pub line_number_end: Option<i32>,
    pub project: String,
    pub rule_name: String,
    pub rule_id: String,
    pub issue_type: Option<String>,
    pub branch: Option<String>,
    pub source_url: Option<String>,
    pub scanner_creation_date: Option<DateTime<Utc>>,
    pub baseline_date: Option<DateTime<Utc>>,
    pub last_analysis_date: Option<DateTime<Utc>>,
    pub code_snippet: Option<String>,
    pub taint_source: Option<String>,
    pub taint_sink: Option<String>,
    pub language: Option<String>,
    pub framework: Option<String>,
    pub scanner_description: Option<String>,
    pub scanner_tags: Vec<String>,
    pub quality_gate: Option<String>,
}
