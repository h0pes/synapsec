//! Scanner output parsers for normalizing findings from various tools.
//!
//! Each parser implements the `Parser` trait, producing normalized
//! `ParsedFinding` records from tool-specific formats (JSON, CSV, XML, SARIF).

pub mod sonarqube;

use crate::models::finding::{CreateFinding, FindingCategory, SeverityLevel};
use crate::services::finding::CategoryData;

/// A normalized finding ready for ingestion.
#[derive(Debug)]
pub struct ParsedFinding {
    pub core: CreateFinding,
    pub category_data: CategoryData,
}

/// Result of parsing a scanner output file.
#[derive(Debug)]
pub struct ParseResult {
    pub findings: Vec<ParsedFinding>,
    pub errors: Vec<ParseError>,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
}

/// Error encountered while parsing an individual record.
#[derive(Debug)]
pub struct ParseError {
    pub record_index: usize,
    pub field: String,
    pub message: String,
}

/// Input format for scanner data.
#[derive(Debug, Clone, PartialEq)]
pub enum InputFormat {
    Json,
    Csv,
    Xml,
    Sarif,
}

/// Trait for pluggable scanner output parsers.
pub trait Parser: Send + Sync {
    /// Parse raw scanner output into normalized findings.
    fn parse(&self, data: &[u8], format: InputFormat) -> Result<ParseResult, anyhow::Error>;

    /// The scanner tool name this parser handles.
    fn source_tool(&self) -> &str;

    /// The finding category this parser produces.
    fn category(&self) -> FindingCategory;

    /// Map tool-specific severity string to normalized severity level.
    fn map_severity(&self, tool_severity: &str) -> SeverityLevel;
}
