//! JFrog Xray SCA vulnerability parser.

use crate::models::finding::{FindingCategory, SeverityLevel};
use crate::parsers::{InputFormat, ParseResult, Parser};

/// Parser for JFrog Xray JSON export format.
#[derive(Debug)]
pub struct JfrogXrayParser;

impl JfrogXrayParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for JfrogXrayParser {
    fn parse(&self, _data: &[u8], _format: InputFormat) -> Result<ParseResult, anyhow::Error> {
        Ok(ParseResult {
            findings: vec![],
            errors: vec![],
            source_tool: self.source_tool().to_string(),
            source_tool_version: None,
        })
    }

    fn source_tool(&self) -> &str {
        "JFrog Xray"
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Sca
    }

    fn map_severity(&self, tool_severity: &str) -> SeverityLevel {
        match tool_severity {
            "Critical" => SeverityLevel::Critical,
            "High" => SeverityLevel::High,
            "Medium" => SeverityLevel::Medium,
            "Low" => SeverityLevel::Low,
            _ => SeverityLevel::Info,
        }
    }
}
