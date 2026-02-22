//! SARIF 2.1.0 parser for generic SAST tool integration.
//!
//! Parses the standard Static Analysis Results Interchange Format,
//! enabling any SARIF-compliant tool to integrate without a custom parser.

use serde::Deserialize;

use crate::models::finding::{CreateFinding, FindingCategory, SeverityLevel};
use crate::models::finding_sast::CreateFindingSast;
use crate::parsers::{InputFormat, ParseError, ParseResult, ParsedFinding, Parser};
use crate::services::finding::CategoryData;
use crate::services::fingerprint;

/// SARIF parser instance.
#[derive(Default)]
pub struct SarifParser;

impl SarifParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for SarifParser {
    fn parse(&self, data: &[u8], format: InputFormat) -> Result<ParseResult, anyhow::Error> {
        match format {
            InputFormat::Sarif | InputFormat::Json => self.parse_sarif(data),
            _ => anyhow::bail!("SARIF parser only supports SARIF/JSON format"),
        }
    }

    fn source_tool(&self) -> &str {
        "SARIF"
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Sast
    }

    fn map_severity(&self, level: &str) -> SeverityLevel {
        match level.to_lowercase().as_str() {
            "error" => SeverityLevel::High,
            "warning" => SeverityLevel::Medium,
            "note" => SeverityLevel::Low,
            "none" => SeverityLevel::Info,
            _ => SeverityLevel::Medium,
        }
    }
}

// -- SARIF 2.1.0 schema (subset) --

#[derive(Debug, Deserialize)]
struct SarifDocument {
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Debug, Deserialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Debug, Deserialize)]
struct SarifDriver {
    name: String,
    version: Option<String>,
    #[serde(default)]
    rules: Vec<SarifRule>,
}

#[derive(Debug, Deserialize)]
struct SarifRule {
    id: String,
    name: Option<String>,
    #[serde(rename = "shortDescription")]
    short_description: Option<SarifMessage>,
    #[serde(rename = "fullDescription")]
    full_description: Option<SarifMessage>,
    #[serde(rename = "defaultConfiguration")]
    default_configuration: Option<SarifConfiguration>,
    properties: Option<SarifProperties>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Debug, Deserialize)]
struct SarifConfiguration {
    level: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifProperties {
    tags: Option<Vec<String>>,
    application_code: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: Option<String>,
    #[serde(rename = "ruleIndex")]
    rule_index: Option<usize>,
    level: Option<String>,
    message: SarifMessage,
    #[serde(default)]
    locations: Vec<SarifLocation>,
    properties: Option<SarifProperties>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: Option<SarifPhysicalLocation>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: Option<SarifArtifactLocation>,
    region: Option<SarifRegion>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Debug, Deserialize, serde::Serialize)]
struct SarifRegion {
    #[serde(rename = "startLine")]
    start_line: Option<i32>,
    #[serde(rename = "endLine")]
    end_line: Option<i32>,
    #[serde(rename = "startColumn")]
    start_column: Option<i32>,
}

impl SarifParser {
    fn parse_sarif(&self, data: &[u8]) -> Result<ParseResult, anyhow::Error> {
        let document: SarifDocument = serde_json::from_slice(data)?;
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        for run in &document.runs {
            let tool_name = &run.tool.driver.name;
            let tool_version = run.tool.driver.version.as_deref();

            for (i, result) in run.results.iter().enumerate() {
                match self.convert_result(result, &run.tool.driver.rules, tool_name, tool_version, i)
                {
                    Ok(finding) => findings.push(finding),
                    Err(err) => errors.push(err),
                }
            }
        }

        let source_tool = document
            .runs
            .first()
            .map(|r| r.tool.driver.name.clone())
            .unwrap_or_else(|| "SARIF".to_string());

        let source_version = document
            .runs
            .first()
            .and_then(|r| r.tool.driver.version.clone());

        Ok(ParseResult {
            findings,
            errors,
            source_tool,
            source_tool_version: source_version,
        })
    }

    fn convert_result(
        &self,
        result: &SarifResult,
        rules: &[SarifRule],
        tool_name: &str,
        tool_version: Option<&str>,
        _index: usize,
    ) -> Result<ParsedFinding, ParseError> {
        let rule_id = result.rule_id.clone().unwrap_or_default();

        // Look up rule definition
        let rule = result
            .rule_index
            .and_then(|idx| rules.get(idx))
            .or_else(|| rules.iter().find(|r| r.id == rule_id));

        // Resolve severity: result level > rule default > "warning"
        let level = result
            .level
            .as_deref()
            .or_else(|| {
                rule.and_then(|r| {
                    r.default_configuration
                        .as_ref()
                        .and_then(|c| c.level.as_deref())
                })
            })
            .unwrap_or("warning");

        let normalized_severity = self.map_severity(level);

        // Extract location info
        let (file_path, line_start, line_end) = result
            .locations
            .first()
            .and_then(|loc| loc.physical_location.as_ref())
            .map(|phys| {
                let uri = phys
                    .artifact_location
                    .as_ref()
                    .map(|a| a.uri.clone())
                    .unwrap_or_default();
                let start = phys.region.as_ref().and_then(|r| r.start_line);
                let end = phys.region.as_ref().and_then(|r| r.end_line);
                (uri, start, end)
            })
            .unwrap_or_default();

        // Extract app_code from result properties or rule properties
        let app_code = result
            .properties
            .as_ref()
            .and_then(|p| p.application_code.clone())
            .or_else(|| {
                rule.and_then(|r| {
                    r.properties
                        .as_ref()
                        .and_then(|p| p.application_code.clone())
                })
            })
            .unwrap_or_default();

        // Extract CWE IDs from rule properties tags
        let cwe_ids: Vec<String> = rule
            .and_then(|r| r.properties.as_ref())
            .and_then(|p| p.tags.as_ref())
            .map(|tags| {
                tags.iter()
                    .filter(|t| t.starts_with("CWE-"))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Extract OWASP category from tags
        let owasp_category = rule
            .and_then(|r| r.properties.as_ref())
            .and_then(|p| p.tags.as_ref())
            .and_then(|tags| {
                tags.iter()
                    .find(|t| t.starts_with("OWASP-"))
                    .cloned()
            });

        // Title: rule name > short description > rule_id
        let title = rule
            .and_then(|r| r.name.clone())
            .or_else(|| {
                rule.and_then(|r| r.short_description.as_ref().map(|d| d.text.clone()))
            })
            .unwrap_or_else(|| rule_id.clone());

        // Description: message > full description > short description
        let description = if !result.message.text.is_empty() {
            result.message.text.clone()
        } else {
            rule.and_then(|r| r.full_description.as_ref().map(|d| d.text.clone()))
                .or_else(|| {
                    rule.and_then(|r| r.short_description.as_ref().map(|d| d.text.clone()))
                })
                .unwrap_or_else(|| title.clone())
        };

        // Compute fingerprint
        let fp = fingerprint::compute_sast(&app_code, &file_path, &rule_id, "main");

        // Build source_finding_id from rule_id + file + line
        let source_finding_id = format!(
            "{rule_id}:{file_path}:{}",
            line_start.map(|l| l.to_string()).unwrap_or_default()
        );

        let raw_finding = serde_json::to_value(result)
            .unwrap_or(serde_json::json!({}));

        let core = CreateFinding {
            source_tool: tool_name.to_string(),
            source_tool_version: tool_version.map(|v| v.to_string()),
            source_finding_id,
            finding_category: self.category(),
            title,
            description,
            normalized_severity,
            original_severity: level.to_string(),
            cvss_score: None,
            cvss_vector: None,
            cwe_ids,
            cve_ids: vec![],
            owasp_category,
            confidence: None,
            fingerprint: fp,
            application_id: None,
            tags: vec![],
            remediation_guidance: None,
            raw_finding,
            metadata: serde_json::json!({
                "app_code": app_code,
                "sarif_rule_index": result.rule_index,
            }),
        };

        let sast = CreateFindingSast {
            file_path,
            line_number_start: line_start,
            line_number_end: line_end,
            project: tool_name.to_string(),
            rule_name: rule
                .and_then(|r| r.name.clone())
                .unwrap_or_else(|| rule_id.clone()),
            rule_id,
            issue_type: Some("VULNERABILITY".to_string()),
            branch: Some("main".to_string()),
            source_url: None,
            scanner_creation_date: None,
            baseline_date: None,
            last_analysis_date: None,
            code_snippet: None,
            taint_source: None,
            taint_sink: None,
            language: None,
            framework: None,
            scanner_description: rule
                .and_then(|r| r.full_description.as_ref().map(|d| d.text.clone())),
            scanner_tags: rule
                .and_then(|r| r.properties.as_ref())
                .and_then(|p| p.tags.clone())
                .unwrap_or_default(),
            quality_gate: None,
        };

        Ok(ParsedFinding {
            core,
            category_data: CategoryData::Sast(sast),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sarif_finds_all_results() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        assert_eq!(result.findings.len(), 5);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.source_tool, "SecurityScanner");
        assert_eq!(result.source_tool_version.as_deref(), Some("3.2.1"));
    }

    #[test]
    fn sarif_severity_mapping() {
        let parser = SarifParser::new();
        assert_eq!(parser.map_severity("error"), SeverityLevel::High);
        assert_eq!(parser.map_severity("warning"), SeverityLevel::Medium);
        assert_eq!(parser.map_severity("note"), SeverityLevel::Low);
        assert_eq!(parser.map_severity("none"), SeverityLevel::Info);
    }

    #[test]
    fn extracts_cwe_from_rule_tags() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        let sql_injection = &result.findings[0];
        assert!(sql_injection.core.cwe_ids.contains(&"CWE-89".to_string()));
    }

    #[test]
    fn extracts_owasp_from_rule_tags() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        let sql_injection = &result.findings[0];
        assert_eq!(
            sql_injection.core.owasp_category,
            Some("OWASP-A03".to_string())
        );
    }

    #[test]
    fn extracts_location_info() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        let first = &result.findings[0];
        if let CategoryData::Sast(ref sast) = first.category_data {
            assert_eq!(
                sast.file_path,
                "src/main/java/com/bank/dao/UserDao.java"
            );
            assert_eq!(sast.line_number_start, Some(45));
            assert_eq!(sast.line_number_end, Some(48));
        } else {
            panic!("Expected SAST category data");
        }
    }

    #[test]
    fn extracts_app_code_from_properties() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        assert_eq!(result.findings[0].core.metadata["app_code"], "APP01");
        assert_eq!(result.findings[2].core.metadata["app_code"], "APP02");
    }

    #[test]
    fn fingerprint_computed_for_all() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        for finding in &result.findings {
            assert_eq!(finding.core.fingerprint.len(), 64);
        }
    }

    #[test]
    fn rule_name_used_as_title() {
        let parser = SarifParser::new();
        let data = include_bytes!("../../tests/fixtures/sarif_sample.json");
        let result = parser.parse(data, InputFormat::Sarif).unwrap();
        assert_eq!(result.findings[0].core.title, "SqlInjection");
        assert_eq!(result.findings[1].core.title, "CrossSiteScripting");
    }

    #[test]
    fn rejects_unsupported_format() {
        let parser = SarifParser::new();
        let result = parser.parse(b"", InputFormat::Csv);
        assert!(result.is_err());
    }
}
