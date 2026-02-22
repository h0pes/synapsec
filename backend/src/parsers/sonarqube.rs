//! SonarQube scanner output parser supporting JSON and CSV formats.
//!
//! Maps SonarQube issue fields to the normalized SAST finding model,
//! extracts application codes, computes fingerprints, and preserves
//! raw finding data for audit purposes.

use serde::Deserialize;

use crate::models::finding::{CreateFinding, FindingCategory, SeverityLevel};
use crate::models::finding_sast::CreateFindingSast;
use crate::parsers::{InputFormat, ParseError, ParseResult, ParsedFinding, Parser};
use crate::services::finding::CategoryData;
use crate::services::fingerprint;

/// SonarQube parser instance.
#[derive(Default)]
pub struct SonarQubeParser;

impl SonarQubeParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for SonarQubeParser {
    fn parse(&self, data: &[u8], format: InputFormat) -> Result<ParseResult, anyhow::Error> {
        match format {
            InputFormat::Json => self.parse_json(data),
            InputFormat::Csv => self.parse_csv(data),
            _ => anyhow::bail!("SonarQube parser only supports JSON and CSV formats"),
        }
    }

    fn source_tool(&self) -> &str {
        "SonarQube"
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Sast
    }

    fn map_severity(&self, tool_severity: &str) -> SeverityLevel {
        match tool_severity.to_uppercase().as_str() {
            "BLOCKER" => SeverityLevel::Critical,
            "CRITICAL" => SeverityLevel::High,
            "MAJOR" => SeverityLevel::Medium,
            "MINOR" => SeverityLevel::Low,
            "INFO" => SeverityLevel::Info,
            _ => SeverityLevel::Medium,
        }
    }
}

/// Deserialized SonarQube issue from JSON/CSV.
#[derive(Debug, Deserialize)]
struct SonarQubeIssue {
    application_code: Option<String>,
    project_key: Option<String>,
    rule_key: Option<String>,
    issue_id: Option<String>,
    rule_name: Option<String>,
    tag: Option<String>,
    issue_description: Option<String>,
    severity: Option<String>,
    issue_type: Option<String>,
    loc: Option<String>,
    component: Option<String>,
    branch: Option<String>,
    url: Option<String>,
    creation_date: Option<String>,
    quality_gate: Option<String>,
    baseline_date: Option<String>,
    last_analysis: Option<String>,
    extraction_date: Option<String>,
    rule_type: Option<String>,
}

impl SonarQubeParser {
    fn parse_json(&self, data: &[u8]) -> Result<ParseResult, anyhow::Error> {
        let issues: Vec<SonarQubeIssue> = serde_json::from_slice(data)?;
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        for (i, issue) in issues.into_iter().enumerate() {
            match self.convert_issue(issue, i) {
                Ok(finding) => findings.push(finding),
                Err(err) => errors.push(err),
            }
        }

        Ok(ParseResult {
            findings,
            errors,
            source_tool: self.source_tool().to_string(),
            source_tool_version: None,
        })
    }

    fn parse_csv(&self, data: &[u8]) -> Result<ParseResult, anyhow::Error> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(data);

        let mut findings = Vec::new();
        let mut errors = Vec::new();

        for (i, result) in reader.deserialize::<SonarQubeIssue>().enumerate() {
            match result {
                Ok(issue) => match self.convert_issue(issue, i) {
                    Ok(finding) => findings.push(finding),
                    Err(err) => errors.push(err),
                },
                Err(e) => errors.push(ParseError {
                    record_index: i,
                    field: "csv_row".to_string(),
                    message: format!("CSV parse error: {e}"),
                }),
            }
        }

        Ok(ParseResult {
            findings,
            errors,
            source_tool: self.source_tool().to_string(),
            source_tool_version: None,
        })
    }

    fn convert_issue(
        &self,
        issue: SonarQubeIssue,
        index: usize,
    ) -> Result<ParsedFinding, ParseError> {
        let app_code = issue.application_code.clone().unwrap_or_default();
        let component = issue.component.clone().unwrap_or_default();
        let rule_key = issue.rule_key.clone().unwrap_or_default();
        let branch = issue.branch.clone().unwrap_or_else(|| "main".to_string());
        let severity_str = issue.severity.clone().unwrap_or_else(|| "MAJOR".to_string());
        let issue_id = issue.issue_id.clone().unwrap_or_default();

        if issue_id.is_empty() {
            return Err(ParseError {
                record_index: index,
                field: "issue_id".to_string(),
                message: "Missing issue_id".to_string(),
            });
        }

        let normalized_severity = self.map_severity(&severity_str);

        // Extract CWE IDs from tags
        let cwe_ids: Vec<String> = issue
            .tag
            .as_deref()
            .unwrap_or("")
            .split(',')
            .filter(|t| t.starts_with("cwe-"))
            .map(|t| format!("CWE-{}", t.trim_start_matches("cwe-")))
            .collect();

        // Extract OWASP category from tags
        let owasp_category = issue
            .tag
            .as_deref()
            .unwrap_or("")
            .split(',')
            .find(|t| t.starts_with("owasp-"))
            .map(|t| t.to_uppercase().replace("owasp-", "OWASP-"));

        // Compute fingerprint
        let fingerprint = fingerprint::compute_sast(&app_code, &component, &rule_key, &branch);

        // Parse line number
        let line_number_start = issue
            .loc
            .as_deref()
            .and_then(|l| l.parse::<i32>().ok());

        // Parse dates
        let scanner_creation_date = issue
            .creation_date
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_str(d, "%Y-%m-%dT%H:%M:%S%z").ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let baseline_date = issue
            .baseline_date
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_str(d, "%Y-%m-%dT%H:%M:%S%z").ok())
            .map(|d| d.with_timezone(&chrono::Utc));
        let last_analysis_date = issue
            .last_analysis
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_str(d, "%Y-%m-%dT%H:%M:%S%z").ok())
            .map(|d| d.with_timezone(&chrono::Utc));

        // Parse scanner tags
        let scanner_tags: Vec<String> = issue
            .tag
            .as_deref()
            .unwrap_or("")
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();

        // Build raw finding JSON for audit trail
        let raw_finding = serde_json::json!({
            "application_code": issue.application_code,
            "project_key": issue.project_key,
            "rule_key": issue.rule_key,
            "issue_id": issue.issue_id,
            "rule_name": issue.rule_name,
            "tag": issue.tag,
            "issue_description": issue.issue_description,
            "severity": issue.severity,
            "issue_type": issue.issue_type,
            "loc": issue.loc,
            "component": issue.component,
            "branch": issue.branch,
            "url": issue.url,
            "creation_date": issue.creation_date,
            "quality_gate": issue.quality_gate,
            "baseline_date": issue.baseline_date,
            "last_analysis": issue.last_analysis,
            "extraction_date": issue.extraction_date,
            "rule_type": issue.rule_type,
        });

        let title = issue
            .rule_name
            .clone()
            .unwrap_or_else(|| rule_key.clone());
        let description = issue
            .issue_description
            .clone()
            .unwrap_or_else(|| title.clone());

        let project = issue
            .project_key
            .clone()
            .unwrap_or_default();

        let core = CreateFinding {
            source_tool: self.source_tool().to_string(),
            source_tool_version: None,
            source_finding_id: issue_id,
            finding_category: self.category(),
            title,
            description,
            normalized_severity,
            original_severity: severity_str,
            cvss_score: None,
            cvss_vector: None,
            cwe_ids,
            cve_ids: vec![],
            owasp_category,
            confidence: None,
            fingerprint,
            application_id: None, // Resolved during ingestion
            tags: scanner_tags.clone(),
            remediation_guidance: None,
            raw_finding,
            metadata: serde_json::json!({
                "app_code": app_code,
                "project_key": project,
            }),
        };

        let sast = CreateFindingSast {
            file_path: component,
            line_number_start,
            line_number_end: None,
            project,
            rule_name: issue.rule_name.unwrap_or_default(),
            rule_id: rule_key,
            issue_type: issue.issue_type,
            branch: Some(branch),
            source_url: issue.url,
            scanner_creation_date,
            baseline_date,
            last_analysis_date,
            code_snippet: None,
            taint_source: None,
            taint_sink: None,
            language: Some("java".to_string()),
            framework: None,
            scanner_description: issue.issue_description,
            scanner_tags,
            quality_gate: issue.quality_gate,
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
    fn parse_json_finds_all_records() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        assert_eq!(result.findings.len(), 10);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.source_tool, "SonarQube");
    }

    #[test]
    fn parse_csv_finds_all_records() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        assert_eq!(result.findings.len(), 3);
        assert_eq!(result.errors.len(), 0);
    }

    #[test]
    fn severity_mapping() {
        let parser = SonarQubeParser::new();
        assert_eq!(parser.map_severity("BLOCKER"), SeverityLevel::Critical);
        assert_eq!(parser.map_severity("CRITICAL"), SeverityLevel::High);
        assert_eq!(parser.map_severity("MAJOR"), SeverityLevel::Medium);
        assert_eq!(parser.map_severity("MINOR"), SeverityLevel::Low);
        assert_eq!(parser.map_severity("INFO"), SeverityLevel::Info);
        assert_eq!(parser.map_severity("UNKNOWN"), SeverityLevel::Medium);
    }

    #[test]
    fn extracts_app_code_into_metadata() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert_eq!(first.core.metadata["app_code"], "APP01");
    }

    #[test]
    fn fingerprint_is_computed() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert!(!first.core.fingerprint.is_empty());
        assert_eq!(first.core.fingerprint.len(), 64); // SHA-256 hex
    }

    #[test]
    fn extracts_cwe_ids_from_tags() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert!(first.core.cwe_ids.contains(&"CWE-89".to_string()));
    }

    #[test]
    fn extracts_owasp_category_from_tags() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert_eq!(first.core.owasp_category, Some("OWASP-A03".to_string()));
    }

    #[test]
    fn preserves_raw_finding() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert_eq!(first.core.raw_finding["issue_id"], "AYsample001");
        assert_eq!(first.core.raw_finding["severity"], "BLOCKER");
    }

    #[test]
    fn category_data_is_sast() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert!(matches!(first.category_data, CategoryData::Sast(_)));
        if let CategoryData::Sast(ref sast) = first.category_data {
            assert_eq!(sast.rule_id, "java:S3649");
            assert_eq!(sast.file_path, "src/main/java/com/bank/payment/PaymentDao.java");
            assert_eq!(sast.line_number_start, Some(42));
        }
    }

    #[test]
    fn handles_multiple_app_codes() {
        let parser = SonarQubeParser::new();
        let data = include_bytes!("../../tests/fixtures/sonarqube_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();

        let app_codes: Vec<&str> = result
            .findings
            .iter()
            .map(|f| f.core.metadata["app_code"].as_str().unwrap())
            .collect();

        assert!(app_codes.contains(&"APP01"));
        assert!(app_codes.contains(&"APP02"));
        assert!(app_codes.contains(&"APP03"));
    }

    #[test]
    fn rejects_unsupported_format() {
        let parser = SonarQubeParser::new();
        let result = parser.parse(b"", InputFormat::Xml);
        assert!(result.is_err());
    }
}
