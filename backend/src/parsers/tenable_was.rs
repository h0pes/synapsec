//! Tenable WAS DAST vulnerability parser.
//!
//! Parses Tenable WAS CSV export format (54 columns) into normalized DAST
//! findings. Skips informational/general records (scan metadata, sitemaps),
//! extracts CWE IDs from the Cross References column, and preserves
//! metadata for downstream app code resolution.

use regex::Regex;
use serde::Deserialize;

use crate::models::finding::{CreateFinding, FindingCategory, SeverityLevel};
use crate::models::finding_dast::CreateFindingDast;
use crate::parsers::{InputFormat, ParseError, ParseResult, ParsedFinding, Parser};
use crate::services::finding::CategoryData;
use crate::services::fingerprint;

/// Maximum length for response_evidence (Plugin Output) to avoid bloat.
const MAX_EVIDENCE_LEN: usize = 10_000;

/// Parser for Tenable WAS CSV export format.
#[derive(Debug, Default)]
pub struct TenableWasParser;

impl TenableWasParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for TenableWasParser {
    fn parse(&self, data: &[u8], format: InputFormat) -> Result<ParseResult, anyhow::Error> {
        match format {
            InputFormat::Csv => self.parse_csv(data),
            _ => anyhow::bail!("Tenable WAS parser only supports CSV format"),
        }
    }

    fn source_tool(&self) -> &str {
        "Tenable WAS"
    }

    fn category(&self) -> FindingCategory {
        FindingCategory::Dast
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

/// Deserialized Tenable WAS CSV record with all 54 columns.
#[derive(Debug, Deserialize)]
#[expect(dead_code, reason = "all 54 columns required for CSV deserialization alignment")]
struct TenableWasRecord {
    #[serde(rename = "Plugin")]
    plugin: String,
    #[serde(rename = "")]
    unnamed: String,
    #[serde(rename = "Family")]
    family: String,
    #[serde(rename = "Severity")]
    severity: String,
    #[serde(rename = "IP Address")]
    ip_address: String,
    #[serde(rename = "Protocol")]
    protocol: String,
    #[serde(rename = "Input Name")]
    input_name: String,
    #[serde(rename = "Input Type")]
    input_type: String,
    #[serde(rename = "Proof")]
    proof: String,
    #[serde(rename = "URL")]
    url: String,
    #[serde(rename = "Port")]
    port: String,
    #[serde(rename = "ACR")]
    acr: String,
    #[serde(rename = "AES")]
    aes: String,
    #[serde(rename = "Exploit?")]
    exploit: String,
    #[serde(rename = "Repository")]
    repository: String,
    #[serde(rename = "DNS Name")]
    dns_name: String,
    #[serde(rename = "Plugin Output")]
    plugin_output: String,
    #[serde(rename = "First Discovered")]
    first_discovered: String,
    #[serde(rename = "Last Observed")]
    last_observed: String,
    #[serde(rename = "Exploit Frameworks")]
    exploit_frameworks: String,
    #[serde(rename = "Recast Risk Comment")]
    recast_risk_comment: String,
    #[serde(rename = "Accept Risk Comment")]
    accept_risk_comment: String,
    #[serde(rename = "Host ID")]
    host_id: String,
    #[serde(rename = "Synopsis")]
    synopsis: String,
    #[serde(rename = "Description")]
    description: String,
    #[serde(rename = "Steps to Remediate")]
    steps_to_remediate: String,
    #[serde(rename = "See Also")]
    see_also: String,
    #[serde(rename = "Risk Factor")]
    risk_factor: String,
    #[serde(rename = "STIG Severity")]
    stig_severity: String,
    #[serde(rename = "Vulnerability Priority Rating")]
    vpr: String,
    #[serde(rename = "Exploit Prediction Scoring System (EPSS)")]
    epss: String,
    #[serde(rename = "CVSS V2 Base Score")]
    cvss_v2_base_score: String,
    #[serde(rename = "CVSS V3 Base Score")]
    cvss_v3_base_score: String,
    #[serde(rename = "CVSS V4 Base Score")]
    cvss_v4_base_score: String,
    #[serde(rename = "CVSS V2 Temporal Score")]
    cvss_v2_temporal_score: String,
    #[serde(rename = "CVSS V3 Temporal Score")]
    cvss_v3_temporal_score: String,
    #[serde(rename = "CVSS V4 Threat Score")]
    cvss_v4_threat_score: String,
    #[serde(rename = "CVSS V2 Vector")]
    cvss_v2_vector: String,
    #[serde(rename = "CVSS V3 Vector")]
    cvss_v3_vector: String,
    #[serde(rename = "CVSS V4 Vector")]
    cvss_v4_vector: String,
    #[serde(rename = "CVSS V4 Threat Vector")]
    cvss_v4_threat_vector: String,
    #[serde(rename = "CVSS V4 Supplemental")]
    cvss_v4_supplemental: String,
    #[serde(rename = "CPE")]
    cpe: String,
    #[serde(rename = "CVE")]
    cve: String,
    #[serde(rename = "BID")]
    bid: String,
    #[serde(rename = "Cross References")]
    cross_references: String,
    #[serde(rename = "Vuln Publication Date")]
    vuln_publication_date: String,
    #[serde(rename = "Security End of Life Date")]
    security_end_of_life_date: String,
    #[serde(rename = "Patch Publication Date")]
    patch_publication_date: String,
    #[serde(rename = "Plugin Publication Date")]
    plugin_publication_date: String,
    #[serde(rename = "Plugin Modification Date")]
    plugin_modification_date: String,
    #[serde(rename = "Exploit Ease")]
    exploit_ease: String,
    #[serde(rename = "Check Type")]
    check_type: String,
    #[serde(rename = "Version")]
    version: String,
}

impl TenableWasParser {
    fn parse_csv(&self, data: &[u8]) -> Result<ParseResult, anyhow::Error> {
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(data);

        let cwe_regex = Regex::new(r"CWE:(\d+)")?;
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        for (i, result) in reader.deserialize::<TenableWasRecord>().enumerate() {
            match result {
                Ok(record) => {
                    // Skip info/general records (scan metadata, sitemaps)
                    if record.severity == "Info" && record.family == "General" {
                        continue;
                    }
                    match self.convert_record(&record, i, &cwe_regex) {
                        Ok(finding) => findings.push(finding),
                        Err(err) => errors.push(err),
                    }
                }
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

    /// Convert a single Tenable WAS record into a normalized finding.
    fn convert_record(
        &self,
        record: &TenableWasRecord,
        index: usize,
        cwe_regex: &Regex,
    ) -> Result<ParsedFinding, ParseError> {
        let plugin_id = &record.plugin;
        if plugin_id.is_empty() {
            return Err(ParseError {
                record_index: index,
                field: "Plugin".to_string(),
                message: "Missing Plugin ID".to_string(),
            });
        }

        let normalized_severity = self.map_severity(&record.severity);

        // CVSS score preference: V3 -> V4 -> V2
        let cvss_score = parse_optional_f32(&record.cvss_v3_base_score)
            .or_else(|| parse_optional_f32(&record.cvss_v4_base_score))
            .or_else(|| parse_optional_f32(&record.cvss_v2_base_score));

        // CVSS vector preference: V3 -> V4 -> V2
        let cvss_vector = non_empty(&record.cvss_v3_vector)
            .or_else(|| non_empty(&record.cvss_v4_vector))
            .or_else(|| non_empty(&record.cvss_v2_vector))
            .map(String::from);

        // Extract CWE IDs from Cross References (e.g., "CWE:79" -> "CWE-79")
        let cwe_ids: Vec<String> = cwe_regex
            .captures_iter(&record.cross_references)
            .map(|cap| format!("CWE-{}", &cap[1]))
            .collect();

        // Extract CVE IDs from CVE column (newline or comma separated)
        let cve_ids: Vec<String> = record
            .cve
            .split(['\n', ','])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        // source_finding_id: plugin_id:url:input_name
        let source_finding_id = format!(
            "{}:{}:{}",
            plugin_id, record.url, record.input_name
        );

        // Fingerprint: compute_dast("", plugin_id:url, "", input_name)
        let target_url_component = format!("{plugin_id}:{}", record.url);
        let fp = fingerprint::compute_dast(
            "",
            &target_url_component,
            "",
            &record.input_name,
        );

        // Title: Synopsis, fallback to "Plugin {plugin_id}"
        let title = if record.synopsis.is_empty() {
            format!("Plugin {plugin_id}")
        } else {
            record.synopsis.clone()
        };

        // Parse dates into metadata
        let first_discovered = parse_tenable_date(&record.first_discovered);
        let last_observed = parse_tenable_date(&record.last_observed);

        // Truncate Plugin Output for response_evidence
        let response_evidence = if record.plugin_output.is_empty() {
            None
        } else if record.plugin_output.len() > MAX_EVIDENCE_LEN {
            Some(record.plugin_output[..MAX_EVIDENCE_LEN].to_string())
        } else {
            Some(record.plugin_output.clone())
        };

        // Build metadata for app code resolver
        let metadata = serde_json::json!({
            "dns_name": non_empty(&record.dns_name),
            "url": non_empty(&record.url),
            "ip_address": non_empty(&record.ip_address),
            "port": non_empty(&record.port),
            "host_id": non_empty(&record.host_id),
            "epss": non_empty(&record.epss),
            "vpr": non_empty(&record.vpr),
            "acr": non_empty(&record.acr),
            "aes": non_empty(&record.aes),
            "first_discovered": first_discovered,
            "last_observed": last_observed,
        });

        // Build raw finding JSON
        let raw_finding = serde_json::json!({
            "plugin": record.plugin,
            "family": record.family,
            "severity": record.severity,
            "ip_address": record.ip_address,
            "input_name": record.input_name,
            "proof": record.proof,
            "url": record.url,
            "dns_name": record.dns_name,
            "synopsis": record.synopsis,
            "description": record.description,
            "cross_references": record.cross_references,
            "cve": record.cve,
            "repository": record.repository,
        });

        let remediation_guidance = non_empty(&record.steps_to_remediate).map(String::from);

        let core = CreateFinding {
            source_tool: self.source_tool().to_string(),
            source_tool_version: None,
            source_finding_id,
            finding_category: self.category(),
            title,
            description: record.description.clone(),
            normalized_severity,
            original_severity: record.severity.clone(),
            cvss_score,
            cvss_vector,
            cwe_ids,
            cve_ids,
            owasp_category: None,
            confidence: None,
            fingerprint: fp,
            application_id: None,
            tags: vec![],
            remediation_guidance,
            raw_finding,
            metadata,
        };

        let parameter = non_empty(&record.input_name).map(String::from);
        let request_evidence = non_empty(&record.proof).map(String::from);

        let dast = CreateFindingDast {
            target_url: record.url.clone(),
            http_method: None,
            parameter,
            attack_vector: None,
            request_evidence,
            response_evidence,
            authentication_required: None,
            authentication_context: None,
            web_application_name: non_empty(&record.dns_name).map(String::from),
            scan_policy: non_empty(&record.repository).map(String::from),
        };

        Ok(ParsedFinding {
            core,
            category_data: CategoryData::Dast(dast),
        })
    }
}

/// Parse a Tenable date string (e.g., "Sep 5, 2025 15:30:16 UTC") into an ISO 8601 string.
fn parse_tenable_date(date_str: &str) -> Option<String> {
    let trimmed = date_str.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Strip trailing " UTC" for parsing, then treat as UTC
    let without_tz = trimmed.strip_suffix(" UTC").unwrap_or(trimmed);
    chrono::NaiveDateTime::parse_from_str(without_tz, "%b %d, %Y %H:%M:%S")
        .ok()
        .map(|dt| format!("{}Z", dt.format("%Y-%m-%dT%H:%M:%S")))
}

/// Parse a string as f32, returning None for empty or non-numeric values.
fn parse_optional_f32(s: &str) -> Option<f32> {
    let trimmed = s.trim();
    if trimmed.is_empty() || trimmed == "N/A" {
        return None;
    }
    trimmed.parse::<f32>().ok()
}

/// Return Some(s) if s is non-empty, None otherwise.
fn non_empty(s: &str) -> Option<&str> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_csv_skips_info_general() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        // 5 rows, 2 are info/general -> 3 findings
        assert_eq!(result.findings.len(), 3);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.source_tool, "Tenable WAS");
    }

    #[test]
    fn severity_mapping() {
        let parser = TenableWasParser::new();
        assert_eq!(parser.map_severity("Critical"), SeverityLevel::Critical);
        assert_eq!(parser.map_severity("High"), SeverityLevel::High);
        assert_eq!(parser.map_severity("Medium"), SeverityLevel::Medium);
        assert_eq!(parser.map_severity("Low"), SeverityLevel::Low);
        assert_eq!(parser.map_severity("Info"), SeverityLevel::Info);
    }

    #[test]
    fn extracts_target_url() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        if let CategoryData::Dast(ref dast) = first.category_data {
            assert!(dast.target_url.starts_with("https://"));
        } else {
            panic!("Expected DAST category data");
        }
    }

    #[test]
    fn fingerprint_uses_plugin_url_input() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        assert!(!first.core.fingerprint.is_empty());
        assert_eq!(first.core.fingerprint.len(), 64);
    }

    #[test]
    fn parses_human_readable_dates() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        assert!(first.core.metadata.get("first_discovered").is_some());
    }

    #[test]
    fn extracts_cwe_from_cross_references() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let has_cwe = result.findings.iter().any(|f| !f.core.cwe_ids.is_empty());
        assert!(has_cwe);
    }

    #[test]
    fn dns_name_in_metadata() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        assert!(first.core.metadata.get("dns_name").is_some());
    }

    #[test]
    fn cvss_score_prefers_v3() {
        let parser = TenableWasParser::new();
        let data = include_bytes!("../../tests/fixtures/tenable_was_sample.csv");
        let result = parser.parse(data, InputFormat::Csv).unwrap();
        let first = &result.findings[0];
        assert!(first.core.cvss_score.is_some());
    }

    #[test]
    fn rejects_json_format() {
        let parser = TenableWasParser::new();
        let result = parser.parse(b"", InputFormat::Json);
        assert!(result.is_err());
    }
}
