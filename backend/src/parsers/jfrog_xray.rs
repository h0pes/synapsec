//! JFrog Xray SCA vulnerability parser.
//!
//! Parses JFrog Xray JSON export format into normalized SCA findings.
//! Supports multi-CVE fan-out (one Xray row with N CVEs produces N findings),
//! GAV coordinate extraction, dependency type inference from impact paths,
//! and preserves metadata for downstream app code resolution.

use serde::{Deserialize, Serialize};

use crate::models::finding::{CreateFinding, FindingCategory, SeverityLevel};
use crate::models::finding_sca::{CreateFindingSca, DependencyType};
use crate::parsers::{InputFormat, ParseError, ParseResult, ParsedFinding, Parser};
use crate::services::finding::CategoryData;
use crate::services::fingerprint;

/// Parser for JFrog Xray JSON export format.
#[derive(Debug, Default)]
pub struct JfrogXrayParser;

impl JfrogXrayParser {
    pub fn new() -> Self {
        Self
    }
}

impl Parser for JfrogXrayParser {
    fn parse(&self, data: &[u8], format: InputFormat) -> Result<ParseResult, anyhow::Error> {
        match format {
            InputFormat::Json => self.parse_json(data),
            _ => anyhow::bail!("JFrog Xray parser only supports JSON format"),
        }
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

// -- Deserialization structs --

/// Top-level JFrog Xray export envelope.
#[derive(Debug, Deserialize)]
struct XrayExport {
    #[expect(dead_code, reason = "present in export for informational purposes")]
    total_rows: Option<u64>,
    rows: Vec<XrayRow>,
}

/// Single vulnerability row from the Xray export.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct XrayRow {
    #[serde(default)]
    cves: Vec<XrayCve>,
    cvss2_max_score: Option<f32>,
    cvss3_max_score: Option<f32>,
    summary: Option<String>,
    severity: Option<String>,
    #[serde(default)]
    severity_source: Option<String>,
    vulnerable_component: Option<String>,
    component_physical_path: Option<String>,
    impacted_artifact: Option<String>,
    #[serde(default)]
    impact_path: Vec<String>,
    path: Option<String>,
    #[serde(default)]
    fixed_versions: Vec<String>,
    published: Option<String>,
    artifact_scan_time: Option<String>,
    issue_id: Option<String>,
    package_type: Option<String>,
    provider: Option<String>,
    description: Option<String>,
    #[serde(default)]
    references: Vec<String>,
}

/// CVE entry within an Xray row.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct XrayCve {
    cve: Option<String>,
    cvss_v2_score: Option<f32>,
    cvss_v2_vector: Option<String>,
    cvss_v3_score: Option<f32>,
    cvss_v3_vector: Option<String>,
}

/// Parsed GAV (group:artifact:version) coordinate.
struct GavCoordinate {
    artifact: String,
    version: String,
}

impl JfrogXrayParser {
    fn parse_json(&self, data: &[u8]) -> Result<ParseResult, anyhow::Error> {
        let export: XrayExport = serde_json::from_slice(data)?;
        let mut findings = Vec::new();
        let mut errors = Vec::new();

        for (row_idx, row) in export.rows.into_iter().enumerate() {
            match self.convert_row(row, row_idx) {
                Ok(row_findings) => findings.extend(row_findings),
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

    /// Convert a single Xray row into one or more findings (multi-CVE fan-out).
    fn convert_row(
        &self,
        row: XrayRow,
        row_idx: usize,
    ) -> Result<Vec<ParsedFinding>, ParseError> {
        let issue_id = row.issue_id.clone().unwrap_or_default();
        if issue_id.is_empty() {
            return Err(ParseError {
                record_index: row_idx,
                field: "issue_id".to_string(),
                message: "Missing issue_id".to_string(),
            });
        }

        let severity_str = row.severity.clone().unwrap_or_default();
        let normalized_severity = self.map_severity(&severity_str);

        // Parse GAV coordinate from vulnerable_component
        let gav = row
            .vulnerable_component
            .as_deref()
            .and_then(Self::parse_gav);
        let package_name = gav
            .as_ref()
            .map(|g| g.artifact.clone())
            .unwrap_or_else(|| {
                row.vulnerable_component
                    .clone()
                    .unwrap_or_default()
            });
        let package_version = gav
            .as_ref()
            .map(|g| g.version.clone())
            .unwrap_or_default();

        // Infer dependency type from impact_path length
        let dependency_type = match row.impact_path.len() {
            0 | 1 => None,
            2 => Some(DependencyType::Direct),
            _ => Some(DependencyType::Transitive),
        };

        // Build dependency path string
        let dependency_path = if row.impact_path.is_empty() {
            None
        } else {
            Some(row.impact_path.join(" -> "))
        };

        // Fixed version: join if multiple, None if empty
        let fixed_version = if row.fixed_versions.is_empty() {
            None
        } else {
            Some(row.fixed_versions.join(", "))
        };

        // Build metadata for app code resolver
        let metadata = serde_json::json!({
            "impacted_artifact": row.impacted_artifact,
            "path": row.path,
            "component_physical_path": row.component_physical_path,
        });

        // Serialize the entire row for raw_finding
        let raw_finding = serde_json::to_value(&row).unwrap_or(serde_json::Value::Null);

        // Multi-CVE fan-out: each CVE produces a separate finding
        let cves = &row.cves;
        if cves.is_empty() {
            // No CVEs: produce one finding with no CVE info
            let source_finding_id = issue_id.clone();
            let fp = fingerprint::compute_sca("", &package_name, &package_version, "");

            let title = row
                .summary
                .clone()
                .unwrap_or_else(|| format!("{issue_id}: vulnerability in {package_name}"));
            let description = row.description.clone().unwrap_or_else(|| title.clone());

            let core = CreateFinding {
                source_tool: self.source_tool().to_string(),
                source_tool_version: None,
                source_finding_id,
                finding_category: self.category(),
                title,
                description,
                normalized_severity: normalized_severity.clone(),
                original_severity: severity_str.clone(),
                cvss_score: row.cvss3_max_score.or(row.cvss2_max_score),
                cvss_vector: None,
                cwe_ids: vec![],
                cve_ids: vec![],
                owasp_category: None,
                confidence: None,
                fingerprint: fp,
                application_id: None,
                tags: vec![],
                remediation_guidance: None,
                raw_finding: raw_finding.clone(),
                metadata: metadata.clone(),
            };

            let sca = CreateFindingSca {
                package_name,
                package_version,
                package_type: row.package_type.clone(),
                fixed_version,
                dependency_type,
                dependency_path,
                license: None,
                license_risk: None,
                sbom_reference: None,
                epss_score: None,
                known_exploited: None,
                exploit_maturity: None,
                affected_artifact: row.impacted_artifact.clone(),
                build_project: None,
            };

            return Ok(vec![ParsedFinding {
                core,
                category_data: CategoryData::Sca(sca),
            }]);
        }

        // One finding per CVE
        let mut findings = Vec::with_capacity(cves.len());
        for cve_entry in cves {
            let cve_id = cve_entry.cve.clone().unwrap_or_default();

            // source_finding_id: append CVE if multiple CVEs in the row
            let source_finding_id = if cves.len() > 1 {
                format!("{issue_id}:{cve_id}")
            } else {
                issue_id.clone()
            };

            let fp =
                fingerprint::compute_sca("", &package_name, &package_version, &cve_id);

            // Prefer per-CVE CVSS v3, fall back to v2, then row-level max
            let cvss_score = cve_entry
                .cvss_v3_score
                .or(cve_entry.cvss_v2_score)
                .or(row.cvss3_max_score)
                .or(row.cvss2_max_score);
            let cvss_vector = cve_entry
                .cvss_v3_vector
                .clone()
                .or_else(|| cve_entry.cvss_v2_vector.clone());

            let title = row
                .summary
                .clone()
                .unwrap_or_else(|| format!("{cve_id}: vulnerability in {package_name}"));
            let description = row.description.clone().unwrap_or_else(|| title.clone());

            let cve_ids = if cve_id.is_empty() {
                vec![]
            } else {
                vec![cve_id.clone()]
            };

            let core = CreateFinding {
                source_tool: self.source_tool().to_string(),
                source_tool_version: None,
                source_finding_id,
                finding_category: self.category(),
                title,
                description,
                normalized_severity: normalized_severity.clone(),
                original_severity: severity_str.clone(),
                cvss_score,
                cvss_vector,
                cwe_ids: vec![],
                cve_ids,
                owasp_category: None,
                confidence: None,
                fingerprint: fp,
                application_id: None,
                tags: vec![],
                remediation_guidance: None,
                raw_finding: raw_finding.clone(),
                metadata: metadata.clone(),
            };

            let sca = CreateFindingSca {
                package_name: package_name.clone(),
                package_version: package_version.clone(),
                package_type: row.package_type.clone(),
                fixed_version: fixed_version.clone(),
                dependency_type: dependency_type.clone(),
                dependency_path: dependency_path.clone(),
                license: None,
                license_risk: None,
                sbom_reference: None,
                epss_score: None,
                known_exploited: None,
                exploit_maturity: None,
                affected_artifact: row.impacted_artifact.clone(),
                build_project: None,
            };

            findings.push(ParsedFinding {
                core,
                category_data: CategoryData::Sca(sca),
            });
        }

        Ok(findings)
    }

    /// Parse a GAV URI (`gav://group:artifact:version`) into components.
    fn parse_gav(component: &str) -> Option<GavCoordinate> {
        let stripped = component.strip_prefix("gav://")?;
        let parts: Vec<&str> = stripped.splitn(3, ':').collect();
        if parts.len() == 3 {
            Some(GavCoordinate {
                artifact: parts[1].to_string(),
                version: parts[2].to_string(),
            })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_finds_all_records() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        // 5 rows, but row 0 has 2 CVEs -> 6 findings
        assert_eq!(result.findings.len(), 6);
        assert_eq!(result.errors.len(), 0);
        assert_eq!(result.source_tool, "JFrog Xray");
    }

    #[test]
    fn severity_mapping() {
        let parser = JfrogXrayParser::new();
        assert_eq!(parser.map_severity("Critical"), SeverityLevel::Critical);
        assert_eq!(parser.map_severity("High"), SeverityLevel::High);
        assert_eq!(parser.map_severity("Medium"), SeverityLevel::Medium);
        assert_eq!(parser.map_severity("Low"), SeverityLevel::Low);
        assert_eq!(parser.map_severity(""), SeverityLevel::Info);
    }

    #[test]
    fn extracts_package_from_gav() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        if let CategoryData::Sca(ref sca) = first.category_data {
            assert!(!sca.package_name.is_empty());
            assert!(!sca.package_version.is_empty());
        } else {
            panic!("Expected SCA category data");
        }
    }

    #[test]
    fn fingerprint_is_per_cve() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        // Records 0 and 1 come from same Xray row but different CVEs
        assert_ne!(
            result.findings[0].core.fingerprint,
            result.findings[1].core.fingerprint
        );
    }

    #[test]
    fn dependency_type_inferred() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let has_transitive = result.findings.iter().any(|f| {
            if let CategoryData::Sca(ref sca) = f.category_data {
                sca.dependency_type == Some(DependencyType::Transitive)
            } else {
                false
            }
        });
        let has_direct = result.findings.iter().any(|f| {
            if let CategoryData::Sca(ref sca) = f.category_data {
                sca.dependency_type == Some(DependencyType::Direct)
            } else {
                false
            }
        });
        assert!(has_transitive);
        assert!(has_direct);
    }

    #[test]
    fn preserves_raw_finding() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert!(first.core.raw_finding.get("issue_id").is_some());
    }

    #[test]
    fn app_code_in_metadata() {
        let parser = JfrogXrayParser::new();
        let data = include_bytes!("../../tests/fixtures/jfrog_xray_sample.json");
        let result = parser.parse(data, InputFormat::Json).unwrap();
        let first = &result.findings[0];
        assert!(first.core.metadata.get("impacted_artifact").is_some());
        assert!(first.core.metadata.get("path").is_some());
    }

    #[test]
    fn rejects_csv_format() {
        let parser = JfrogXrayParser::new();
        let result = parser.parse(b"", InputFormat::Csv);
        assert!(result.is_err());
    }
}
