//! Cross-tool deduplication for findings from different scanners.
//!
//! Compares two finding candidates from different tools within the same
//! category to determine if they represent the same vulnerability.
//! This is pure logic with no database access — the caller is responsible
//! for fetching candidates and persisting match results.

use uuid::Uuid;

use crate::models::finding::{ConfidenceLevel, FindingCategory};

/// Candidate finding for cross-tool deduplication comparison.
#[derive(Debug, Clone)]
pub struct CrossDedupCandidate {
    pub id: Uuid,
    pub category: FindingCategory,
    pub application_id: Option<Uuid>,
    pub source_tool: String,
    pub cve_ids: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub package_name: Option<String>,
    pub file_path: Option<String>,
    pub line_number: Option<i32>,
    pub branch: Option<String>,
    pub target_url: Option<String>,
    pub parameter: Option<String>,
}

/// Result of a cross-tool deduplication match.
#[derive(Debug, Clone)]
pub struct CrossDedupMatch {
    pub finding_a_id: Uuid,
    pub finding_b_id: Uuid,
    pub confidence: ConfidenceLevel,
    pub match_reason: String,
}

/// Check if two findings from different tools are cross-tool duplicates.
///
/// Returns `Some(CrossDedupMatch)` if the pair should be deduplicated,
/// `None` otherwise. Both candidates must share the same category,
/// belong to the same application, and originate from different tools.
pub fn check_cross_dedup(a: &CrossDedupCandidate, b: &CrossDedupCandidate) -> Option<CrossDedupMatch> {
    // Guard: must be same category
    if a.category != b.category {
        return None;
    }
    // Guard: must be different source tool
    if a.source_tool == b.source_tool {
        return None;
    }
    // Guard: must have same application_id (both Some and equal)
    match (&a.application_id, &b.application_id) {
        (Some(app_a), Some(app_b)) if app_a == app_b => {}
        _ => return None,
    }

    match a.category {
        FindingCategory::Sca => check_sca(a, b),
        FindingCategory::Sast => check_sast(a, b),
        FindingCategory::Dast => check_dast(a, b),
    }
}

/// Check SCA cross-tool dedup: CVE intersection + optional package match.
fn check_sca(a: &CrossDedupCandidate, b: &CrossDedupCandidate) -> Option<CrossDedupMatch> {
    if !has_common_id(&a.cve_ids, &b.cve_ids) {
        return None;
    }

    let same_package = match (&a.package_name, &b.package_name) {
        (Some(pa), Some(pb)) => pa == pb,
        _ => false,
    };

    let (confidence, match_reason) = if same_package {
        (ConfidenceLevel::High, "Same CVE and package name across tools".to_string())
    } else {
        (ConfidenceLevel::Medium, "Same CVE across tools (different or missing package)".to_string())
    };

    Some(CrossDedupMatch {
        finding_a_id: a.id,
        finding_b_id: b.id,
        confidence,
        match_reason,
    })
}

/// Check SAST cross-tool dedup: CWE + file + line proximity + branch.
fn check_sast(a: &CrossDedupCandidate, b: &CrossDedupCandidate) -> Option<CrossDedupMatch> {
    if !has_common_id(&a.cwe_ids, &b.cwe_ids) {
        return None;
    }

    // Both must have a branch; branches must match
    let (branch_a, branch_b) = match (&a.branch, &b.branch) {
        (Some(ba), Some(bb)) => (ba, bb),
        _ => return None,
    };
    if branch_a != branch_b {
        return None;
    }

    // Both must have file_path; paths must match exactly
    let (file_a, file_b) = match (&a.file_path, &b.file_path) {
        (Some(fa), Some(fb)) => (fa, fb),
        _ => return None,
    };
    if file_a != file_b {
        return None;
    }

    /// Maximum line distance for high-confidence SAST match.
    const LINE_PROXIMITY_THRESHOLD: i32 = 5;

    let nearby_lines = match (a.line_number, b.line_number) {
        (Some(la), Some(lb)) => (la - lb).abs() <= LINE_PROXIMITY_THRESHOLD,
        _ => false,
    };

    let (confidence, match_reason) = if nearby_lines {
        (
            ConfidenceLevel::High,
            "Same CWE, file, branch, and nearby line across tools".to_string(),
        )
    } else {
        (
            ConfidenceLevel::Medium,
            "Same CWE, file, and branch across tools (different line)".to_string(),
        )
    };

    Some(CrossDedupMatch {
        finding_a_id: a.id,
        finding_b_id: b.id,
        confidence,
        match_reason,
    })
}

/// Check DAST cross-tool dedup: CWE + target URL + optional parameter.
fn check_dast(a: &CrossDedupCandidate, b: &CrossDedupCandidate) -> Option<CrossDedupMatch> {
    if !has_common_id(&a.cwe_ids, &b.cwe_ids) {
        return None;
    }

    // Both must have target_url; URLs must match
    let (url_a, url_b) = match (&a.target_url, &b.target_url) {
        (Some(ua), Some(ub)) => (ua, ub),
        _ => return None,
    };
    if url_a != url_b {
        return None;
    }

    let same_parameter = match (&a.parameter, &b.parameter) {
        (Some(pa), Some(pb)) => pa == pb,
        _ => false,
    };

    let (confidence, match_reason) = if same_parameter {
        (
            ConfidenceLevel::High,
            "Same CWE, target URL, and parameter across tools".to_string(),
        )
    } else {
        (
            ConfidenceLevel::Medium,
            "Same CWE and target URL across tools (no parameter match)".to_string(),
        )
    };

    Some(CrossDedupMatch {
        finding_a_id: a.id,
        finding_b_id: b.id,
        confidence,
        match_reason,
    })
}

/// Check whether two ID lists share at least one common element.
fn has_common_id(a: &[String], b: &[String]) -> bool {
    a.iter().any(|id| b.contains(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a candidate with sensible defaults.
    fn make_candidate(overrides: CandidateOverrides) -> CrossDedupCandidate {
        let app_id = overrides.application_id.unwrap_or_else(|| Some(Uuid::nil()));
        CrossDedupCandidate {
            id: overrides.id.unwrap_or_else(Uuid::new_v4),
            category: overrides.category.unwrap_or(FindingCategory::Sca),
            application_id: app_id,
            source_tool: overrides.source_tool.unwrap_or_else(|| "tool-a".to_string()),
            cve_ids: overrides.cve_ids.unwrap_or_default(),
            cwe_ids: overrides.cwe_ids.unwrap_or_default(),
            package_name: overrides.package_name.unwrap_or(None),
            file_path: overrides.file_path.unwrap_or(None),
            line_number: overrides.line_number.unwrap_or(None),
            branch: overrides.branch.unwrap_or(None),
            target_url: overrides.target_url.unwrap_or(None),
            parameter: overrides.parameter.unwrap_or(None),
        }
    }

    #[derive(Default)]
    struct CandidateOverrides {
        id: Option<Uuid>,
        category: Option<FindingCategory>,
        application_id: Option<Option<Uuid>>,
        source_tool: Option<String>,
        cve_ids: Option<Vec<String>>,
        cwe_ids: Option<Vec<String>>,
        package_name: Option<Option<String>>,
        file_path: Option<Option<String>>,
        line_number: Option<Option<i32>>,
        branch: Option<Option<String>>,
        target_url: Option<Option<String>>,
        parameter: Option<Option<String>>,
    }

    #[test]
    fn sca_same_cve_same_app_is_match() {
        let a = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("JFrog Xray".to_string()),
            cve_ids: Some(vec!["CVE-2023-1234".to_string()]),
            package_name: Some(Some("log4j-core".to_string())),
            ..Default::default()
        });
        let b = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("Snyk".to_string()),
            cve_ids: Some(vec!["CVE-2023-1234".to_string()]),
            package_name: Some(Some("log4j-core".to_string())),
            ..Default::default()
        });

        let result = check_cross_dedup(&a, &b);
        assert!(result.is_some(), "Expected a match for same CVE + same package");
        let m = result.unwrap();
        assert_eq!(m.confidence, ConfidenceLevel::High);
        assert_eq!(m.finding_a_id, a.id);
        assert_eq!(m.finding_b_id, b.id);
    }

    #[test]
    fn same_tool_is_not_cross_dedup() {
        let a = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("JFrog Xray".to_string()),
            cve_ids: Some(vec!["CVE-2023-1234".to_string()]),
            package_name: Some(Some("log4j-core".to_string())),
            ..Default::default()
        });
        let b = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("JFrog Xray".to_string()),
            cve_ids: Some(vec!["CVE-2023-1234".to_string()]),
            package_name: Some(Some("log4j-core".to_string())),
            ..Default::default()
        });

        let result = check_cross_dedup(&a, &b);
        assert!(result.is_none(), "Same tool should not produce a cross-dedup match");
    }

    #[test]
    fn different_category_is_not_cross_dedup() {
        let a = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("JFrog Xray".to_string()),
            cve_ids: Some(vec!["CVE-2023-1234".to_string()]),
            ..Default::default()
        });
        let b = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            source_tool: Some("Tenable WAS".to_string()),
            cve_ids: Some(vec!["CVE-2023-1234".to_string()]),
            ..Default::default()
        });

        let result = check_cross_dedup(&a, &b);
        assert!(result.is_none(), "Cross-category pairs go to correlation, not dedup");
    }

    #[test]
    fn sast_same_cwe_same_file_nearby_line_same_branch() {
        let a = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            line_number: Some(Some(42)),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let b = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("Checkmarx".to_string()),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            line_number: Some(Some(45)),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let result = check_cross_dedup(&a, &b);
        assert!(result.is_some(), "Expected high-confidence SAST match");
        let m = result.unwrap();
        assert_eq!(m.confidence, ConfidenceLevel::High);
    }

    #[test]
    fn sast_different_branch_is_not_dedup() {
        let a = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            line_number: Some(Some(42)),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let b = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("Checkmarx".to_string()),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            line_number: Some(Some(42)),
            branch: Some(Some("feature/auth".to_string())),
            ..Default::default()
        });

        let result = check_cross_dedup(&a, &b);
        assert!(result.is_none(), "Different branches should not match for SAST");
    }
}
