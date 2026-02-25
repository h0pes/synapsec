//! Correlation engine for cross-tool and intra-tool finding relationships.
//!
//! Implements six correlation rules (CR-1 through CR-6) as pure matching
//! logic. Compares a new finding against existing findings to identify
//! cross-category relationships (SCA/SAST/DAST) and intra-tool patterns
//! (same SAST rule across files, same CWE in same file).
//!
//! This module contains no database access — the caller is responsible for
//! fetching candidates and persisting the resulting relationships.

use uuid::Uuid;

use crate::models::finding::{ConfidenceLevel, FindingCategory, RelationshipType};

/// Candidate finding for correlation comparison.
#[derive(Debug, Clone)]
pub struct CorrelationCandidate {
    pub id: Uuid,
    pub category: FindingCategory,
    pub application_id: Option<Uuid>,
    pub source_tool: String,
    pub cve_ids: Vec<String>,
    pub cwe_ids: Vec<String>,
    pub rule_id: Option<String>,
    pub file_path: Option<String>,
    pub branch: Option<String>,
    pub target_url: Option<String>,
    pub parameter: Option<String>,
    pub package_name: Option<String>,
}

/// Result of a correlation match.
#[derive(Debug, Clone)]
pub struct CorrelationMatch {
    pub existing_finding_id: Uuid,
    pub rule_name: String,
    pub relationship_type: RelationshipType,
    pub confidence: ConfidenceLevel,
    pub match_reason: String,
}

/// Correlate a new finding against a list of existing findings.
///
/// Applies the 6 correlation rules (CR-1 through CR-6) and returns
/// all matches found. A single new finding can match multiple existing
/// findings under different rules.
pub fn correlate_finding(
    new_finding: &CorrelationCandidate,
    existing_findings: &[CorrelationCandidate],
) -> Vec<CorrelationMatch> {
    let rules: &[fn(&CorrelationCandidate, &CorrelationCandidate) -> Option<CorrelationMatch>] = &[
        try_cr1,
        try_cr2,
        try_cr3,
        try_cr4,
        try_cr5,
        try_cr6,
    ];

    existing_findings
        .iter()
        .flat_map(|existing| {
            rules
                .iter()
                .filter_map(|rule| rule(new_finding, existing))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Check whether two ID lists share at least one common element.
fn has_common_id(a: &[String], b: &[String]) -> bool {
    a.iter().any(|id| b.contains(id))
}

/// Check that both candidates belong to the same application.
fn same_app(a: &CorrelationCandidate, b: &CorrelationCandidate) -> bool {
    matches!(
        (&a.application_id, &b.application_id),
        (Some(app_a), Some(app_b)) if app_a == app_b
    )
}

/// Production branch name used for cross-category SAST participation.
const PRODUCTION_BRANCH: &str = "main";

/// Check whether a candidate is on the production branch.
fn is_production_branch(candidate: &CorrelationCandidate) -> bool {
    candidate.branch.as_deref() == Some(PRODUCTION_BRANCH)
}

// ---------------------------------------------------------------------------
// Cross-tool rules (different categories, same application)
// ---------------------------------------------------------------------------

/// CR-1: Same CVE cross-category (SCA <-> DAST).
///
/// Matches when both findings share at least one CVE ID and are from
/// different categories within the SCA/DAST pair.
fn try_cr1(
    new: &CorrelationCandidate,
    existing: &CorrelationCandidate,
) -> Option<CorrelationMatch> {
    // Must be different categories
    if new.category == existing.category {
        return None;
    }
    // Both must be SCA or DAST
    if !is_sca_or_dast(new) || !is_sca_or_dast(existing) {
        return None;
    }
    if !same_app(new, existing) {
        return None;
    }
    if !has_common_id(&new.cve_ids, &existing.cve_ids) {
        return None;
    }

    Some(CorrelationMatch {
        existing_finding_id: existing.id,
        rule_name: "CR-1".to_string(),
        relationship_type: RelationshipType::CorrelatedWith,
        confidence: ConfidenceLevel::High,
        match_reason: "Same CVE across SCA and DAST categories".to_string(),
    })
}

/// CR-2: Same CWE cross-category (SAST <-> DAST), production branch.
///
/// Matches when both findings share at least one CWE ID and are from
/// different categories within the SAST/DAST pair. The SAST finding
/// must be on the production branch.
fn try_cr2(
    new: &CorrelationCandidate,
    existing: &CorrelationCandidate,
) -> Option<CorrelationMatch> {
    if new.category == existing.category {
        return None;
    }
    if !is_sast_or_dast(new) || !is_sast_or_dast(existing) {
        return None;
    }
    if !same_app(new, existing) {
        return None;
    }
    if !has_common_id(&new.cwe_ids, &existing.cwe_ids) {
        return None;
    }

    // The SAST finding must be on the production branch
    let sast_candidate = if new.category == FindingCategory::Sast {
        new
    } else {
        existing
    };
    if !is_production_branch(sast_candidate) {
        return None;
    }

    Some(CorrelationMatch {
        existing_finding_id: existing.id,
        rule_name: "CR-2".to_string(),
        relationship_type: RelationshipType::CorrelatedWith,
        confidence: ConfidenceLevel::Medium,
        match_reason: "Same CWE across SAST (production) and DAST categories".to_string(),
    })
}

/// CR-3: SCA package matched to SAST import.
///
/// Matches when an SCA finding's package name appears as a
/// case-insensitive substring of the SAST finding's file path.
/// The SAST finding must be on the production branch.
fn try_cr3(
    new: &CorrelationCandidate,
    existing: &CorrelationCandidate,
) -> Option<CorrelationMatch> {
    if new.category == existing.category {
        return None;
    }

    // Identify which is SCA and which is SAST
    let (sca, sast) = identify_pair(new, existing, FindingCategory::Sca, FindingCategory::Sast)?;

    if !same_app(new, existing) {
        return None;
    }
    if !is_production_branch(sast) {
        return None;
    }

    let package = sca.package_name.as_deref()?;
    let file = sast.file_path.as_deref().or(sast.rule_id.as_deref())?;

    // Case-insensitive substring match
    if !file.to_lowercase().contains(&package.to_lowercase()) {
        return None;
    }

    Some(CorrelationMatch {
        existing_finding_id: existing.id,
        rule_name: "CR-3".to_string(),
        relationship_type: RelationshipType::CorrelatedWith,
        confidence: ConfidenceLevel::Medium,
        match_reason: format!(
            "SCA package '{}' found in SAST file path/rule",
            package
        ),
    })
}

/// CR-4: DAST endpoint matched to SAST handler.
///
/// MVP implementation: matches when a DAST finding has a target URL,
/// a SAST finding has a file path, they share a CWE, and the SAST
/// finding is on the production branch.
fn try_cr4(
    new: &CorrelationCandidate,
    existing: &CorrelationCandidate,
) -> Option<CorrelationMatch> {
    if new.category == existing.category {
        return None;
    }

    let (dast, sast) = identify_pair(new, existing, FindingCategory::Dast, FindingCategory::Sast)?;

    if !same_app(new, existing) {
        return None;
    }
    if !is_production_branch(sast) {
        return None;
    }

    // DAST must have target_url, SAST must have file_path
    dast.target_url.as_ref()?;
    sast.file_path.as_ref()?;

    // They must share at least one CWE
    if !has_common_id(&new.cwe_ids, &existing.cwe_ids) {
        return None;
    }

    Some(CorrelationMatch {
        existing_finding_id: existing.id,
        rule_name: "CR-4".to_string(),
        relationship_type: RelationshipType::CorrelatedWith,
        confidence: ConfidenceLevel::Medium,
        match_reason: "DAST endpoint and SAST handler share CWE in same application".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Intra-tool rules (same category SAST, same application, same branch)
// ---------------------------------------------------------------------------

/// CR-5: Same SAST rule_id across multiple files.
///
/// Matches when two SAST findings share the same rule but appear in
/// different files within the same application and branch.
fn try_cr5(
    new: &CorrelationCandidate,
    existing: &CorrelationCandidate,
) -> Option<CorrelationMatch> {
    if new.category != FindingCategory::Sast || existing.category != FindingCategory::Sast {
        return None;
    }
    if !same_app(new, existing) {
        return None;
    }

    // Same branch (both must be Some and equal)
    let (branch_new, branch_existing) = match (&new.branch, &existing.branch) {
        (Some(bn), Some(be)) => (bn, be),
        _ => return None,
    };
    if branch_new != branch_existing {
        return None;
    }

    // Same rule_id (both must be Some and equal)
    let (rule_new, rule_existing) = match (&new.rule_id, &existing.rule_id) {
        (Some(rn), Some(re)) => (rn, re),
        _ => return None,
    };
    if rule_new != rule_existing {
        return None;
    }

    // Different file_path (both must be Some and not equal)
    let (file_new, file_existing) = match (&new.file_path, &existing.file_path) {
        (Some(fn_), Some(fe)) => (fn_, fe),
        _ => return None,
    };
    if file_new == file_existing {
        return None;
    }

    Some(CorrelationMatch {
        existing_finding_id: existing.id,
        rule_name: "CR-5".to_string(),
        relationship_type: RelationshipType::GroupedUnder,
        confidence: ConfidenceLevel::High,
        match_reason: format!(
            "Same SAST rule '{}' in different files",
            rule_new
        ),
    })
}

/// CR-6: Same CWE in same file (SAST).
///
/// Matches when two SAST findings share a CWE and appear in the same
/// file within the same application and branch, but have different
/// rule IDs or finding IDs.
fn try_cr6(
    new: &CorrelationCandidate,
    existing: &CorrelationCandidate,
) -> Option<CorrelationMatch> {
    if new.category != FindingCategory::Sast || existing.category != FindingCategory::Sast {
        return None;
    }
    if !same_app(new, existing) {
        return None;
    }

    // Same branch
    let (branch_new, branch_existing) = match (&new.branch, &existing.branch) {
        (Some(bn), Some(be)) => (bn, be),
        _ => return None,
    };
    if branch_new != branch_existing {
        return None;
    }

    // Must share at least one CWE
    if !has_common_id(&new.cwe_ids, &existing.cwe_ids) {
        return None;
    }

    // Same file_path (both must be Some and equal)
    let (file_new, file_existing) = match (&new.file_path, &existing.file_path) {
        (Some(fn_), Some(fe)) => (fn_, fe),
        _ => return None,
    };
    if file_new != file_existing {
        return None;
    }

    // Different rule_id OR different finding IDs (to avoid self-matching)
    let different_rule = match (&new.rule_id, &existing.rule_id) {
        (Some(rn), Some(re)) => rn != re,
        _ => true,
    };
    if !different_rule && new.id == existing.id {
        return None;
    }

    Some(CorrelationMatch {
        existing_finding_id: existing.id,
        rule_name: "CR-6".to_string(),
        relationship_type: RelationshipType::GroupedUnder,
        confidence: ConfidenceLevel::High,
        match_reason: "Same CWE in same SAST file".to_string(),
    })
}

// ---------------------------------------------------------------------------
// Internal utilities
// ---------------------------------------------------------------------------

/// Check whether a candidate is SCA or DAST.
fn is_sca_or_dast(c: &CorrelationCandidate) -> bool {
    matches!(c.category, FindingCategory::Sca | FindingCategory::Dast)
}

/// Check whether a candidate is SAST or DAST.
fn is_sast_or_dast(c: &CorrelationCandidate) -> bool {
    matches!(c.category, FindingCategory::Sast | FindingCategory::Dast)
}

/// Identify which candidate matches which category in a two-category pair.
///
/// Returns `Some((cat_a_candidate, cat_b_candidate))` when the pair contains
/// exactly one of each requested category, `None` otherwise.
fn identify_pair<'a>(
    new: &'a CorrelationCandidate,
    existing: &'a CorrelationCandidate,
    cat_a: FindingCategory,
    cat_b: FindingCategory,
) -> Option<(&'a CorrelationCandidate, &'a CorrelationCandidate)> {
    if new.category == cat_a && existing.category == cat_b {
        Some((new, existing))
    } else if new.category == cat_b && existing.category == cat_a {
        Some((existing, new))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Test helper ----------------------------------------------------------

    /// Overrides for building a test candidate with sensible defaults.
    #[derive(Default)]
    struct CandidateOverrides {
        id: Option<Uuid>,
        category: Option<FindingCategory>,
        application_id: Option<Option<Uuid>>,
        source_tool: Option<String>,
        cve_ids: Option<Vec<String>>,
        cwe_ids: Option<Vec<String>>,
        rule_id: Option<Option<String>>,
        file_path: Option<Option<String>>,
        branch: Option<Option<String>>,
        target_url: Option<Option<String>>,
        parameter: Option<Option<String>>,
        package_name: Option<Option<String>>,
    }

    /// Build a candidate with sensible defaults.
    fn make_candidate(overrides: CandidateOverrides) -> CorrelationCandidate {
        let app_id = overrides.application_id.unwrap_or_else(|| Some(Uuid::nil()));
        CorrelationCandidate {
            id: overrides.id.unwrap_or_else(Uuid::new_v4),
            category: overrides.category.unwrap_or(FindingCategory::Sast),
            application_id: app_id,
            source_tool: overrides.source_tool.unwrap_or_else(|| "tool-a".to_string()),
            cve_ids: overrides.cve_ids.unwrap_or_default(),
            cwe_ids: overrides.cwe_ids.unwrap_or_default(),
            rule_id: overrides.rule_id.unwrap_or(None),
            file_path: overrides.file_path.unwrap_or(None),
            branch: overrides.branch.unwrap_or(None),
            target_url: overrides.target_url.unwrap_or(None),
            parameter: overrides.parameter.unwrap_or(None),
            package_name: overrides.package_name.unwrap_or(None),
        }
    }

    // -- CR-1 tests -----------------------------------------------------------

    #[test]
    fn cr1_same_cve_sca_dast_same_app() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("JFrog Xray".to_string()),
            cve_ids: Some(vec!["CVE-2021-44228".to_string()]),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            source_tool: Some("Tenable WAS".to_string()),
            cve_ids: Some(vec!["CVE-2021-44228".to_string()]),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing.clone()]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule_name, "CR-1");
        assert_eq!(matches[0].relationship_type, RelationshipType::CorrelatedWith);
        assert_eq!(matches[0].confidence, ConfidenceLevel::High);
        assert_eq!(matches[0].existing_finding_id, existing.id);
    }

    #[test]
    fn cr1_no_match_different_app() {
        let app_a = Uuid::new_v4();
        let app_b = Uuid::new_v4();
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            application_id: Some(Some(app_a)),
            cve_ids: Some(vec!["CVE-2021-44228".to_string()]),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            application_id: Some(Some(app_b)),
            cve_ids: Some(vec!["CVE-2021-44228".to_string()]),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        assert!(matches.is_empty(), "Different apps should not match");
    }

    #[test]
    fn cr1_no_match_same_category() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            cve_ids: Some(vec!["CVE-2021-44228".to_string()]),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            cve_ids: Some(vec!["CVE-2021-44228".to_string()]),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        assert!(
            matches.iter().all(|m| m.rule_name != "CR-1"),
            "Same category should not fire CR-1"
        );
    }

    // -- CR-2 tests -----------------------------------------------------------

    #[test]
    fn cr2_same_cwe_sast_dast_production_branch() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            source_tool: Some("Tenable WAS".to_string()),
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing.clone()]);
        let cr2_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-2").collect();
        assert_eq!(cr2_matches.len(), 1);
        assert_eq!(cr2_matches[0].relationship_type, RelationshipType::CorrelatedWith);
        assert_eq!(cr2_matches[0].confidence, ConfidenceLevel::Medium);
        assert_eq!(cr2_matches[0].existing_finding_id, existing.id);
    }

    #[test]
    fn cr2_sast_non_production_branch_no_match() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            branch: Some(Some("develop".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            source_tool: Some("Tenable WAS".to_string()),
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        let cr2_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-2").collect();
        assert!(
            cr2_matches.is_empty(),
            "Non-production branch should not fire CR-2"
        );
    }

    // -- CR-3 tests -----------------------------------------------------------

    #[test]
    fn cr3_sca_package_in_sast_file_path() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            source_tool: Some("JFrog Xray".to_string()),
            package_name: Some(Some("log4j".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            file_path: Some(Some("src/main/java/com/example/Log4jHelper.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing.clone()]);
        let cr3_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-3").collect();
        assert_eq!(cr3_matches.len(), 1);
        assert_eq!(cr3_matches[0].confidence, ConfidenceLevel::Medium);
        assert_eq!(cr3_matches[0].existing_finding_id, existing.id);
    }

    #[test]
    fn cr3_no_match_non_production() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            package_name: Some(Some("log4j".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            file_path: Some(Some("src/main/java/com/example/Log4jHelper.java".to_string())),
            branch: Some(Some("develop".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        let cr3_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-3").collect();
        assert!(cr3_matches.is_empty(), "Non-production branch should not fire CR-3");
    }

    // -- CR-4 tests -----------------------------------------------------------

    #[test]
    fn cr4_dast_endpoint_sast_handler_shared_cwe() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            source_tool: Some("Tenable WAS".to_string()),
            target_url: Some(Some("https://app.example.com/api/users".to_string())),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            file_path: Some(Some("src/main/java/com/example/UserController.java".to_string())),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing.clone()]);
        let cr4_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-4").collect();
        assert_eq!(cr4_matches.len(), 1);
        assert_eq!(cr4_matches[0].confidence, ConfidenceLevel::Medium);
        assert_eq!(cr4_matches[0].existing_finding_id, existing.id);
    }

    // -- CR-5 tests -----------------------------------------------------------

    #[test]
    fn cr5_same_rule_multiple_files() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/DaoA.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/DaoB.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing.clone()]);
        let cr5_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-5").collect();
        assert_eq!(cr5_matches.len(), 1);
        assert_eq!(cr5_matches[0].relationship_type, RelationshipType::GroupedUnder);
        assert_eq!(cr5_matches[0].confidence, ConfidenceLevel::High);
        assert_eq!(cr5_matches[0].existing_finding_id, existing.id);
    }

    #[test]
    fn cr5_different_branch_separate() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/DaoA.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/DaoA.java".to_string())),
            branch: Some(Some("develop".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        let cr5_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-5").collect();
        assert!(cr5_matches.is_empty(), "Different branches should not match for CR-5");
    }

    #[test]
    fn cr5_same_file_no_match() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        let cr5_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-5").collect();
        assert!(cr5_matches.is_empty(), "Same file should not match for CR-5");
    }

    // -- CR-6 tests -----------------------------------------------------------

    #[test]
    fn cr6_same_cwe_same_file() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            rule_id: Some(Some("java:S2077".to_string())),
            file_path: Some(Some("src/main/java/com/example/Dao.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing.clone()]);
        let cr6_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-6").collect();
        assert_eq!(cr6_matches.len(), 1);
        assert_eq!(cr6_matches[0].relationship_type, RelationshipType::GroupedUnder);
        assert_eq!(cr6_matches[0].confidence, ConfidenceLevel::High);
        assert_eq!(cr6_matches[0].existing_finding_id, existing.id);
    }

    #[test]
    fn cr6_different_file_no_match() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            rule_id: Some(Some("java:S3649".to_string())),
            file_path: Some(Some("src/main/java/com/example/DaoA.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            rule_id: Some(Some("java:S2077".to_string())),
            file_path: Some(Some("src/main/java/com/example/DaoB.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        let cr6_matches: Vec<_> = matches.iter().filter(|m| m.rule_name == "CR-6").collect();
        assert!(cr6_matches.is_empty(), "Different file should not fire CR-6");
    }

    // -- Multi-rule tests -----------------------------------------------------

    #[test]
    fn multiple_rules_can_fire_for_same_pair() {
        // SAST + DAST pair that shares CWE, where SAST is on main, DAST has URL,
        // SAST has file_path — should fire both CR-2 and CR-4
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Dast),
            source_tool: Some("Tenable WAS".to_string()),
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            target_url: Some(Some("https://app.example.com/xss".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            source_tool: Some("SonarQube".to_string()),
            cwe_ids: Some(vec!["CWE-79".to_string()]),
            file_path: Some(Some("src/main/java/com/example/XssHandler.java".to_string())),
            branch: Some(Some("main".to_string())),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        let rule_names: Vec<&str> = matches.iter().map(|m| m.rule_name.as_str()).collect();
        assert!(rule_names.contains(&"CR-2"), "CR-2 should fire");
        assert!(rule_names.contains(&"CR-4"), "CR-4 should fire");
    }

    #[test]
    fn no_matches_returns_empty() {
        let new = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sast),
            cwe_ids: Some(vec!["CWE-89".to_string()]),
            branch: Some(Some("feature/test".to_string())),
            ..Default::default()
        });
        let existing = make_candidate(CandidateOverrides {
            category: Some(FindingCategory::Sca),
            cve_ids: Some(vec!["CVE-2023-9999".to_string()]),
            ..Default::default()
        });

        let matches = correlate_finding(&new, &[existing]);
        assert!(matches.is_empty(), "Unrelated findings should produce no matches");
    }
}
