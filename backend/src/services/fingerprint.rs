//! Fingerprint computation for deduplication across finding categories.
//!
//! Each category uses a deterministic hash of identifying fields that remain
//! stable across re-scans, excluding volatile fields like line numbers (SAST)
//! or CWE IDs (DAST) that may change without the underlying issue changing.

use sha2::{Digest, Sha256};

/// Compute a SAST finding fingerprint.
///
/// Inputs: app_code, file_path, rule_id, branch.
/// Excludes line_number because code edits shift lines without changing the issue.
pub fn compute_sast(app_code: &str, file_path: &str, rule_id: &str, branch: &str) -> String {
    hash(&format!("SAST:{app_code}:{file_path}:{rule_id}:{branch}"))
}

/// Compute an SCA finding fingerprint.
///
/// Inputs: app_code, package_name, package_version, cve_id.
/// Includes CVE because the same package+version may have multiple CVEs.
pub fn compute_sca(
    app_code: &str,
    package_name: &str,
    package_version: &str,
    cve_id: &str,
) -> String {
    hash(&format!(
        "SCA:{app_code}:{package_name}:{package_version}:{cve_id}"
    ))
}

/// Compute a DAST finding fingerprint.
///
/// Inputs: app_code, target_url, http_method, parameter.
/// Excludes CWE because the same endpoint vulnerability may be reclassified.
pub fn compute_dast(
    app_code: &str,
    target_url: &str,
    http_method: &str,
    parameter: &str,
) -> String {
    hash(&format!(
        "DAST:{app_code}:{target_url}:{http_method}:{parameter}"
    ))
}

/// SHA-256 hash a string and return hex-encoded digest.
fn hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sast_same_inputs_same_fingerprint() {
        let fp1 = compute_sast("APP1", "src/main.rs", "sqli-rule", "main");
        let fp2 = compute_sast("APP1", "src/main.rs", "sqli-rule", "main");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn sast_different_file_different_fingerprint() {
        let fp1 = compute_sast("APP1", "src/main.rs", "sqli-rule", "main");
        let fp2 = compute_sast("APP1", "src/other.rs", "sqli-rule", "main");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn sast_different_app_different_fingerprint() {
        let fp1 = compute_sast("APP1", "src/main.rs", "sqli-rule", "main");
        let fp2 = compute_sast("APP2", "src/main.rs", "sqli-rule", "main");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn sca_same_inputs_same_fingerprint() {
        let fp1 = compute_sca("APP1", "lodash", "4.17.20", "CVE-2021-23337");
        let fp2 = compute_sca("APP1", "lodash", "4.17.20", "CVE-2021-23337");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn sca_different_cve_different_fingerprint() {
        let fp1 = compute_sca("APP1", "lodash", "4.17.20", "CVE-2021-23337");
        let fp2 = compute_sca("APP1", "lodash", "4.17.20", "CVE-2021-99999");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn dast_same_inputs_same_fingerprint() {
        let fp1 = compute_dast("APP1", "/api/login", "POST", "username");
        let fp2 = compute_dast("APP1", "/api/login", "POST", "username");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn dast_different_parameter_different_fingerprint() {
        let fp1 = compute_dast("APP1", "/api/login", "POST", "username");
        let fp2 = compute_dast("APP1", "/api/login", "POST", "password");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn fingerprint_is_hex_sha256() {
        let fp = compute_sast("APP1", "file.rs", "rule1", "main");
        assert_eq!(fp.len(), 64); // SHA-256 hex = 64 chars
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn cross_category_no_collision() {
        // Same identifying fields but different category prefix
        let sast = compute_sast("APP1", "target", "rule", "param");
        let dast = compute_dast("APP1", "target", "rule", "param");
        assert_ne!(sast, dast);
    }
}
