//! SCA-specific finding layer model.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "dependency_type")]
pub enum DependencyType {
    Direct,
    Transitive,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "exploit_maturity")]
pub enum ExploitMaturity {
    #[sqlx(rename = "Proof_of_Concept")]
    ProofOfConcept,
    Functional,
    Weaponized,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingSca {
    pub finding_id: Uuid,
    pub package_name: String,
    pub package_version: String,
    pub package_type: Option<String>,
    pub fixed_version: Option<String>,
    pub dependency_type: Option<DependencyType>,
    pub dependency_path: Option<String>,
    pub license: Option<String>,
    pub license_risk: Option<String>,
    pub sbom_reference: Option<String>,
    pub epss_score: Option<f32>,
    pub known_exploited: Option<bool>,
    pub exploit_maturity: Option<ExploitMaturity>,
    pub affected_artifact: Option<String>,
    pub build_project: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFindingSca {
    pub package_name: String,
    pub package_version: String,
    pub package_type: Option<String>,
    pub fixed_version: Option<String>,
    pub dependency_type: Option<DependencyType>,
    pub dependency_path: Option<String>,
    pub license: Option<String>,
    pub license_risk: Option<String>,
    pub sbom_reference: Option<String>,
    pub epss_score: Option<f32>,
    pub known_exploited: Option<bool>,
    pub exploit_maturity: Option<ExploitMaturity>,
    pub affected_artifact: Option<String>,
    pub build_project: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exploit_maturity_serialization() {
        let em = ExploitMaturity::ProofOfConcept;
        let json = serde_json::to_string(&em).unwrap();
        assert_eq!(json, "\"ProofOfConcept\"");
    }

    #[test]
    fn dependency_type_serialization() {
        let dt = DependencyType::Transitive;
        let json = serde_json::to_string(&dt).unwrap();
        assert_eq!(json, "\"Transitive\"");
    }
}
