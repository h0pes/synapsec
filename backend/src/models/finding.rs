//! Core finding model with enums shared across all finding types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// -- Enums matching PostgreSQL --

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "finding_category", rename_all = "SCREAMING_SNAKE_CASE")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FindingCategory {
    Sast,
    Sca,
    Dast,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "finding_status")]
pub enum FindingStatus {
    New,
    Confirmed,
    #[sqlx(rename = "In_Remediation")]
    #[serde(rename = "In_Remediation")]
    InRemediation,
    Mitigated,
    Verified,
    Closed,
    #[sqlx(rename = "False_Positive_Requested")]
    #[serde(rename = "False_Positive_Requested")]
    FalsePositiveRequested,
    #[sqlx(rename = "False_Positive")]
    #[serde(rename = "False_Positive")]
    FalsePositive,
    #[sqlx(rename = "Risk_Accepted")]
    #[serde(rename = "Risk_Accepted")]
    RiskAccepted,
    #[sqlx(rename = "Deferred_Remediation")]
    #[serde(rename = "Deferred_Remediation")]
    DeferredRemediation,
    Invalidated,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "severity_level")]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl SeverityLevel {
    /// Numeric weight for risk score calculation (0.0–1.0 scale).
    pub fn weight(&self) -> f32 {
        match self {
            Self::Critical => 1.0,
            Self::High => 0.8,
            Self::Medium => 0.5,
            Self::Low => 0.2,
            Self::Info => 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "sla_status")]
pub enum SlaStatus {
    #[sqlx(rename = "On_Track")]
    #[serde(rename = "On_Track")]
    OnTrack,
    #[sqlx(rename = "At_Risk")]
    #[serde(rename = "At_Risk")]
    AtRisk,
    Breached,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "confidence_level")]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "relationship_type")]
pub enum RelationshipType {
    #[sqlx(rename = "duplicate_of")]
    #[serde(rename = "duplicate_of")]
    DuplicateOf,
    #[sqlx(rename = "correlated_with")]
    #[serde(rename = "correlated_with")]
    CorrelatedWith,
    #[sqlx(rename = "grouped_under")]
    #[serde(rename = "grouped_under")]
    GroupedUnder,
    #[sqlx(rename = "superseded_by")]
    #[serde(rename = "superseded_by")]
    SupersededBy,
}

// -- Core Finding --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Finding {
    pub id: Uuid,
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    pub source_finding_id: String,
    pub finding_category: FindingCategory,
    pub title: String,
    pub description: String,
    pub normalized_severity: SeverityLevel,
    pub original_severity: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cwe_ids: serde_json::Value,
    pub cve_ids: serde_json::Value,
    pub owasp_category: Option<String>,
    pub status: FindingStatus,
    pub composite_risk_score: Option<f32>,
    pub confidence: Option<ConfidenceLevel>,
    pub fingerprint: String,
    pub application_id: Option<Uuid>,
    pub remediation_owner: Option<String>,
    pub office_owner: Option<String>,
    pub office_manager: Option<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status_changed_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub sla_due_date: Option<DateTime<Utc>>,
    pub sla_status: Option<SlaStatus>,
    pub tags: serde_json::Value,
    pub remediation_guidance: Option<String>,
    pub raw_finding: serde_json::Value,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFinding {
    pub source_tool: String,
    pub source_tool_version: Option<String>,
    pub source_finding_id: String,
    pub finding_category: FindingCategory,
    pub title: String,
    pub description: String,
    pub normalized_severity: SeverityLevel,
    pub original_severity: String,
    pub cvss_score: Option<f32>,
    pub cvss_vector: Option<String>,
    pub cwe_ids: Vec<String>,
    pub cve_ids: Vec<String>,
    pub owasp_category: Option<String>,
    pub confidence: Option<ConfidenceLevel>,
    pub fingerprint: String,
    pub application_id: Option<Uuid>,
    pub tags: Vec<String>,
    pub remediation_guidance: Option<String>,
    pub raw_finding: serde_json::Value,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateFinding {
    pub normalized_severity: Option<SeverityLevel>,
    pub status: Option<FindingStatus>,
    pub application_id: Option<Uuid>,
    pub remediation_owner: Option<String>,
    pub office_owner: Option<String>,
    pub office_manager: Option<String>,
    pub sla_due_date: Option<DateTime<Utc>>,
    pub sla_status: Option<SlaStatus>,
    pub tags: Option<Vec<String>>,
    pub remediation_guidance: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

/// Response DTO excluding raw_finding for list views.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingSummary {
    pub id: Uuid,
    pub source_tool: String,
    pub finding_category: FindingCategory,
    pub title: String,
    pub normalized_severity: SeverityLevel,
    pub status: FindingStatus,
    pub composite_risk_score: Option<f32>,
    pub fingerprint: String,
    pub application_id: Option<Uuid>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub sla_status: Option<SlaStatus>,
}

// -- Finding Relationships --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingRelationship {
    pub id: Uuid,
    pub source_finding_id: Uuid,
    pub target_finding_id: Uuid,
    pub relationship_type: RelationshipType,
    pub confidence: Option<ConfidenceLevel>,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub notes: Option<String>,
}

// -- Finding History --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingHistory {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub action: String,
    pub field_changed: Option<String>,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
    pub actor_id: Option<Uuid>,
    pub actor_name: String,
    pub justification: Option<String>,
    pub created_at: DateTime<Utc>,
}

// -- Finding Comments --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingComment {
    pub id: Uuid,
    pub finding_id: Uuid,
    pub author_id: Uuid,
    pub author_name: String,
    pub content: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateComment {
    pub content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_status_serialization() {
        let status = FindingStatus::InRemediation;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"In_Remediation\"");
    }

    #[test]
    fn finding_status_deserialization() {
        let status: FindingStatus =
            serde_json::from_str("\"False_Positive_Requested\"").unwrap();
        assert_eq!(status, FindingStatus::FalsePositiveRequested);
    }

    #[test]
    fn finding_category_serialization() {
        let cat = FindingCategory::Sast;
        let json = serde_json::to_string(&cat).unwrap();
        assert_eq!(json, "\"SAST\"");
    }

    #[test]
    fn severity_weight_ordering() {
        assert!(SeverityLevel::Critical.weight() > SeverityLevel::High.weight());
        assert!(SeverityLevel::High.weight() > SeverityLevel::Medium.weight());
        assert!(SeverityLevel::Medium.weight() > SeverityLevel::Low.weight());
        assert!(SeverityLevel::Low.weight() > SeverityLevel::Info.weight());
        assert_eq!(SeverityLevel::Info.weight(), 0.0);
    }

    #[test]
    fn relationship_type_serialization() {
        let rt = RelationshipType::DuplicateOf;
        let json = serde_json::to_string(&rt).unwrap();
        assert_eq!(json, "\"duplicate_of\"");
    }

    #[test]
    fn create_finding_round_trip() {
        let cf = CreateFinding {
            source_tool: "sonarqube".to_string(),
            source_tool_version: Some("10.4".to_string()),
            source_finding_id: "AX123".to_string(),
            finding_category: FindingCategory::Sast,
            title: "SQL Injection".to_string(),
            description: "Possible SQL injection".to_string(),
            normalized_severity: SeverityLevel::High,
            original_severity: "MAJOR".to_string(),
            cvss_score: Some(8.5),
            cvss_vector: None,
            cwe_ids: vec!["CWE-89".to_string()],
            cve_ids: vec![],
            owasp_category: Some("A03:2021".to_string()),
            confidence: Some(ConfidenceLevel::High),
            fingerprint: "abc123".to_string(),
            application_id: None,
            tags: vec!["auto-triaged".to_string()],
            remediation_guidance: None,
            raw_finding: serde_json::json!({}),
            metadata: serde_json::json!({}),
        };
        let json = serde_json::to_string(&cf).unwrap();
        let deserialized: CreateFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.source_tool, "sonarqube");
        assert_eq!(deserialized.cwe_ids, vec!["CWE-89"]);
    }
}
