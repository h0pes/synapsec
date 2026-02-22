//! DAST-specific finding layer model.

use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct FindingDast {
    pub finding_id: Uuid,
    pub target_url: String,
    pub http_method: Option<String>,
    pub parameter: Option<String>,
    pub attack_vector: Option<String>,
    pub request_evidence: Option<String>,
    pub response_evidence: Option<String>,
    pub authentication_required: Option<bool>,
    pub authentication_context: Option<String>,
    pub web_application_name: Option<String>,
    pub scan_policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateFindingDast {
    pub target_url: String,
    pub http_method: Option<String>,
    pub parameter: Option<String>,
    pub attack_vector: Option<String>,
    pub request_evidence: Option<String>,
    pub response_evidence: Option<String>,
    pub authentication_required: Option<bool>,
    pub authentication_context: Option<String>,
    pub web_application_name: Option<String>,
    pub scan_policy: Option<String>,
}
