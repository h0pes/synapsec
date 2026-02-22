//! Audit log, ingestion log, and system config models.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

// -- Audit Log --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditLog {
    pub id: Uuid,
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub action: String,
    pub actor_id: Option<Uuid>,
    pub actor_name: String,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateAuditLog {
    pub entity_type: String,
    pub entity_id: Option<Uuid>,
    pub action: String,
    pub actor_id: Option<Uuid>,
    pub actor_name: String,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
}

// -- Ingestion Log --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct IngestionLog {
    pub id: Uuid,
    pub source_tool: String,
    pub ingestion_type: String,
    pub file_name: Option<String>,
    pub total_records: i32,
    pub new_findings: i32,
    pub updated_findings: i32,
    pub duplicates: i32,
    pub errors: i32,
    pub quarantined: i32,
    pub status: String,
    pub error_details: Option<serde_json::Value>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub initiated_by: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIngestionLog {
    pub source_tool: String,
    pub ingestion_type: String,
    pub file_name: Option<String>,
    pub initiated_by: Option<Uuid>,
}

// -- Triage Rules --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TriageRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub conditions: serde_json::Value,
    pub is_active: bool,
    pub priority: i32,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTriageRule {
    pub name: String,
    pub description: Option<String>,
    pub conditions: serde_json::Value,
    pub is_active: Option<bool>,
    pub priority: Option<i32>,
}

// -- System Config --

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SystemConfig {
    pub key: String,
    pub value: serde_json::Value,
    pub description: Option<String>,
    pub updated_by: Option<Uuid>,
    pub updated_at: DateTime<Utc>,
}

// -- Scanner API Keys --

#[derive(Debug, Clone, FromRow)]
pub struct ScannerApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub scanner_name: String,
    pub key_label: String,
    pub encrypted_key: String,
    pub api_url: Option<String>,
    pub is_active: bool,
    pub last_used: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Response DTO — excludes encrypted_key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerApiKeyResponse {
    pub id: Uuid,
    pub scanner_name: String,
    pub key_label: String,
    pub api_url: Option<String>,
    pub is_active: bool,
    pub last_used: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<ScannerApiKey> for ScannerApiKeyResponse {
    fn from(k: ScannerApiKey) -> Self {
        Self {
            id: k.id,
            scanner_name: k.scanner_name,
            key_label: k.key_label,
            api_url: k.api_url,
            is_active: k.is_active,
            last_used: k.last_used,
            created_at: k.created_at,
        }
    }
}
