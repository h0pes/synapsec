//! Correlation rule model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::models::finding::ConfidenceLevel;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct CorrelationRule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub confidence: ConfidenceLevel,
    pub is_active: bool,
    pub priority: i32,
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateCorrelationRule {
    pub name: String,
    pub description: Option<String>,
    pub rule_type: String,
    pub conditions: serde_json::Value,
    pub confidence: Option<ConfidenceLevel>,
    pub priority: Option<i32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateCorrelationRule {
    pub name: Option<String>,
    pub description: Option<String>,
    pub rule_type: Option<String>,
    pub conditions: Option<serde_json::Value>,
    pub confidence: Option<ConfidenceLevel>,
    pub is_active: Option<bool>,
    pub priority: Option<i32>,
}
