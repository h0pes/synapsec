//! App code pattern model for configurable regex-based app code extraction.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AppCodePattern {
    pub id: Uuid,
    pub source_tool: String,
    pub field_name: String,
    pub regex_pattern: String,
    pub priority: i32,
    pub description: Option<String>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
