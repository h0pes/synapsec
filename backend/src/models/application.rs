//! Application registry model with corporate APM enrichment.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "asset_criticality")]
pub enum AssetCriticality {
    #[sqlx(rename = "Very_High")]
    VeryHigh,
    High,
    #[sqlx(rename = "Medium_High")]
    MediumHigh,
    Medium,
    #[sqlx(rename = "Medium_Low")]
    MediumLow,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "asset_tier")]
pub enum AssetTier {
    #[sqlx(rename = "Tier_1")]
    Tier1,
    #[sqlx(rename = "Tier_2")]
    Tier2,
    #[sqlx(rename = "Tier_3")]
    Tier3,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "exposure_level")]
pub enum ExposureLevel {
    #[sqlx(rename = "Internet_Facing")]
    InternetFacing,
    #[serde(rename = "DMZ")]
    Dmz,
    Internal,
    #[sqlx(rename = "Dev_Test")]
    DevTest,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "data_classification")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(type_name = "app_status")]
pub enum AppStatus {
    Active,
    Deprecated,
    Decommissioned,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Application {
    pub id: Uuid,
    pub app_name: String,
    pub app_code: String,
    pub description: Option<String>,
    pub criticality: Option<AssetCriticality>,
    pub tier: AssetTier,
    pub business_unit: Option<String>,
    pub business_owner: Option<String>,
    pub technical_owner: Option<String>,
    pub security_champion: Option<String>,
    pub technology_stack: serde_json::Value,
    pub deployment_environment: serde_json::Value,
    pub exposure: Option<ExposureLevel>,
    pub data_classification: Option<DataClassification>,
    pub regulatory_scope: serde_json::Value,
    pub repository_urls: serde_json::Value,
    pub scanner_project_ids: serde_json::Value,
    pub status: AppStatus,
    pub is_verified: bool,

    // Corporate APM enrichment
    pub ssa_code: Option<String>,
    pub ssa_name: Option<String>,
    pub functional_reference_email: Option<String>,
    pub technical_reference_email: Option<String>,
    pub effective_office_owner: Option<String>,
    pub effective_office_name: Option<String>,
    pub confidentiality_level: Option<String>,
    pub integrity_level: Option<String>,
    pub availability_level: Option<String>,
    pub is_dora_fei: Option<bool>,
    pub is_gdpr_subject: Option<bool>,
    pub has_pci_data: Option<bool>,
    pub is_psd2_relevant: Option<bool>,
    pub apm_metadata: serde_json::Value,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateApplication {
    pub app_name: String,
    pub app_code: String,
    pub description: Option<String>,
    pub criticality: Option<AssetCriticality>,
    pub tier: Option<AssetTier>,
    pub business_unit: Option<String>,
    pub business_owner: Option<String>,
    pub technical_owner: Option<String>,
    pub security_champion: Option<String>,
    pub technology_stack: Option<Vec<String>>,
    pub exposure: Option<ExposureLevel>,
    pub data_classification: Option<DataClassification>,
    pub repository_urls: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UpdateApplication {
    pub app_name: Option<String>,
    pub description: Option<String>,
    pub criticality: Option<AssetCriticality>,
    pub tier: Option<AssetTier>,
    pub business_unit: Option<String>,
    pub business_owner: Option<String>,
    pub technical_owner: Option<String>,
    pub security_champion: Option<String>,
    pub technology_stack: Option<Vec<String>>,
    pub exposure: Option<ExposureLevel>,
    pub data_classification: Option<DataClassification>,
    pub repository_urls: Option<Vec<String>>,
    pub status: Option<AppStatus>,
}

/// Summary DTO for list views.
#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct ApplicationSummary {
    pub id: Uuid,
    pub app_name: String,
    pub app_code: String,
    pub criticality: Option<AssetCriticality>,
    pub tier: AssetTier,
    pub business_unit: Option<String>,
    pub status: AppStatus,
    pub is_verified: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asset_criticality_serialization() {
        let c = AssetCriticality::VeryHigh;
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(json, "\"VeryHigh\"");
    }

    #[test]
    fn app_status_round_trip() {
        let status = AppStatus::Deprecated;
        let json = serde_json::to_string(&status).unwrap();
        let deserialized: AppStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, AppStatus::Deprecated);
    }

    #[test]
    fn create_application_minimal() {
        let ca = CreateApplication {
            app_name: "Test App".to_string(),
            app_code: "TSTA1".to_string(),
            description: None,
            criticality: None,
            tier: None,
            business_unit: None,
            business_owner: None,
            technical_owner: None,
            security_champion: None,
            technology_stack: None,
            exposure: None,
            data_classification: None,
            repository_urls: None,
        };
        let json = serde_json::to_string(&ca).unwrap();
        assert!(json.contains("TSTA1"));
    }
}
