//! Application registry service: CRUD, bulk import, and corporate APM CSV/XLSX import.

use calamine::{open_workbook_from_rs, Reader, Xlsx};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::io::Cursor;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::application::{
    AppStatus, Application, ApplicationSummary, AssetCriticality, CreateApplication,
    UpdateApplication,
};
use crate::models::pagination::{PagedResult, Pagination};

/// Filters for listing applications.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct ApplicationFilters {
    pub status: Option<AppStatus>,
    pub criticality: Option<AssetCriticality>,
    pub business_unit: Option<String>,
    pub ssa_code: Option<String>,
    pub is_dora_fei: Option<bool>,
    pub is_gdpr_subject: Option<bool>,
    pub has_pci_data: Option<bool>,
    pub is_psd2_relevant: Option<bool>,
    pub search: Option<String>,
}

/// Result of a bulk import operation.
#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub total: usize,
    pub created: usize,
    pub updated: usize,
    pub errors: Vec<ImportError>,
}

/// Individual import error.
#[derive(Debug, Serialize)]
pub struct ImportError {
    pub row: usize,
    pub app_code: Option<String>,
    pub message: String,
}

/// APM CSV import result with additional detail.
#[derive(Debug, Serialize)]
pub struct ApmImportResult {
    pub total: usize,
    pub created: usize,
    pub updated: usize,
    pub skipped: usize,
    pub errors: Vec<ImportError>,
}

/// Configurable CSV-to-field mapping for corporate APM imports.
#[derive(Debug, Clone, Deserialize)]
pub struct ApmFieldMapping {
    #[serde(default = "default_app_code_column")]
    pub app_code_column: String,
    #[serde(default = "default_app_name_column")]
    pub app_name_column: String,
    #[serde(default = "default_ssa_code_column")]
    pub ssa_code_column: String,
    #[serde(default = "default_ssa_name_column")]
    pub ssa_name_column: String,
    #[serde(default = "default_criticality_column")]
    pub criticality_column: String,
    #[serde(default = "default_functional_ref_column")]
    pub functional_ref_email_column: String,
    #[serde(default = "default_technical_ref_column")]
    pub technical_ref_email_column: String,
    #[serde(default = "default_office_owner_column")]
    pub office_owner_column: String,
    #[serde(default = "default_office_name_column")]
    pub office_name_column: String,
    #[serde(default = "default_struttura_reale_owner_column")]
    pub struttura_reale_owner_column: String,
    #[serde(default = "default_struttura_reale_name_column")]
    pub struttura_reale_name_column: String,
    #[serde(default = "default_confidentiality_column")]
    pub confidentiality_column: String,
    #[serde(default = "default_integrity_column")]
    pub integrity_column: String,
    #[serde(default = "default_availability_column")]
    pub availability_column: String,
}

fn default_app_code_column() -> String {
    "CODICE ACRONIMO".to_string()
}
fn default_app_name_column() -> String {
    "DESCRIZIONE ACRONIMO".to_string()
}
fn default_ssa_code_column() -> String {
    "CODICE SSA".to_string()
}
fn default_ssa_name_column() -> String {
    "DESCRIZIONE SSA".to_string()
}
fn default_criticality_column() -> String {
    "ACRONYM CRITICALITY (SYNTHESIS LEVEL)".to_string()
}
fn default_functional_ref_column() -> String {
    "REFERENTE FUNZIONALE EMAIL".to_string()
}
fn default_technical_ref_column() -> String {
    "REFERENTE TECNICO EMAIL".to_string()
}
fn default_office_owner_column() -> String {
    "RESPONSABILE UFFICIO NOMINATIVO".to_string()
}
fn default_office_name_column() -> String {
    "UFFICIO NOMINATIVO".to_string()
}
fn default_struttura_reale_owner_column() -> String {
    "RESPONSABILE STRUTTURA REALE DI GESTIONE".to_string()
}
fn default_struttura_reale_name_column() -> String {
    "STRUTTURA REALE DI GESTIONE NOMINATIVO".to_string()
}
fn default_confidentiality_column() -> String {
    "RISERVATEZZA".to_string()
}
fn default_integrity_column() -> String {
    "INTEGRITA".to_string()
}
fn default_availability_column() -> String {
    "DISPONIBILITA".to_string()
}

impl Default for ApmFieldMapping {
    fn default() -> Self {
        Self {
            app_code_column: default_app_code_column(),
            app_name_column: default_app_name_column(),
            ssa_code_column: default_ssa_code_column(),
            ssa_name_column: default_ssa_name_column(),
            criticality_column: default_criticality_column(),
            functional_ref_email_column: default_functional_ref_column(),
            technical_ref_email_column: default_technical_ref_column(),
            office_owner_column: default_office_owner_column(),
            office_name_column: default_office_name_column(),
            struttura_reale_owner_column: default_struttura_reale_owner_column(),
            struttura_reale_name_column: default_struttura_reale_name_column(),
            confidentiality_column: default_confidentiality_column(),
            integrity_column: default_integrity_column(),
            availability_column: default_availability_column(),
        }
    }
}

/// Create a new application.
pub async fn create(pool: &PgPool, input: &CreateApplication) -> Result<Application, AppError> {
    let tech_stack = input
        .technology_stack
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap_or_default())
        .unwrap_or(serde_json::json!([]));
    let repo_urls = input
        .repository_urls
        .as_ref()
        .map(|v| serde_json::to_value(v).unwrap_or_default())
        .unwrap_or(serde_json::json!([]));

    let app = sqlx::query_as::<_, Application>(
        r#"
        INSERT INTO applications (app_name, app_code, description, criticality, tier,
            business_unit, business_owner, technical_owner, security_champion,
            technology_stack, repository_urls, exposure, data_classification)
        VALUES ($1, $2, $3, $4, COALESCE($5, 'Tier_2'), $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING *
        "#,
    )
    .bind(&input.app_name)
    .bind(&input.app_code)
    .bind(&input.description)
    .bind(&input.criticality)
    .bind(&input.tier)
    .bind(&input.business_unit)
    .bind(&input.business_owner)
    .bind(&input.technical_owner)
    .bind(&input.security_champion)
    .bind(&tech_stack)
    .bind(&repo_urls)
    .bind(&input.exposure)
    .bind(&input.data_classification)
    .fetch_one(pool)
    .await
    .map_err(|e| match e {
        sqlx::Error::Database(ref db_err) if db_err.is_unique_violation() => {
            AppError::Conflict(format!("Application with code '{}' already exists", input.app_code))
        }
        _ => AppError::Database(e),
    })?;

    Ok(app)
}

/// Find application by ID.
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Application, AppError> {
    sqlx::query_as::<_, Application>("SELECT * FROM applications WHERE id = $1")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| AppError::NotFound("Application not found".to_string()))
}

/// Find application by app_code.
pub async fn find_by_app_code(
    pool: &PgPool,
    app_code: &str,
) -> Result<Option<Application>, AppError> {
    let app =
        sqlx::query_as::<_, Application>("SELECT * FROM applications WHERE app_code = $1")
            .bind(app_code)
            .fetch_optional(pool)
            .await?;
    Ok(app)
}

/// Find or create a stub application for a given app_code.
///
/// Used during ingestion when a finding references an unknown application.
/// Creates an unverified stub that can be enriched later.
pub async fn find_or_create_stub(
    pool: &PgPool,
    app_code: &str,
    source_tool: &str,
) -> Result<Application, AppError> {
    if let Some(existing) = find_by_app_code(pool, app_code).await? {
        return Ok(existing);
    }

    let app = sqlx::query_as::<_, Application>(
        r#"
        INSERT INTO applications (app_name, app_code, is_verified, description)
        VALUES ($1, $2, false, $3)
        ON CONFLICT (app_code) DO UPDATE SET updated_at = NOW()
        RETURNING *
        "#,
    )
    .bind(format!("[Stub] {app_code}"))
    .bind(app_code)
    .bind(format!("Auto-created stub from {source_tool} ingestion"))
    .fetch_one(pool)
    .await?;

    Ok(app)
}

/// List applications with filters and pagination.
pub async fn list(
    pool: &PgPool,
    filters: &ApplicationFilters,
    pagination: &Pagination,
) -> Result<PagedResult<ApplicationSummary>, AppError> {
    let mut conditions: Vec<String> = Vec::new();
    let mut param_index = 0u32;

    // Build dynamic WHERE clauses
    if filters.status.is_some() {
        param_index += 1;
        conditions.push(format!("status = ${param_index}"));
    }
    if filters.criticality.is_some() {
        param_index += 1;
        conditions.push(format!("criticality = ${param_index}"));
    }
    if filters.business_unit.is_some() {
        param_index += 1;
        conditions.push(format!("business_unit ILIKE ${param_index}"));
    }
    if filters.ssa_code.is_some() {
        param_index += 1;
        conditions.push(format!("ssa_code = ${param_index}"));
    }
    if filters.is_dora_fei.is_some() {
        param_index += 1;
        conditions.push(format!("is_dora_fei = ${param_index}"));
    }
    if filters.is_gdpr_subject.is_some() {
        param_index += 1;
        conditions.push(format!("is_gdpr_subject = ${param_index}"));
    }
    if filters.has_pci_data.is_some() {
        param_index += 1;
        conditions.push(format!("has_pci_data = ${param_index}"));
    }
    if filters.is_psd2_relevant.is_some() {
        param_index += 1;
        conditions.push(format!("is_psd2_relevant = ${param_index}"));
    }
    if filters.search.is_some() {
        param_index += 1;
        conditions.push(format!(
            "(app_name ILIKE ${param_index} OR app_code ILIKE ${param_index})"
        ));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    // Count query
    let count_sql = format!("SELECT COUNT(*) as count FROM applications {where_clause}");
    // Data query
    let data_sql = format!(
        "SELECT id, app_name, app_code, criticality, tier, business_unit, status, is_verified \
         FROM applications {where_clause} ORDER BY app_name ASC LIMIT {} OFFSET {}",
        pagination.limit(),
        pagination.offset()
    );

    // Build and execute count query with dynamic binds
    let mut count_query = sqlx::query_scalar::<_, i64>(&count_sql);
    let mut data_query = sqlx::query_as::<_, ApplicationSummary>(&data_sql);

    // Bind parameters in the same order for both queries
    macro_rules! bind_both {
        ($val:expr) => {
            count_query = count_query.bind($val);
            data_query = data_query.bind($val);
        };
    }

    if let Some(ref status) = filters.status {
        bind_both!(status);
    }
    if let Some(ref criticality) = filters.criticality {
        bind_both!(criticality);
    }
    if let Some(ref bu) = filters.business_unit {
        let pattern = format!("%{bu}%");
        count_query = count_query.bind(pattern.clone());
        data_query = data_query.bind(pattern);
    }
    if let Some(ref ssa) = filters.ssa_code {
        bind_both!(ssa);
    }
    if let Some(ref dora) = filters.is_dora_fei {
        bind_both!(dora);
    }
    if let Some(ref gdpr) = filters.is_gdpr_subject {
        bind_both!(gdpr);
    }
    if let Some(ref pci) = filters.has_pci_data {
        bind_both!(pci);
    }
    if let Some(ref psd2) = filters.is_psd2_relevant {
        bind_both!(psd2);
    }
    if let Some(ref search) = filters.search {
        let pattern = format!("%{search}%");
        count_query = count_query.bind(pattern.clone());
        data_query = data_query.bind(pattern);
    }

    let total = count_query.fetch_one(pool).await?;
    let items = data_query.fetch_all(pool).await?;

    Ok(PagedResult::new(items, total, pagination))
}

/// List unverified stub applications.
pub async fn list_unverified(
    pool: &PgPool,
    pagination: &Pagination,
) -> Result<PagedResult<ApplicationSummary>, AppError> {
    let total = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM applications WHERE is_verified = false",
    )
    .fetch_one(pool)
    .await?;

    let items = sqlx::query_as::<_, ApplicationSummary>(
        "SELECT id, app_name, app_code, criticality, tier, business_unit, status, is_verified \
         FROM applications WHERE is_verified = false \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )
    .bind(pagination.limit())
    .bind(pagination.offset())
    .fetch_all(pool)
    .await?;

    Ok(PagedResult::new(items, total, pagination))
}

/// Update an application by ID.
pub async fn update(
    pool: &PgPool,
    id: Uuid,
    input: &UpdateApplication,
) -> Result<Application, AppError> {
    // Verify application exists
    let existing = find_by_id(pool, id).await?;

    let app = sqlx::query_as::<_, Application>(
        r#"
        UPDATE applications SET
            app_name = COALESCE($2, app_name),
            description = COALESCE($3, description),
            criticality = COALESCE($4, criticality),
            tier = COALESCE($5, tier),
            business_unit = COALESCE($6, business_unit),
            business_owner = COALESCE($7, business_owner),
            technical_owner = COALESCE($8, technical_owner),
            security_champion = COALESCE($9, security_champion),
            technology_stack = COALESCE($10, technology_stack),
            exposure = COALESCE($11, exposure),
            data_classification = COALESCE($12, data_classification),
            repository_urls = COALESCE($13, repository_urls),
            status = COALESCE($14, status),
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
        "#,
    )
    .bind(existing.id)
    .bind(&input.app_name)
    .bind(&input.description)
    .bind(&input.criticality)
    .bind(&input.tier)
    .bind(&input.business_unit)
    .bind(&input.business_owner)
    .bind(&input.technical_owner)
    .bind(&input.security_champion)
    .bind(input.technology_stack.as_ref().map(|v| serde_json::to_value(v).unwrap_or_default()))
    .bind(&input.exposure)
    .bind(&input.data_classification)
    .bind(input.repository_urls.as_ref().map(|v| serde_json::to_value(v).unwrap_or_default()))
    .bind(&input.status)
    .fetch_one(pool)
    .await?;

    Ok(app)
}

/// Bulk import applications from a JSON array.
pub async fn import_bulk(
    pool: &PgPool,
    apps: &[CreateApplication],
) -> Result<ImportResult, AppError> {
    let mut created = 0usize;
    let mut updated = 0usize;
    let mut errors = Vec::new();

    for (i, input) in apps.iter().enumerate() {
        match find_by_app_code(pool, &input.app_code).await? {
            Some(existing) => {
                let update = UpdateApplication {
                    app_name: Some(input.app_name.clone()),
                    description: input.description.clone(),
                    criticality: input.criticality.clone(),
                    tier: input.tier.clone(),
                    business_unit: input.business_unit.clone(),
                    business_owner: input.business_owner.clone(),
                    technical_owner: input.technical_owner.clone(),
                    security_champion: input.security_champion.clone(),
                    technology_stack: input.technology_stack.clone(),
                    exposure: input.exposure.clone(),
                    data_classification: input.data_classification.clone(),
                    repository_urls: input.repository_urls.clone(),
                    status: None,
                };
                match self::update(pool, existing.id, &update).await {
                    Ok(_) => updated += 1,
                    Err(e) => errors.push(ImportError {
                        row: i + 1,
                        app_code: Some(input.app_code.clone()),
                        message: e.to_string(),
                    }),
                }
            }
            None => match create(pool, input).await {
                Ok(_) => created += 1,
                Err(e) => errors.push(ImportError {
                    row: i + 1,
                    app_code: Some(input.app_code.clone()),
                    message: e.to_string(),
                }),
            },
        }
    }

    Ok(ImportResult {
        total: apps.len(),
        created,
        updated,
        errors,
    })
}

/// Import format for APM files.
#[derive(Debug, Clone, PartialEq)]
pub enum ApmFormat {
    Csv,
    Xlsx,
}

impl ApmFormat {
    /// Detect format from filename extension.
    pub fn from_filename(filename: &str) -> Option<Self> {
        let lower = filename.to_lowercase();
        if lower.ends_with(".csv") {
            Some(Self::Csv)
        } else if lower.ends_with(".xlsx") || lower.ends_with(".xls") {
            Some(Self::Xlsx)
        } else {
            None
        }
    }
}

/// Parse and import applications from a corporate APM file (CSV or XLSX).
///
/// Implements the Struttura Reale ownership override: if "Struttura Reale"
/// fields are populated and differ from the standard office, the Struttura
/// Reale owner becomes the effective_office_owner.
pub async fn import_apm(
    pool: &PgPool,
    data: &[u8],
    mapping: &ApmFieldMapping,
    format: &ApmFormat,
) -> Result<ApmImportResult, AppError> {
    // Extract rows as Vec<HashMap<header, value>> from either format
    let rows = match format {
        ApmFormat::Csv => parse_csv_rows(data)?,
        ApmFormat::Xlsx => parse_xlsx_rows(data)?,
    };

    let mut created = 0usize;
    let mut updated = 0usize;
    let mut skipped = 0usize;
    let mut errors = Vec::new();

    for (i, row) in rows.iter().enumerate() {
        let get_field = |col: &str| -> Option<String> {
            row.get(col)
                .filter(|v| !v.trim().is_empty())
                .map(|v| v.trim().to_string())
        };

        let app_code = match get_field(&mapping.app_code_column) {
            Some(code) => code,
            None => {
                skipped += 1;
                continue;
            }
        };

        let app_name = get_field(&mapping.app_name_column)
            .unwrap_or_else(|| format!("[APM] {app_code}"));

        // Criticality mapping: fallback to Medium when empty
        let criticality = map_criticality(get_field(&mapping.criticality_column).as_deref());

        // Struttura Reale ownership override logic
        let office_owner = get_field(&mapping.office_owner_column);
        let office_name = get_field(&mapping.office_name_column);
        let struttura_owner = get_field(&mapping.struttura_reale_owner_column);
        let struttura_name = get_field(&mapping.struttura_reale_name_column);

        let (effective_owner, effective_name) =
            resolve_effective_owner(&office_owner, &office_name, &struttura_owner, &struttura_name);

        // Regulatory flags — treat non-empty, non-"N" values as true
        let is_dora_fei = get_field("DORA FEI").map(|v| is_flag_true(&v));
        let is_gdpr_subject = get_field("GDPR").map(|v| is_flag_true(&v));
        let has_pci_data = get_field("PCI").map(|v| is_flag_true(&v));
        let is_psd2_relevant = get_field("PSD2").map(|v| is_flag_true(&v));

        // Store entire row as JSONB metadata
        let row_metadata = serde_json::to_value(row).unwrap_or_default();

        // Upsert by app_code
        let result = sqlx::query_as::<_, Application>(
            r#"
            INSERT INTO applications (
                app_name, app_code, criticality, tier,
                ssa_code, ssa_name,
                functional_reference_email, technical_reference_email,
                effective_office_owner, effective_office_name,
                confidentiality_level, integrity_level, availability_level,
                is_dora_fei, is_gdpr_subject, has_pci_data, is_psd2_relevant,
                apm_metadata, is_verified
            )
            VALUES ($1, $2, $3, 'Tier_2', $4, $5, $6, $7, $8, $9, $10, $11, $12,
                    COALESCE($13, false), COALESCE($14, false), COALESCE($15, false), COALESCE($16, false),
                    $17, true)
            ON CONFLICT (app_code) DO UPDATE SET
                app_name = EXCLUDED.app_name,
                criticality = EXCLUDED.criticality,
                ssa_code = EXCLUDED.ssa_code,
                ssa_name = EXCLUDED.ssa_name,
                functional_reference_email = EXCLUDED.functional_reference_email,
                technical_reference_email = EXCLUDED.technical_reference_email,
                effective_office_owner = EXCLUDED.effective_office_owner,
                effective_office_name = EXCLUDED.effective_office_name,
                confidentiality_level = EXCLUDED.confidentiality_level,
                integrity_level = EXCLUDED.integrity_level,
                availability_level = EXCLUDED.availability_level,
                is_dora_fei = EXCLUDED.is_dora_fei,
                is_gdpr_subject = EXCLUDED.is_gdpr_subject,
                has_pci_data = EXCLUDED.has_pci_data,
                is_psd2_relevant = EXCLUDED.is_psd2_relevant,
                apm_metadata = EXCLUDED.apm_metadata,
                is_verified = true,
                updated_at = NOW()
            RETURNING *
            "#,
        )
        .bind(&app_name)
        .bind(&app_code)
        .bind(&criticality)
        .bind(get_field(&mapping.ssa_code_column))
        .bind(get_field(&mapping.ssa_name_column))
        .bind(get_field(&mapping.functional_ref_email_column))
        .bind(get_field(&mapping.technical_ref_email_column))
        .bind(&effective_owner)
        .bind(&effective_name)
        .bind(get_field(&mapping.confidentiality_column))
        .bind(get_field(&mapping.integrity_column))
        .bind(get_field(&mapping.availability_column))
        .bind(is_dora_fei)
        .bind(is_gdpr_subject)
        .bind(has_pci_data)
        .bind(is_psd2_relevant)
        .bind(&row_metadata)
        .fetch_one(pool)
        .await;

        match result {
            Ok(app) => {
                if app.created_at == app.updated_at {
                    created += 1;
                } else {
                    updated += 1;
                }
            }
            Err(e) => errors.push(ImportError {
                row: i + 2,
                app_code: Some(app_code),
                message: e.to_string(),
            }),
        }
    }

    Ok(ApmImportResult {
        total: created + updated + skipped + errors.len(),
        created,
        updated,
        skipped,
        errors,
    })
}

/// Parse CSV data into a list of header→value maps.
fn parse_csv_rows(
    data: &[u8],
) -> Result<Vec<std::collections::HashMap<String, String>>, AppError> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(true)
        .from_reader(data);

    let headers: Vec<String> = reader
        .headers()
        .map_err(|e| AppError::Validation(format!("Invalid CSV headers: {e}")))?
        .iter()
        .map(|h| h.to_string())
        .collect();

    let mut rows = Vec::new();
    for result in reader.records() {
        let record =
            result.map_err(|e| AppError::Validation(format!("CSV parse error: {e}")))?;
        let mut map = std::collections::HashMap::new();
        for (i, header) in headers.iter().enumerate() {
            if let Some(value) = record.get(i) {
                map.insert(header.clone(), value.to_string());
            }
        }
        rows.push(map);
    }
    Ok(rows)
}

/// Parse XLSX data into a list of header→value maps.
fn parse_xlsx_rows(
    data: &[u8],
) -> Result<Vec<std::collections::HashMap<String, String>>, AppError> {
    let cursor = Cursor::new(data);
    let mut workbook: Xlsx<_> = open_workbook_from_rs(cursor)
        .map_err(|e| AppError::Validation(format!("Invalid XLSX file: {e}")))?;

    // Use first sheet
    let sheet_name = workbook
        .sheet_names()
        .first()
        .cloned()
        .ok_or_else(|| AppError::Validation("XLSX file has no sheets".to_string()))?;

    let range = workbook
        .worksheet_range(&sheet_name)
        .map_err(|e| AppError::Validation(format!("Failed to read sheet '{sheet_name}': {e}")))?;

    let mut row_iter = range.rows();

    // First row is headers
    let header_row = row_iter
        .next()
        .ok_or_else(|| AppError::Validation("XLSX sheet is empty".to_string()))?;

    let headers: Vec<String> = header_row
        .iter()
        .map(|cell| cell.to_string().trim().to_string())
        .collect();

    let mut rows = Vec::new();
    for row in row_iter {
        let mut map = std::collections::HashMap::new();
        for (i, header) in headers.iter().enumerate() {
            let value = row
                .get(i)
                .map(|cell| cell.to_string())
                .unwrap_or_default();
            map.insert(header.clone(), value);
        }
        rows.push(map);
    }

    Ok(rows)
}

/// Map criticality string from APM CSV to the AssetCriticality enum.
///
/// Falls back to Medium when the value is empty or unrecognized.
fn map_criticality(value: Option<&str>) -> AssetCriticality {
    match value.map(|v| v.trim().to_lowercase()).as_deref() {
        Some("very high") | Some("very_high") | Some("veryhigh") => AssetCriticality::VeryHigh,
        Some("high") => AssetCriticality::High,
        Some("medium high") | Some("medium_high") | Some("mediumhigh") => {
            AssetCriticality::MediumHigh
        }
        Some("medium") => AssetCriticality::Medium,
        Some("medium low") | Some("medium_low") | Some("mediumlow") => AssetCriticality::MediumLow,
        Some("low") => AssetCriticality::Low,
        _ => AssetCriticality::Medium, // Default fallback
    }
}

/// Resolve effective ownership applying the Struttura Reale override.
///
/// If Struttura Reale fields are populated AND differ from the standard office,
/// the Struttura Reale owner becomes the effective owner.
fn resolve_effective_owner(
    office_owner: &Option<String>,
    office_name: &Option<String>,
    struttura_owner: &Option<String>,
    struttura_name: &Option<String>,
) -> (Option<String>, Option<String>) {
    match (struttura_owner, struttura_name) {
        (Some(sr_owner), Some(sr_name))
            if !sr_owner.is_empty()
                && !sr_name.is_empty()
                && (office_name.as_deref() != Some(sr_name.as_str())
                    || office_owner.as_deref() != Some(sr_owner.as_str())) =>
        {
            (Some(sr_owner.clone()), Some(sr_name.clone()))
        }
        _ => (office_owner.clone(), office_name.clone()),
    }
}

/// Check if a CSV flag value is considered true.
fn is_flag_true(value: &str) -> bool {
    let v = value.trim().to_uppercase();
    matches!(v.as_str(), "Y" | "YES" | "SI" | "TRUE" | "1" | "S" | "X")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn criticality_mapping_standard_values() {
        assert_eq!(map_criticality(Some("Very High")), AssetCriticality::VeryHigh);
        assert_eq!(map_criticality(Some("High")), AssetCriticality::High);
        assert_eq!(map_criticality(Some("Medium")), AssetCriticality::Medium);
        assert_eq!(map_criticality(Some("Medium High")), AssetCriticality::MediumHigh);
        assert_eq!(map_criticality(Some("Medium Low")), AssetCriticality::MediumLow);
        assert_eq!(map_criticality(Some("Low")), AssetCriticality::Low);
    }

    #[test]
    fn criticality_mapping_fallback_to_medium() {
        assert_eq!(map_criticality(None), AssetCriticality::Medium);
        assert_eq!(map_criticality(Some("")), AssetCriticality::Medium);
        assert_eq!(map_criticality(Some("Unknown")), AssetCriticality::Medium);
    }

    #[test]
    fn criticality_mapping_case_insensitive() {
        assert_eq!(map_criticality(Some("VERY HIGH")), AssetCriticality::VeryHigh);
        assert_eq!(map_criticality(Some("high")), AssetCriticality::High);
        assert_eq!(map_criticality(Some("LOW")), AssetCriticality::Low);
    }

    #[test]
    fn struttura_reale_override_when_different() {
        let office_owner = Some("Mario Rossi".to_string());
        let office_name = Some("Ufficio A".to_string());
        let struttura_owner = Some("Luigi Verdi".to_string());
        let struttura_name = Some("Struttura B".to_string());

        let (owner, name) =
            resolve_effective_owner(&office_owner, &office_name, &struttura_owner, &struttura_name);
        assert_eq!(owner.as_deref(), Some("Luigi Verdi"));
        assert_eq!(name.as_deref(), Some("Struttura B"));
    }

    #[test]
    fn struttura_reale_no_override_when_same() {
        let office_owner = Some("Mario Rossi".to_string());
        let office_name = Some("Ufficio A".to_string());
        let struttura_owner = Some("Mario Rossi".to_string());
        let struttura_name = Some("Ufficio A".to_string());

        let (owner, name) =
            resolve_effective_owner(&office_owner, &office_name, &struttura_owner, &struttura_name);
        assert_eq!(owner.as_deref(), Some("Mario Rossi"));
        assert_eq!(name.as_deref(), Some("Ufficio A"));
    }

    #[test]
    fn struttura_reale_no_override_when_empty() {
        let office_owner = Some("Mario Rossi".to_string());
        let office_name = Some("Ufficio A".to_string());
        let struttura_owner: Option<String> = None;
        let struttura_name: Option<String> = None;

        let (owner, name) =
            resolve_effective_owner(&office_owner, &office_name, &struttura_owner, &struttura_name);
        assert_eq!(owner.as_deref(), Some("Mario Rossi"));
        assert_eq!(name.as_deref(), Some("Ufficio A"));
    }

    #[test]
    fn flag_parsing() {
        assert!(is_flag_true("Y"));
        assert!(is_flag_true("Yes"));
        assert!(is_flag_true("SI"));
        assert!(is_flag_true("true"));
        assert!(is_flag_true("1"));
        assert!(is_flag_true("X"));
        assert!(!is_flag_true("N"));
        assert!(!is_flag_true("No"));
        assert!(!is_flag_true(""));
        assert!(!is_flag_true("false"));
    }

    #[test]
    fn apm_format_detection() {
        assert_eq!(ApmFormat::from_filename("data.csv"), Some(ApmFormat::Csv));
        assert_eq!(ApmFormat::from_filename("data.xlsx"), Some(ApmFormat::Xlsx));
        assert_eq!(ApmFormat::from_filename("data.xls"), Some(ApmFormat::Xlsx));
        assert_eq!(ApmFormat::from_filename("DATA.XLSX"), Some(ApmFormat::Xlsx));
        assert_eq!(ApmFormat::from_filename("data.json"), None);
    }

    #[test]
    fn csv_parsing_to_row_maps() {
        let csv_data = b"A,B,C\n1,2,3\n4,5,6";
        let rows = parse_csv_rows(csv_data).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["A"], "1");
        assert_eq!(rows[0]["B"], "2");
        assert_eq!(rows[1]["C"], "6");
    }

    #[test]
    fn default_field_mapping() {
        let mapping = ApmFieldMapping::default();
        assert_eq!(mapping.app_code_column, "CODICE ACRONIMO");
        assert_eq!(
            mapping.criticality_column,
            "ACRONYM CRITICALITY (SYNTHESIS LEVEL)"
        );
    }
}
