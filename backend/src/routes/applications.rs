//! Application registry routes: CRUD, bulk import, and APM CSV import.

use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::rbac::RequireManager;
use crate::models::application::{Application, ApplicationSummary, CreateApplication, UpdateApplication};
use crate::models::pagination::{PagedResult, Pagination};
use crate::services::application::{
    self as app_service, ApmFieldMapping, ApmFormat, ApmImportResult, ApplicationFilters,
    ImportResult,
};
use crate::AppState;

/// GET /api/v1/applications — list applications with filters and pagination.
pub async fn list(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
    Query(filters): Query<ApplicationFilters>,
) -> Result<Json<ApiResponse<PagedResult<ApplicationSummary>>>, AppError> {
    let result = app_service::list(&state.db, &filters, &pagination).await?;
    Ok(ApiResponse::success(result))
}

/// POST /api/v1/applications — create a new application (manager+).
pub async fn create(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    Json(body): Json<CreateApplication>,
) -> Result<Json<ApiResponse<Application>>, AppError> {
    let app = app_service::create(&state.db, &body).await?;
    Ok(ApiResponse::success(app))
}

/// GET /api/v1/applications/:id — get application by ID.
pub async fn get_by_id(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<Application>>, AppError> {
    let app = app_service::find_by_id(&state.db, id).await?;
    Ok(ApiResponse::success(app))
}

/// PUT /api/v1/applications/:id — update application (manager+).
pub async fn update(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateApplication>,
) -> Result<Json<ApiResponse<Application>>, AppError> {
    let app = app_service::update(&state.db, id, &body).await?;
    Ok(ApiResponse::success(app))
}

/// GET /api/v1/applications/code/:code — get application by app_code.
pub async fn get_by_code(
    State(state): State<AppState>,
    Path(code): Path<String>,
) -> Result<Json<ApiResponse<Application>>, AppError> {
    let app = app_service::find_by_app_code(&state.db, &code)
        .await?
        .ok_or_else(|| AppError::NotFound(format!("Application with code '{code}' not found")))?;
    Ok(ApiResponse::success(app))
}

/// POST /api/v1/applications/import — bulk import from JSON array (manager+).
pub async fn import_bulk(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    Json(body): Json<Vec<CreateApplication>>,
) -> Result<Json<ApiResponse<ImportResult>>, AppError> {
    let result = app_service::import_bulk(&state.db, &body).await?;
    Ok(ApiResponse::success(result))
}

/// POST /api/v1/applications/import/apm — import from corporate APM CSV/XLSX (manager+, multipart).
pub async fn import_apm(
    State(state): State<AppState>,
    RequireManager(_manager): RequireManager,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<ApmImportResult>>, AppError> {
    let mut file_data: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut mapping = ApmFieldMapping::default();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Multipart error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                file_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::Validation(format!("Failed to read file: {e}")))?
                        .to_vec(),
                );
            }
            "mapping" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::Validation(format!("Failed to read mapping: {e}")))?;
                mapping = serde_json::from_str(&text)
                    .map_err(|e| AppError::Validation(format!("Invalid mapping JSON: {e}")))?;
            }
            _ => {}
        }
    }

    let data = file_data.ok_or_else(|| {
        AppError::Validation("Missing 'file' field in multipart request".to_string())
    })?;

    let format = filename
        .as_deref()
        .and_then(ApmFormat::from_filename)
        .unwrap_or(ApmFormat::Csv);

    let result = app_service::import_apm(&state.db, &data, &mapping, &format).await?;
    Ok(ApiResponse::success(result))
}

/// GET /api/v1/applications/unverified — list unverified stub applications.
pub async fn list_unverified(
    State(state): State<AppState>,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ApiResponse<PagedResult<ApplicationSummary>>>, AppError> {
    let result = app_service::list_unverified(&state.db, &pagination).await?;
    Ok(ApiResponse::success(result))
}
