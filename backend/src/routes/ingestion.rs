//! Ingestion routes: file upload, history, and log details.

use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use uuid::Uuid;

use crate::errors::{ApiResponse, AppError};
use crate::middleware::auth::CurrentUser;
use crate::middleware::rbac::RequireManager;
use crate::models::pagination::{PagedResult, Pagination};
use crate::parsers::InputFormat;
use crate::services::ingestion::{
    self, IngestionLog, IngestionLogSummary, IngestionResult, ParserType,
};
use crate::AppState;

/// POST /api/v1/ingestion/upload — upload scanner output for ingestion (manager+, multipart).
pub async fn upload(
    State(state): State<AppState>,
    RequireManager(user): RequireManager,
    mut multipart: Multipart,
) -> Result<Json<ApiResponse<IngestionResult>>, AppError> {
    let mut file_data: Option<Vec<u8>> = None;
    let mut file_name = String::from("unknown");
    let mut parser_type: Option<ParserType> = None;
    let mut format: Option<InputFormat> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::Validation(format!("Multipart error: {e}")))?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                if let Some(fname) = field.file_name() {
                    file_name = fname.to_string();
                }
                file_data = Some(
                    field
                        .bytes()
                        .await
                        .map_err(|e| AppError::Validation(format!("Failed to read file: {e}")))?
                        .to_vec(),
                );
            }
            "parser_type" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::Validation(format!("Failed to read parser_type: {e}")))?;
                parser_type = Some(serde_json::from_value(serde_json::Value::String(text.clone()))
                    .map_err(|_| {
                        AppError::Validation(format!(
                            "Invalid parser_type '{text}'. Supported: sonarqube, sarif"
                        ))
                    })?);
            }
            "format" => {
                let text = field
                    .text()
                    .await
                    .map_err(|e| AppError::Validation(format!("Failed to read format: {e}")))?;
                format = Some(serde_json::from_value(serde_json::Value::String(text.clone()))
                    .map_err(|_| {
                        AppError::Validation(format!(
                            "Invalid format '{text}'. Supported: json, csv, xml, sarif"
                        ))
                    })?);
            }
            _ => {}
        }
    }

    let data = file_data.ok_or_else(|| {
        AppError::Validation("Missing 'file' field in multipart request".to_string())
    })?;

    let pt = parser_type.ok_or_else(|| {
        AppError::Validation("Missing 'parser_type' field".to_string())
    })?;

    let fmt = format.ok_or_else(|| {
        AppError::Validation("Missing 'format' field".to_string())
    })?;

    let result =
        ingestion::ingest_file(&state.db, &data, &file_name, &pt, &fmt, user.id).await?;

    Ok(ApiResponse::success(result))
}

/// GET /api/v1/ingestion/history — list past ingestion events.
pub async fn history(
    State(state): State<AppState>,
    _user: CurrentUser,
    Query(pagination): Query<Pagination>,
) -> Result<Json<ApiResponse<PagedResult<IngestionLogSummary>>>, AppError> {
    let total = ingestion::count_history(&state.db).await?;
    let logs = ingestion::list_history(&state.db, pagination.limit(), pagination.offset()).await?;
    let paged = PagedResult::new(logs, total, &pagination);
    Ok(ApiResponse::success(paged))
}

/// GET /api/v1/ingestion/:id — get full ingestion log details.
pub async fn get_log(
    State(state): State<AppState>,
    _user: CurrentUser,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<IngestionLog>>, AppError> {
    let log = ingestion::get_log(&state.db, id).await?;
    Ok(ApiResponse::success(log))
}
