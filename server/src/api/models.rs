use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::{require_session_from_headers, ErrorResponse};
use crate::utils::encryption;

// ============================================
// Request/Response Types
// ============================================

#[derive(Debug, Deserialize)]
pub struct CreateModelConfigRequest {
    pub name: String,
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    #[serde(default)]
    pub is_default: bool,
}

#[derive(Debug, Serialize)]
pub struct ModelConfigItem {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub settings: Option<serde_json::Value>,
    pub is_default: Option<bool>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListModelConfigsResponse {
    pub models: Vec<ModelConfigItem>,
}

#[derive(Debug, Serialize)]
pub struct DeleteResponse {
    pub success: bool,
}

// ============================================
// Helpers
// ============================================

async fn get_user_org_id(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let row =
        sqlx::query("SELECT organization_id FROM organization_member WHERE user_id = $1 LIMIT 1")
            .bind(user_id)
            .fetch_optional(db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        format!("Database error: {}", e),
                        "DB_ERROR",
                    )),
                )
            })?;

    match row {
        Some(r) => Ok(r.get("organization_id")),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Organization not found",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}

// ============================================
// Handlers
// ============================================

/// Create a new model configuration
///
/// **Auth: Session Required**
pub async fn create_model_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateModelConfigRequest>,
) -> Result<Json<ModelConfigItem>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    if req.name.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Model name cannot be empty",
                "INVALID_NAME",
            )),
        ));
    }

    // If setting as default, unset other defaults first
    if req.is_default {
        let _ =
            sqlx::query("UPDATE model_config SET is_default = FALSE WHERE organization_id = $1")
                .bind(org_id)
                .execute(&state.db)
                .await;
    }

    // Encrypt the model API key if provided
    let encrypted_api_key = match &req.api_key {
        Some(key) if !key.is_empty() => {
            let encrypted = encryption::encrypt(key).map_err(|e| {
                tracing::error!("Failed to encrypt model API key: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        "Failed to encrypt API key",
                        "ENCRYPTION_FAILED",
                    )),
                )
            })?;
            Some(encrypted)
        }
        _ => None,
    };

    let row = sqlx::query(
        r#"
        INSERT INTO model_config (organization_id, name, provider, model, api_key_encrypted, base_url, is_default)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, organization_id, name, provider, model, base_url, settings, is_default, created_at, updated_at
        "#
    )
    .bind(org_id)
    .bind(&req.name)
    .bind(&req.provider)
    .bind(&req.model)
    .bind(&encrypted_api_key)
    .bind(&req.base_url)
    .bind(req.is_default)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create model config: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(
            "Failed to create model configuration", "DB_INSERT_FAILED"
        )))
    })?;

    Ok(Json(ModelConfigItem {
        id: row.get("id"),
        organization_id: row.get("organization_id"),
        name: row.get("name"),
        provider: row.get("provider"),
        model: row.get("model"),
        base_url: row.get("base_url"),
        settings: row.get("settings"),
        is_default: row.get("is_default"),
        created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
    }))
}

/// List all model configurations for the current organization
///
/// **Auth: Session Required**
pub async fn list_model_configs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListModelConfigsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, name, provider, model, base_url, settings, is_default, created_at, updated_at
        FROM model_config
        WHERE organization_id = $1
        ORDER BY created_at DESC
        "#
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list model configs: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ErrorResponse::new(
            "Failed to list model configurations", "DB_QUERY_FAILED"
        )))
    })?;

    let models: Vec<ModelConfigItem> = rows
        .into_iter()
        .map(|row| ModelConfigItem {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            name: row.get("name"),
            provider: row.get("provider"),
            model: row.get("model"),
            base_url: row.get("base_url"),
            settings: row.get("settings"),
            is_default: row.get("is_default"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
            updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
        })
        .collect();

    Ok(Json(ListModelConfigsResponse { models }))
}

/// Delete a model configuration
///
/// **Auth: Session Required**
pub async fn delete_model_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(model_id): Path<Uuid>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let result = sqlx::query("DELETE FROM model_config WHERE id = $1 AND organization_id = $2")
        .bind(model_id)
        .bind(org_id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Failed to delete model config: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "Failed to delete model configuration",
                    "DB_DELETE_FAILED",
                )),
            )
        })?;

    Ok(Json(DeleteResponse {
        success: result.rows_affected() > 0,
    }))
}

/// Set a model as default
///
/// **Auth: Session Required**
pub async fn set_default_model(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(model_id): Path<Uuid>,
) -> Result<Json<DeleteResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    // Unset all defaults
    let _ = sqlx::query("UPDATE model_config SET is_default = FALSE WHERE organization_id = $1")
        .bind(org_id)
        .execute(&state.db)
        .await;

    // Set the new default
    let result = sqlx::query(
        "UPDATE model_config SET is_default = TRUE WHERE id = $1 AND organization_id = $2",
    )
    .bind(model_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to set default model: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to set default model",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    Ok(Json(DeleteResponse {
        success: result.rows_affected() > 0,
    }))
}
