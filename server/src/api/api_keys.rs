use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::{require_session_from_headers, ErrorResponse};
use crate::utils::{generate_api_key, hash_api_key};

// ============================================
// Request/Response Types
// ============================================

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    #[serde(default)]
    pub scopes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub key: String,
    pub prefix: String,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ApiKeyItem {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub name: String,
    pub key_prefix: String,
    pub scopes: Option<Vec<String>>,
    pub rate_limit_rpm: Option<i32>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListApiKeysResponse {
    pub keys: Vec<ApiKeyItem>,
}

#[derive(Debug, Serialize)]
pub struct RevokeApiKeyResponse {
    pub success: bool,
}

// ============================================
// Helpers
// ============================================

async fn get_user_org_id(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let row = sqlx::query(
        r#"
        SELECT om.organization_id
        FROM organization_member om
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
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
                "Organization not found. Create one first.",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}

// ============================================
// Handlers
// ============================================

/// Create a new API key
///
/// **Auth: Session Required**
pub async fn create_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<CreateApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
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
                "API key name cannot be empty",
                "INVALID_NAME",
            )),
        ));
    }

    let (key, prefix) = generate_api_key();
    let key_hash = hash_api_key(&key);

    let row = sqlx::query(
        r#"
        INSERT INTO api_key (organization_id, name, key_prefix, key_hash, scopes, created_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id, created_at
        "#,
    )
    .bind(org_id)
    .bind(&req.name)
    .bind(&prefix)
    .bind(&key_hash)
    .bind(&req.scopes)
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to create API key",
                "DB_INSERT_FAILED",
            )),
        )
    })?;

    let id: Uuid = row.get("id");
    let created_at: chrono::NaiveDateTime = row.get("created_at");

    Ok(Json(CreateApiKeyResponse {
        id,
        key,
        prefix,
        name: req.name,
        scopes: req.scopes,
        created_at: created_at.and_utc(),
    }))
}

/// List all API keys for the current organization
///
/// **Auth: Session Required**
pub async fn list_api_keys(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ListApiKeysResponse>, (StatusCode, Json<ErrorResponse>)> {
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
        SELECT id, organization_id, name, key_prefix, scopes, rate_limit_rpm,
               last_used_at, expires_at, revoked_at, created_by, created_at
        FROM api_key
        WHERE organization_id = $1 AND revoked_at IS NULL
        ORDER BY created_at DESC
        "#,
    )
    .bind(org_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list API keys: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to list API keys",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let keys: Vec<ApiKeyItem> = rows
        .into_iter()
        .map(|row| ApiKeyItem {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            name: row.get("name"),
            key_prefix: row.get("key_prefix"),
            scopes: row.get("scopes"),
            rate_limit_rpm: row.get("rate_limit_rpm"),
            last_used_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("last_used_at")
                .map(|dt| dt.and_utc()),
            expires_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("expires_at")
                .map(|dt| dt.and_utc()),
            revoked_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("revoked_at")
                .map(|dt| dt.and_utc()),
            created_by: row.get("created_by"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        })
        .collect();

    Ok(Json(ListApiKeysResponse { keys }))
}

/// Revoke an API key
///
/// **Auth: Session Required**
pub async fn revoke_api_key(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(key_id): axum::extract::Path<Uuid>,
) -> Result<Json<RevokeApiKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let result = sqlx::query(
        r#"
        UPDATE api_key
        SET revoked_at = NOW()
        WHERE id = $1 AND organization_id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(key_id)
    .bind(org_id)
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to revoke API key: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to revoke API key",
                "DB_UPDATE_FAILED",
            )),
        )
    })?;

    Ok(Json(RevokeApiKeyResponse {
        success: result.rows_affected() > 0,
    }))
}
