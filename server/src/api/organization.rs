use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::{require_session_from_headers, ErrorResponse};

// ============================================
// Response Types
// ============================================

#[derive(Debug, Serialize)]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub owner_id: String,
    pub plan: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ============================================
// Handlers
// ============================================

/// Get or create organization for the current user
///
/// **Auth: Session Required**
pub async fn get_or_create_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<OrganizationResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    // Check if user already has an organization
    let existing = sqlx::query(
        r#"
        SELECT o.id, o.name, o.slug, o.owner_id, o.plan, o.created_at, o.updated_at
        FROM organization o
        JOIN organization_member om ON o.id = om.organization_id
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
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

    if let Some(row) = existing {
        return Ok(Json(OrganizationResponse {
            id: row.get("id"),
            name: row.get("name"),
            slug: row.get("slug"),
            owner_id: row.get("owner_id"),
            plan: row.get("plan"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
            updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
        }));
    }

    // Create new organization
    let display_name = user.email.split('@').next().unwrap_or("user");
    let slug = format!(
        "org-{}-{}",
        &user.user_id[..8.min(user.user_id.len())],
        chrono::Utc::now().timestamp_millis()
    );
    let org_name = format!(
        "{}'s Organization",
        user.name.as_deref().unwrap_or(display_name)
    );

    let row = sqlx::query(
        r#"
        INSERT INTO organization (name, slug, owner_id)
        VALUES ($1, $2, $3)
        RETURNING id, name, slug, owner_id, plan, created_at, updated_at
        "#,
    )
    .bind(&org_name)
    .bind(&slug)
    .bind(&user.user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create organization: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to create organization",
                "DB_INSERT_FAILED",
            )),
        )
    })?;

    let org_id: Uuid = row.get("id");

    // Add user as owner member
    let _ = sqlx::query(
        "INSERT INTO organization_member (organization_id, user_id, role) VALUES ($1, $2, 'owner')",
    )
    .bind(org_id)
    .bind(&user.user_id)
    .execute(&state.db)
    .await;

    Ok(Json(OrganizationResponse {
        id: row.get("id"),
        name: row.get("name"),
        slug: row.get("slug"),
        owner_id: row.get("owner_id"),
        plan: row.get("plan"),
        created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        updated_at: row.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
    }))
}

/// Get current user's organization (without creating)
///
/// **Auth: Session Required**
pub async fn get_current_organization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<Option<OrganizationResponse>>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let row = sqlx::query(
        r#"
        SELECT o.id, o.name, o.slug, o.owner_id, o.plan, o.created_at, o.updated_at
        FROM organization o
        JOIN organization_member om ON o.id = om.organization_id
        WHERE om.user_id = $1
        LIMIT 1
        "#,
    )
    .bind(&user.user_id)
    .fetch_optional(&state.db)
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
        Some(r) => Ok(Json(Some(OrganizationResponse {
            id: r.get("id"),
            name: r.get("name"),
            slug: r.get("slug"),
            owner_id: r.get("owner_id"),
            plan: r.get("plan"),
            created_at: r.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
            updated_at: r.get::<chrono::NaiveDateTime, _>("updated_at").and_utc(),
        }))),
        None => Ok(Json(None)),
    }
}
