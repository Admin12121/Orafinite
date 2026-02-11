use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use super::AppState;
use crate::middleware::{require_session_from_headers, ErrorResponse};

// ============================================
// Request/Response Types
// ============================================

#[derive(Debug, Deserialize)]
pub struct ListGuardLogsParams {
    /// Page number (1-based)
    #[serde(default = "default_page")]
    pub page: i64,

    /// Items per page (1..=200)
    #[serde(default = "default_per_page")]
    pub per_page: i64,

    /// Filter by safety status: "safe", "threat", or omit for all
    pub status: Option<String>,

    /// Filter by request type: "scan", "validate", "batch", or omit for all
    pub request_type: Option<String>,

    /// Filter by threat category (e.g. "injection", "toxicity")
    pub category: Option<String>,

    /// Search by IP address prefix
    pub ip: Option<String>,

    /// Cursor-based pagination: pass the `id` of the last item from the
    /// previous page to efficiently fetch the next page.  When provided,
    /// `page` is ignored.
    pub cursor: Option<Uuid>,

    /// Time-range lower bound (ISO-8601 / RFC-3339)
    pub from: Option<String>,

    /// Time-range upper bound (ISO-8601 / RFC-3339)
    pub to: Option<String>,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    50
}

#[derive(Debug, Serialize)]
pub struct GuardLogItem {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub api_key_id: Option<Uuid>,
    pub prompt_hash: String,
    pub is_safe: bool,
    pub risk_score: Option<f32>,
    pub threats_detected: Option<serde_json::Value>,
    pub threat_categories: Option<Vec<String>>,
    pub latency_ms: Option<i32>,
    pub cached: Option<bool>,
    pub ip_address: Option<String>,
    pub request_type: Option<String>,
    pub user_agent: Option<String>,
    pub scan_options: Option<serde_json::Value>,
    pub response_id: Option<Uuid>,
    /// Full prompt text – only populated for threats (NULL for safe prompts)
    pub prompt_text: Option<String>,
    pub sanitized_prompt: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct PaginationMeta {
    pub page: i64,
    pub per_page: i64,
    pub total_items: i64,
    pub total_pages: i64,
    /// The cursor value to pass as `?cursor=` for the next page
    pub next_cursor: Option<Uuid>,
    pub has_next: bool,
    pub has_prev: bool,
}

#[derive(Debug, Serialize)]
pub struct ListGuardLogsResponse {
    pub logs: Vec<GuardLogItem>,
    pub pagination: PaginationMeta,
}

#[derive(Debug, Deserialize)]
pub struct GuardStatsParams {
    pub period: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GuardStatsResponse {
    pub total_scans: i64,
    pub threats_blocked: i64,
    pub safe_prompts: i64,
    pub avg_latency: i64,
    /// Breakdown by request type
    pub by_type: Option<Vec<TypeBreakdown>>,
    /// Top threat categories
    pub top_categories: Option<Vec<CategoryCount>>,
}

#[derive(Debug, Serialize)]
pub struct TypeBreakdown {
    pub request_type: String,
    pub count: i64,
}

#[derive(Debug, Serialize)]
pub struct CategoryCount {
    pub category: String,
    pub count: i64,
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

/// List guard logs for the current organization with pagination and filters
///
/// **Auth: Session Required**
///
/// ## Query Parameters
///
/// | Param          | Type   | Default | Description                              |
/// |----------------|--------|---------|------------------------------------------|
/// | `page`         | i64    | 1       | Page number (1-based, ignored if cursor) |
/// | `per_page`     | i64    | 50      | Items per page (max 200)                 |
/// | `status`       | string | —       | `"safe"` or `"threat"`                   |
/// | `request_type` | string | —       | `"scan"`, `"validate"`, `"batch"`        |
/// | `category`     | string | —       | Threat category filter                   |
/// | `ip`           | string | —       | IP address prefix filter                 |
/// | `cursor`       | uuid   | —       | Last item ID for cursor pagination       |
/// | `from`         | string | —       | Start time (RFC-3339)                    |
/// | `to`           | string | —       | End time (RFC-3339)                      |
pub async fn list_guard_logs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListGuardLogsParams>,
) -> Result<Json<ListGuardLogsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;
    let per_page = params.per_page.clamp(1, 200);
    let page = params.page.max(1);

    // ── Build dynamic WHERE clause ──────────────────────────────────

    let mut conditions: Vec<String> = vec!["organization_id = $1".to_string()];
    let mut bind_idx: usize = 2; // $1 is org_id

    // Status filter
    if let Some(ref status) = params.status {
        match status.as_str() {
            "safe" => conditions.push("is_safe = true".to_string()),
            "threat" => conditions.push("is_safe = false".to_string()),
            _ => {} // ignore unknown
        }
    }

    // Request type filter
    if params.request_type.is_some() {
        conditions.push(format!("request_type = ${}", bind_idx));
        bind_idx += 1;
    }

    // Category filter (array contains)
    if params.category.is_some() {
        conditions.push(format!("${} = ANY(threat_categories)", bind_idx));
        bind_idx += 1;
    }

    // IP filter (prefix match)
    if params.ip.is_some() {
        conditions.push(format!("ip_address LIKE ${}", bind_idx));
        bind_idx += 1;
    }

    // Time range: from
    let from_dt = params.from.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    });
    if from_dt.is_some() {
        conditions.push(format!("created_at >= ${}", bind_idx));
        bind_idx += 1;
    }

    // Time range: to
    let to_dt = params.to.as_ref().and_then(|s| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&Utc))
    });
    if to_dt.is_some() {
        conditions.push(format!("created_at <= ${}", bind_idx));
        bind_idx += 1;
    }

    // Cursor-based pagination (uses the created_at of the cursor row)
    let cursor_created_at: Option<chrono::NaiveDateTime> = if let Some(cursor_id) = params.cursor {
        let row = sqlx::query("SELECT created_at FROM guard_log WHERE id = $1")
            .bind(cursor_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse::new(
                        format!("Cursor lookup failed: {}", e),
                        "CURSOR_ERROR",
                    )),
                )
            })?;
        row.map(|r| r.get::<chrono::NaiveDateTime, _>("created_at"))
    } else {
        None
    };

    if cursor_created_at.is_some() {
        conditions.push(format!(
            "(created_at, id) < (${}, ${})",
            bind_idx,
            bind_idx + 1
        ));
        bind_idx += 2;
    }

    let where_clause = conditions.join(" AND ");

    // ── Count total matching rows (for offset pagination) ───────────

    let count_sql = format!(
        "SELECT COUNT(*) as cnt FROM guard_log WHERE {}",
        where_clause
    );

    let mut count_query = sqlx::query(&count_sql).bind(org_id);

    // Bind dynamic params in the same order
    if let Some(ref rt) = params.request_type {
        count_query = count_query.bind(rt);
    }
    if let Some(ref cat) = params.category {
        count_query = count_query.bind(cat);
    }
    if let Some(ref ip) = params.ip {
        count_query = count_query.bind(format!("{}%", ip));
    }
    if let Some(dt) = from_dt {
        count_query = count_query.bind(dt.naive_utc());
    }
    if let Some(dt) = to_dt {
        count_query = count_query.bind(dt.naive_utc());
    }
    if let Some(ts) = cursor_created_at {
        count_query = count_query.bind(ts);
        count_query = count_query.bind(params.cursor.unwrap());
    }

    let count_row = count_query.fetch_one(&state.db).await.map_err(|e| {
        tracing::error!("Failed to count guard logs: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to count guard logs",
                "DB_QUERY_FAILED",
            )),
        )
    })?;
    let total_items: i64 = count_row.get("cnt");

    // ── Fetch page of rows ──────────────────────────────────────────

    let offset = if cursor_created_at.is_some() {
        0 // cursor-based doesn't use offset
    } else {
        (page - 1) * per_page
    };

    // We keep $N consistent with bind_idx used above, but we need to
    // add LIMIT and OFFSET as the final params.
    let data_sql = format!(
        r#"
        SELECT id, organization_id, api_key_id, prompt_hash, is_safe,
               risk_score, threats_detected, threat_categories,
               latency_ms, cached, ip_address, request_type,
               user_agent, scan_options, response_id,
               prompt_text, sanitized_prompt, created_at
        FROM guard_log
        WHERE {}
        ORDER BY created_at DESC, id DESC
        LIMIT ${} OFFSET ${}
        "#,
        where_clause,
        bind_idx,
        bind_idx + 1
    );

    let mut data_query = sqlx::query(&data_sql).bind(org_id);

    if let Some(ref rt) = params.request_type {
        data_query = data_query.bind(rt);
    }
    if let Some(ref cat) = params.category {
        data_query = data_query.bind(cat);
    }
    if let Some(ref ip) = params.ip {
        data_query = data_query.bind(format!("{}%", ip));
    }
    if let Some(dt) = from_dt {
        data_query = data_query.bind(dt.naive_utc());
    }
    if let Some(dt) = to_dt {
        data_query = data_query.bind(dt.naive_utc());
    }
    if let Some(ts) = cursor_created_at {
        data_query = data_query.bind(ts);
        data_query = data_query.bind(params.cursor.unwrap());
    }

    data_query = data_query.bind(per_page).bind(offset);

    let rows = data_query.fetch_all(&state.db).await.map_err(|e| {
        tracing::error!("Failed to list guard logs: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to list guard logs",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let logs: Vec<GuardLogItem> = rows
        .into_iter()
        .map(|row| GuardLogItem {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            api_key_id: row.get("api_key_id"),
            prompt_hash: row.get("prompt_hash"),
            is_safe: row.get("is_safe"),
            risk_score: row.get("risk_score"),
            threats_detected: row.get("threats_detected"),
            threat_categories: row.get::<Option<Vec<String>>, _>("threat_categories"),
            latency_ms: row.get("latency_ms"),
            cached: row.get("cached"),
            ip_address: row.get("ip_address"),
            request_type: row.get("request_type"),
            user_agent: row.get("user_agent"),
            scan_options: row.get("scan_options"),
            response_id: row.get("response_id"),
            prompt_text: row.get("prompt_text"),
            sanitized_prompt: row.get("sanitized_prompt"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        })
        .collect();

    // Build pagination metadata
    let total_pages = if total_items == 0 {
        1
    } else {
        (total_items + per_page - 1) / per_page
    };

    let next_cursor = logs.last().map(|l| l.id);
    let has_next = if cursor_created_at.is_some() {
        logs.len() as i64 == per_page
    } else {
        page < total_pages
    };

    Ok(Json(ListGuardLogsResponse {
        logs,
        pagination: PaginationMeta {
            page: if cursor_created_at.is_some() {
                0 // not meaningful for cursor pagination
            } else {
                page
            },
            per_page,
            total_items,
            total_pages,
            next_cursor,
            has_next,
            has_prev: if cursor_created_at.is_some() {
                true // cursor means we already moved past page 1
            } else {
                page > 1
            },
        },
    }))
}

// ============================================
// Period helpers
// ============================================

/// Convert period string to a UTC cutoff datetime
fn period_to_cutoff(period: &str) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    match period {
        "today" => Some(now.date_naive().and_hms_opt(0, 0, 0).unwrap().and_utc()),
        "24h" => Some(now - chrono::Duration::hours(24)),
        "48h" => Some(now - chrono::Duration::hours(48)),
        "3d" => Some(now - chrono::Duration::days(3)),
        "7d" => Some(now - chrono::Duration::days(7)),
        "30d" => Some(now - chrono::Duration::days(30)),
        _ => None,
    }
}

// ============================================
// Guard Stats Handler
// ============================================

/// Get guard statistics for the current organization
///
/// Supports optional `?period=` query param: today, 24h, 48h, 3d, 7d, 30d
///
/// Returns:
/// - Aggregate counts (total scans, threats blocked, safe prompts, avg latency)
/// - Breakdown by request type (scan / validate / batch)
/// - Top threat categories
///
/// **Auth: Session Required**
pub async fn get_guard_stats(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<GuardStatsParams>,
) -> Result<Json<GuardStatsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    let cutoff = params.period.as_deref().and_then(period_to_cutoff);

    // ── Aggregate stats ─────────────────────────────────────────────

    let agg_row = if let Some(cutoff_dt) = cutoff {
        sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_scans,
                COUNT(*) FILTER (WHERE is_safe = true) as safe_prompts,
                COUNT(*) FILTER (WHERE is_safe = false) as threats_blocked,
                COALESCE(AVG(latency_ms)::BIGINT, 0) as avg_latency
            FROM guard_log
            WHERE organization_id = $1 AND created_at >= $2
            "#,
        )
        .bind(org_id)
        .bind(cutoff_dt.naive_utc())
        .fetch_one(&state.db)
        .await
    } else {
        sqlx::query(
            r#"
            SELECT
                COUNT(*) as total_scans,
                COUNT(*) FILTER (WHERE is_safe = true) as safe_prompts,
                COUNT(*) FILTER (WHERE is_safe = false) as threats_blocked,
                COALESCE(AVG(latency_ms)::BIGINT, 0) as avg_latency
            FROM guard_log
            WHERE organization_id = $1
            "#,
        )
        .bind(org_id)
        .fetch_one(&state.db)
        .await
    }
    .map_err(|e| {
        tracing::error!("Failed to get guard stats: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to get guard statistics",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    // ── Breakdown by request type ───────────────────────────────────

    let type_rows = if let Some(cutoff_dt) = cutoff {
        sqlx::query(
            r#"
            SELECT COALESCE(request_type, 'scan') as req_type, COUNT(*) as cnt
            FROM guard_log
            WHERE organization_id = $1 AND created_at >= $2
            GROUP BY req_type
            ORDER BY cnt DESC
            "#,
        )
        .bind(org_id)
        .bind(cutoff_dt.naive_utc())
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            r#"
            SELECT COALESCE(request_type, 'scan') as req_type, COUNT(*) as cnt
            FROM guard_log
            WHERE organization_id = $1
            GROUP BY req_type
            ORDER BY cnt DESC
            "#,
        )
        .bind(org_id)
        .fetch_all(&state.db)
        .await
    }
    .unwrap_or_default();

    let by_type: Vec<TypeBreakdown> = type_rows
        .iter()
        .map(|r| TypeBreakdown {
            request_type: r.get("req_type"),
            count: r.get("cnt"),
        })
        .collect();

    // ── Top threat categories ───────────────────────────────────────

    let cat_rows = if let Some(cutoff_dt) = cutoff {
        sqlx::query(
            r#"
            SELECT unnest(threat_categories) as category, COUNT(*) as cnt
            FROM guard_log
            WHERE organization_id = $1
              AND created_at >= $2
              AND is_safe = false
              AND threat_categories IS NOT NULL
              AND array_length(threat_categories, 1) > 0
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 10
            "#,
        )
        .bind(org_id)
        .bind(cutoff_dt.naive_utc())
        .fetch_all(&state.db)
        .await
    } else {
        sqlx::query(
            r#"
            SELECT unnest(threat_categories) as category, COUNT(*) as cnt
            FROM guard_log
            WHERE organization_id = $1
              AND is_safe = false
              AND threat_categories IS NOT NULL
              AND array_length(threat_categories, 1) > 0
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 10
            "#,
        )
        .bind(org_id)
        .fetch_all(&state.db)
        .await
    }
    .unwrap_or_default();

    let top_categories: Vec<CategoryCount> = cat_rows
        .iter()
        .map(|r| CategoryCount {
            category: r.get("category"),
            count: r.get("cnt"),
        })
        .collect();

    Ok(Json(GuardStatsResponse {
        total_scans: agg_row.get("total_scans"),
        threats_blocked: agg_row.get("threats_blocked"),
        safe_prompts: agg_row.get("safe_prompts"),
        avg_latency: agg_row.get("avg_latency"),
        by_type: if by_type.is_empty() {
            None
        } else {
            Some(by_type)
        },
        top_categories: if top_categories.is_empty() {
            None
        } else {
            Some(top_categories)
        },
    }))
}
