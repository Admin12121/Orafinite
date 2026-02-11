// ============================================
// Server-Sent Events (SSE) for Real-Time Guard Log Streaming
// ============================================
//
// Provides a `/v1/guard/events` endpoint that streams guard log events
// to connected clients in real-time using SSE.
//
// Architecture:
// 1. Guard scan handler writes log entries to the write buffer
// 2. Write buffer flushes to DB and publishes events to Redis pub/sub
// 3. This SSE endpoint subscribes to Redis pub/sub and streams events to clients
//
// Clients connect with their session token for auth. Each client only
// receives events for their organization.
//
// NOTE: The browser's EventSource API does NOT support custom headers.
// Therefore this endpoint accepts the session token from:
//   1. `Authorization: Bearer <token>` header (for non-browser clients)
//   2. `?token=<token>` query parameter (for browser EventSource)
//   3. `better-auth.session_token` cookie (for same-origin browser requests)

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    Json,
};
use futures::stream::Stream;
use serde::Deserialize;
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::AppState;
use crate::db::write_buffer::GuardLogEvent;
use crate::middleware::{require_session_from_headers, ErrorResponse};

// ============================================
// SSE Stream wrapper
// ============================================

/// A stream that receives guard log events filtered for a specific organization
struct GuardEventStream {
    rx: mpsc::Receiver<Event>,
}

impl Stream for GuardEventStream {
    type Item = Result<Event, Infallible>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(event)) => Poll::Ready(Some(Ok(event))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// ============================================
// SSE Query Params (for token-based auth fallback)
// ============================================

#[derive(Debug, Deserialize, Default)]
pub struct SseQueryParams {
    /// Session token passed as query param (fallback for EventSource which
    /// cannot set custom headers).
    pub token: Option<String>,
}

// ============================================
// Helper: extract session token from multiple sources
// ============================================

/// Try to extract the session token from (in priority order):
/// 1. `Authorization: Bearer <token>` header
/// 2. `?token=<token>` query parameter
/// 3. `better-auth.session_token` cookie
fn extract_session_token<'a>(
    headers: &'a HeaderMap,
    query_token: Option<&'a str>,
) -> Option<&'a str> {
    // 1. Authorization header
    if let Some(auth) = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        if !auth.is_empty() {
            return Some(auth);
        }
    }

    // 2. Query parameter
    if let Some(token) = query_token {
        if !token.is_empty() {
            return Some(token);
        }
    }

    // 3. Cookie: better-auth.session_token
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookie_header.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("better-auth.session_token=") {
                let value = value.trim();
                if !value.is_empty() {
                    // The cookie value may be URL-encoded; for session tokens
                    // this is typically not needed, but we handle it just in case.
                    return Some(value);
                }
            }
        }
    }

    None
}

/// Validate a session token against the database and return the authenticated user.
async fn validate_session_token(
    db: &sqlx::PgPool,
    token: &str,
) -> Result<crate::middleware::auth::AuthenticatedUser, (StatusCode, Json<ErrorResponse>)> {
    use sqlx::Row;

    let result = sqlx::query(
        r#"
        SELECT
            s.id as session_id,
            s.user_id,
            u.email,
            u.name
        FROM session s
        JOIN "user" u ON s.user_id = u.id
        WHERE s.token = $1
          AND s.expires_at > NOW()
        "#,
    )
    .bind(token)
    .fetch_optional(db)
    .await;

    match result {
        Ok(Some(row)) => Ok(crate::middleware::auth::AuthenticatedUser {
            session_id: row.get("session_id"),
            user_id: row.get("user_id"),
            email: row.get("email"),
            name: row.get("name"),
        }),
        Ok(None) => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Invalid or expired session token",
                "SESSION_INVALID",
            )),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                format!("Database error: {}", e),
                "DB_ERROR",
            )),
        )),
    }
}

// ============================================
// Helper: get org ID for user
// ============================================

async fn get_user_org_id(
    db: &sqlx::PgPool,
    user_id: &str,
) -> Result<Uuid, (StatusCode, Json<ErrorResponse>)> {
    let row = sqlx::query_scalar::<_, Uuid>(
        "SELECT organization_id FROM organization_member WHERE user_id = $1 LIMIT 1",
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
        Some(org_id) => Ok(org_id),
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
// SSE Handler
// ============================================

/// Stream real-time guard log events via Server-Sent Events
///
/// **Auth: Session Required**
///
/// Accepts session token from multiple sources (since EventSource API
/// cannot set custom headers):
///
/// 1. `Authorization: Bearer <token>` header (non-browser clients)
/// 2. `?token=<token>` query parameter (browser EventSource)
/// 3. `better-auth.session_token` cookie (same-origin browser requests)
///
/// Events are filtered to only show entries for the authenticated user's organization.
///
/// ## Event Types:
/// - `guard_log` — A new guard scan result (safe or threat)
/// - `stats_update` — Periodic stats summary (every 10 seconds)
/// - `connected` — Initial connection confirmation with org info
///
/// ## Usage (browser):
/// ```js
/// // Option A: cookie-based (same-origin, automatic)
/// const es = new EventSource('/v1/guard/events', { withCredentials: true });
///
/// // Option B: query param (cross-origin or when cookies unavailable)
/// const es = new EventSource('/v1/guard/events?token=SESSION_TOKEN');
/// ```
pub async fn guard_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SseQueryParams>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Authenticate user — try header, then query param, then cookie
    let token = extract_session_token(&headers, query.token.as_deref());

    let user = match token {
        Some(t) => validate_session_token(&state.db, t).await?,
        None => {
            // Last resort: try the standard require_session_from_headers
            // which only checks the Authorization header
            require_session_from_headers(&state.db, &headers)
                .await
                .map_err(|(status, json)| {
                    (
                        status,
                        Json(ErrorResponse::new(
                            format!(
                                "{}. For SSE connections, pass token via ?token= query parameter or cookie.",
                                json.error
                            ),
                            json.code.clone(),
                        )),
                    )
                })?
        }
    };

    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    tracing::info!(
        "SSE client connected: user={}, org={}",
        user.user_id,
        org_id
    );

    // Create a channel for this SSE client
    let (tx, rx) = mpsc::channel::<Event>(256);

    // Send initial connection event
    let connected_event = Event::default().event("connected").data(
        serde_json::json!({
            "organization_id": org_id.to_string(),
            "user_id": user.user_id,
            "message": "Connected to real-time guard log stream"
        })
        .to_string(),
    );

    if tx.send(connected_event).await.is_err() {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to initialize SSE stream",
                "SSE_INIT_FAILED",
            )),
        ));
    }

    // Spawn a background task that subscribes to Redis pub/sub
    // and forwards matching events to this client's channel
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
    let tx_clone = tx.clone();
    let db_pool = state.db.clone();

    tokio::spawn(async move {
        // Connect to Redis for pub/sub (needs a separate connection)
        let client = match redis::Client::open(redis_url) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("SSE: Failed to create Redis client: {}", e);
                return;
            }
        };

        let mut pubsub_conn = match client.get_async_pubsub().await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("SSE: Failed to connect to Redis pub/sub: {}", e);
                return;
            }
        };

        if let Err(e) = pubsub_conn.subscribe("guard_log_events").await {
            tracing::error!("SSE: Failed to subscribe to guard_log_events: {}", e);
            return;
        }

        tracing::debug!("SSE: Subscribed to guard_log_events for org {}", org_id);

        // Also spawn a periodic stats updater
        let tx_stats = tx_clone.clone();
        let stats_org_id = org_id;
        let stats_db = db_pool.clone();

        let stats_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;

                // Fetch current stats
                let stats = fetch_org_stats(&stats_db, stats_org_id).await;
                let event = Event::default()
                    .event("stats_update")
                    .data(serde_json::to_string(&stats).unwrap_or_default());

                if tx_stats.send(event).await.is_err() {
                    // Client disconnected
                    break;
                }
            }
        });

        // Listen for events on the pub/sub channel
        use futures::StreamExt;
        let mut msg_stream = pubsub_conn.on_message();

        while let Some(msg) = msg_stream.next().await {
            let payload: String = match msg.get_payload() {
                Ok(p) => p,
                Err(_) => continue,
            };

            // Parse the event and filter by organization
            let event: GuardLogEvent = match serde_json::from_str(&payload) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Only send events for this client's organization
            if event.organization_id != Some(org_id) {
                continue;
            }

            let sse_event = Event::default().event("guard_log").data(payload);

            if tx_clone.send(sse_event).await.is_err() {
                // Client disconnected
                tracing::debug!("SSE client disconnected: org={}", org_id);
                break;
            }
        }

        // Clean up stats task
        stats_handle.abort();
        tracing::debug!("SSE: Pub/sub listener exiting for org {}", org_id);
    });

    // Return the SSE response
    let stream = GuardEventStream { rx };
    let sse = Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("ping"),
    );

    Ok(sse.into_response())
}

// ============================================
// Stats helper
// ============================================

#[derive(serde::Serialize)]
struct OrgStats {
    total_scans: i64,
    threats_blocked: i64,
    safe_prompts: i64,
    avg_latency: i64,
}

async fn fetch_org_stats(db: &sqlx::PgPool, org_id: Uuid) -> OrgStats {
    use sqlx::Row;

    let row = sqlx::query(
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
    .fetch_one(db)
    .await;

    match row {
        Ok(r) => OrgStats {
            total_scans: r.get("total_scans"),
            threats_blocked: r.get("threats_blocked"),
            safe_prompts: r.get("safe_prompts"),
            avg_latency: r.get("avg_latency"),
        },
        Err(e) => {
            tracing::error!("Failed to fetch org stats for SSE: {}", e);
            OrgStats {
                total_scans: 0,
                threats_blocked: 0,
                safe_prompts: 0,
                avg_latency: 0,
            }
        }
    }
}
