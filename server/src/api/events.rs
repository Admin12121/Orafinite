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
// Therefore this endpoint accepts auth from:
//   1. `Authorization: Bearer <token>` header (for non-browser clients)
//   2. `?ticket=<ticket>` query parameter — a short-lived, single-use ticket
//      obtained via `POST /v1/guard/events/ticket` (for browser EventSource)
//   3. `better-auth.session_token` cookie (for same-origin browser requests)
//
// SECURITY: Raw session tokens are NEVER accepted via query parameters.
// The `?ticket=` mechanism uses a one-time, 30-second Redis-backed ticket
// that is deleted on first use, preventing token leakage through URLs,
// logs, Referer headers, browser history, and proxy/CDN logs.

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use futures::stream::Stream;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use uuid::Uuid;

use super::AppState;
use crate::db::write_buffer::GuardLogEvent;
use crate::middleware::{ErrorResponse, require_session_from_headers};

/// TTL for SSE tickets in seconds. Tickets expire after this duration
/// even if not redeemed.
const SSE_TICKET_TTL_SECS: u64 = 30;

/// Redis key prefix for SSE tickets.
const SSE_TICKET_PREFIX: &str = "sse_ticket:";

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
// SSE Query Params
// ============================================

#[derive(Debug, Deserialize, Default)]
pub struct SseQueryParams {
    /// A short-lived, single-use ticket obtained from `POST /v1/guard/events/ticket`.
    /// This replaces the old `?token=` parameter to avoid leaking session tokens in URLs.
    pub ticket: Option<String>,
}

// ============================================
// Ticket types
// ============================================

/// Payload stored in Redis for an SSE ticket.
#[derive(Debug, Serialize, Deserialize)]
struct SseTicketPayload {
    user_id: String,
    email: String,
    name: Option<String>,
    session_id: String,
}

/// Response body for the ticket creation endpoint.
#[derive(Debug, Serialize)]
pub struct SseTicketResponse {
    /// The one-time ticket to pass as `?ticket=` when connecting to the SSE endpoint.
    pub ticket: String,
    /// Number of seconds until the ticket expires.
    pub expires_in: u64,
}

// ============================================
// Helper: extract session token from header or cookie (NOT query params)
// ============================================

/// Try to extract the session token from (in priority order):
/// 1. `Authorization: Bearer <token>` header
/// 2. `better-auth.session_token` cookie
///
/// NOTE: Query parameters are intentionally excluded here. Session tokens
/// must never appear in URLs. Use the `?ticket=` mechanism instead.
fn extract_session_token_from_headers<'a>(headers: &'a HeaderMap) -> Option<&'a str> {
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

    // 2. Cookie: better-auth.session_token
    if let Some(cookie_header) = headers.get("cookie").and_then(|v| v.to_str().ok()) {
        for part in cookie_header.split(';') {
            let part = part.trim();
            if let Some(value) = part.strip_prefix("better-auth.session_token=") {
                let value = value.trim();
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }
    }

    None
}

// ============================================
// Helper: redeem a one-time SSE ticket from Redis
// ============================================

/// Attempt to redeem a one-time SSE ticket. If the ticket is valid and has not
/// been used before, returns the authenticated user info and atomically deletes
/// the ticket from Redis so it cannot be reused.
async fn redeem_sse_ticket(
    redis: &mut redis::aio::ConnectionManager,
    ticket: &str,
) -> Option<crate::middleware::auth::AuthenticatedUser> {
    let key = format!("{}{}", SSE_TICKET_PREFIX, ticket);

    // Atomically GET and DELETE to ensure single-use
    let payload: Option<String> = redis::cmd("GETDEL")
        .arg(&key)
        .query_async(redis)
        .await
        .ok()?;

    let payload = payload?;

    let ticket_data: SseTicketPayload = serde_json::from_str(&payload).ok()?;

    Some(crate::middleware::auth::AuthenticatedUser {
        user_id: ticket_data.user_id,
        email: ticket_data.email,
        name: ticket_data.name,
        session_id: ticket_data.session_id,
    })
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
        Err(_e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Authentication service unavailable",
                "AUTH_ERROR",
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
    .map_err(|_e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Organization lookup unavailable",
                "ORG_ERROR",
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
// Ticket Creation Endpoint
// ============================================

/// Create a short-lived, single-use SSE ticket.
///
/// **Auth: Session Required** (via Authorization header or cookie)
///
/// Returns a ticket that can be used exactly once within 30 seconds
/// to authenticate an SSE `EventSource` connection via `?ticket=<ticket>`.
///
/// This replaces the insecure pattern of passing raw session tokens
/// as query parameters, which would leak them into logs, browser
/// history, Referer headers, and proxy/CDN logs.
///
/// ## Request
/// ```text
/// POST /v1/guard/events/ticket
/// Authorization: Bearer <session_token>
/// ```
///
/// ## Response
/// ```json
/// {
///   "ticket": "a1b2c3d4-e5f6-...",
///   "expires_in": 30
/// }
/// ```
///
/// ## Usage
/// ```js
/// // 1. Obtain a ticket (session cookie sent automatically)
/// const res = await fetch('/v1/guard/events/ticket', { method: 'POST', credentials: 'include' });
/// const { ticket } = await res.json();
///
/// // 2. Connect SSE with the one-time ticket (NOT the session token)
/// const es = new EventSource(`/v1/guard/events?ticket=${ticket}`, { withCredentials: true });
/// ```
pub async fn create_sse_ticket(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SseTicketResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Authenticate the user via header or cookie — NOT query params
    let token = extract_session_token_from_headers(&headers).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Session token required. Use Authorization header or session cookie.",
                "SESSION_REQUIRED",
            )),
        )
    })?;

    let user = validate_session_token(&state.db, token).await?;

    // Generate a cryptographically random ticket ID
    let ticket = Uuid::new_v4().to_string();

    // Store ticket payload in Redis with TTL
    let payload = SseTicketPayload {
        user_id: user.user_id,
        email: user.email,
        name: user.name,
        session_id: user.session_id,
    };

    let payload_json = serde_json::to_string(&payload).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to create ticket",
                "TICKET_ERROR",
            )),
        )
    })?;

    let key = format!("{}{}", SSE_TICKET_PREFIX, ticket);
    let mut redis = state.redis.clone();

    redis
        .set_ex::<_, _, ()>(&key, &payload_json, SSE_TICKET_TTL_SECS)
        .await
        .map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new("Failed to store ticket", "TICKET_ERROR")),
            )
        })?;

    tracing::debug!(
        "SSE ticket created for user={}, expires in {}s",
        payload.user_id,
        SSE_TICKET_TTL_SECS
    );

    Ok(Json(SseTicketResponse {
        ticket,
        expires_in: SSE_TICKET_TTL_SECS,
    }))
}

// ============================================
// SSE Handler
// ============================================

/// Stream real-time guard log events via Server-Sent Events
///
/// **Auth: Session Required**
///
/// Accepts authentication from multiple sources (since EventSource API
/// cannot set custom headers):
///
/// 1. `Authorization: Bearer <token>` header (non-browser clients)
/// 2. `?ticket=<ticket>` — a short-lived, single-use ticket obtained
///    from `POST /v1/guard/events/ticket` (browser EventSource)
/// 3. `better-auth.session_token` cookie (same-origin browser requests)
///
/// **SECURITY:** Raw session tokens are NOT accepted via query parameters.
/// Use the ticket mechanism for EventSource connections.
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
/// // Option B: one-time ticket (recommended for cross-origin or cookie issues)
/// const res = await fetch('/v1/guard/events/ticket', { method: 'POST', credentials: 'include' });
/// const { ticket } = await res.json();
/// const es = new EventSource(`/v1/guard/events?ticket=${ticket}`, { withCredentials: true });
/// ```
pub async fn guard_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SseQueryParams>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    // Authenticate user.
    //
    // IMPORTANT: Check the one-time `?ticket=` parameter FIRST, before
    // cookie-based auth.  Browsers always send cookies on same-origin
    // requests, so `extract_session_token_from_headers` would find the
    // `better-auth.session_token` cookie and attempt DB validation with
    // the raw cookie value — which may differ from the token stored in
    // the session table (Better Auth can transform/hash it).  If we
    // checked cookies first the ticket would never be reached.
    //
    // Priority order:
    //   1. `?ticket=<ticket>`        — one-time Redis ticket (browser SSE)
    //   2. `Authorization: Bearer`   — header token (non-browser clients)
    //   3. Cookie fallback           — same-origin browser requests
    let user = if let Some(ref ticket) = query.ticket {
        // Auth via one-time ticket — redeem from Redis (atomic get+delete)
        if ticket.is_empty() {
            return Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Empty ticket provided",
                    "TICKET_INVALID",
                )),
            ));
        }

        let mut redis = state.redis.clone();
        redeem_sse_ticket(&mut redis, ticket).await.ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Invalid, expired, or already-used ticket. \
                     Obtain a new ticket via POST /v1/guard/events/ticket.",
                    "TICKET_INVALID",
                )),
            )
        })?
    } else if let Some(token) = extract_session_token_from_headers(&headers) {
        // Auth via Authorization header or cookie — direct session validation
        validate_session_token(&state.db, token).await?
    } else {
        // Last resort: try the standard require_session_from_headers
        // which only checks the Authorization header
        require_session_from_headers(&state.db, &headers)
            .await
            .map_err(|(status, json)| {
                (
                    status,
                    Json(ErrorResponse::new(
                        format!(
                            "{}. For SSE connections, obtain a ticket via POST /v1/guard/events/ticket \
                             and pass it as ?ticket= query parameter, or use cookie-based auth.",
                            json.error
                        ),
                        json.code.clone(),
                    )),
                )
            })?
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
