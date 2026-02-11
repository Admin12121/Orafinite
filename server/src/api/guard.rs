use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use futures::future::join_all;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use std::collections::HashMap;

use super::AppState;
use crate::db::write_buffer::GuardLogEntry;
use crate::grpc::ml_client::{
    AdvancedScanOptions as GrpcAdvancedScanOptions, ScanMode as GrpcScanMode,
    ScanOptions as GrpcScanOptions, ScannerConfigEntry as GrpcScannerConfigEntry,
    ScannerResultInfo,
};
use crate::middleware::rate_limit::{
    check_monthly_quota, check_monthly_quota_remaining, check_rate_limit, increment_monthly_quota,
    monthly_quota_for_plan, rate_limit_key, MONTHLY_QUOTA_BASIC, RATE_LIMIT_WINDOW_SECONDS,
};
use crate::middleware::{require_api_key_from_headers, ErrorResponse};
use crate::utils::hash_prompt;

// ============================================
// Scan Mode (JSON API representation)
// ============================================

/// Which scanning to perform: prompt only, output only, or both.
/// Maps directly to the proto ScanMode enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiScanMode {
    PromptOnly,
    OutputOnly,
    Both,
}

impl Default for ApiScanMode {
    fn default() -> Self {
        ApiScanMode::PromptOnly
    }
}

impl From<ApiScanMode> for GrpcScanMode {
    fn from(m: ApiScanMode) -> Self {
        match m {
            ApiScanMode::PromptOnly => GrpcScanMode::PromptOnly,
            ApiScanMode::OutputOnly => GrpcScanMode::OutputOnly,
            ApiScanMode::Both => GrpcScanMode::Both,
        }
    }
}

impl From<GrpcScanMode> for ApiScanMode {
    fn from(m: GrpcScanMode) -> Self {
        match m {
            GrpcScanMode::PromptOnly => ApiScanMode::PromptOnly,
            GrpcScanMode::OutputOnly => ApiScanMode::OutputOnly,
            GrpcScanMode::Both => ApiScanMode::Both,
        }
    }
}

// ============================================
// Per-Scanner Configuration (JSON API)
// ============================================

/// Configuration for a single scanner sent by the client.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiScannerConfig {
    /// Whether this scanner is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Detection threshold (0.0 – 1.0). Default varies per scanner (typically 0.5).
    #[serde(default = "default_threshold")]
    pub threshold: f32,

    /// Scanner-specific settings encoded as a JSON string.
    /// Examples:
    ///   BanTopics:       {"topics": ["violence","religion"]}
    ///   BanCompetitors:  {"competitors": ["CompanyA"], "redact": true}
    ///   TokenLimit:      {"limit": 4096, "encoding_name": "cl100k_base"}
    #[serde(default)]
    pub settings_json: String,
}

fn default_threshold() -> f32 {
    0.5
}

impl From<ApiScannerConfig> for GrpcScannerConfigEntry {
    fn from(c: ApiScannerConfig) -> Self {
        GrpcScannerConfigEntry {
            enabled: c.enabled,
            threshold: c.threshold,
            settings_json: c.settings_json,
        }
    }
}

// ============================================
// Request/Response Types
// ============================================

#[derive(Debug, Deserialize)]
pub struct ScanPromptRequest {
    #[serde(deserialize_with = "validate_prompt")]
    pub prompt: String,
    #[serde(default)]
    pub options: ScanOptions,
}

// Custom deserializer for prompt validation
fn validate_prompt<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let prompt = String::deserialize(deserializer)?;

    // Validate prompt length (max 32KB)
    const MAX_PROMPT_LENGTH: usize = 32 * 1024;
    if prompt.len() > MAX_PROMPT_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "Prompt exceeds maximum length of {} bytes",
            MAX_PROMPT_LENGTH
        )));
    }

    // Validate prompt is not empty
    if prompt.trim().is_empty() {
        return Err(serde::de::Error::custom("Prompt cannot be empty"));
    }

    Ok(prompt)
}

#[derive(Debug, Deserialize)]
pub struct ScanOptions {
    #[serde(default = "default_true")]
    pub check_injection: bool,
    #[serde(default = "default_true")]
    pub check_toxicity: bool,
    #[serde(default = "default_true")]
    pub check_pii: bool,
    #[serde(default)]
    pub sanitize: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            check_injection: true,
            check_toxicity: true,
            check_pii: true,
            sanitize: false,
        }
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanPromptResponse {
    pub id: Uuid,
    pub safe: bool,
    pub sanitized_prompt: Option<String>,
    pub threats: Vec<ThreatDetection>,
    pub risk_score: f32,
    pub latency_ms: u64,
    pub cached: bool,
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_categories: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ThreatDetection {
    pub threat_type: String,
    pub confidence: f32,
    pub description: String,
    pub severity: String,
}

/// Extract user-agent from request headers
fn extract_user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[derive(Debug, Deserialize)]
pub struct ValidateOutputRequest {
    #[serde(deserialize_with = "validate_output_content")]
    pub output: String,
    pub original_prompt: Option<String>,
}

// Custom deserializer for output validation
fn validate_output_content<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let output = String::deserialize(deserializer)?;

    // Validate output length (max 64KB)
    const MAX_OUTPUT_LENGTH: usize = 64 * 1024;
    if output.len() > MAX_OUTPUT_LENGTH {
        return Err(serde::de::Error::custom(format!(
            "Output exceeds maximum length of {} bytes",
            MAX_OUTPUT_LENGTH
        )));
    }

    if output.trim().is_empty() {
        return Err(serde::de::Error::custom("Output cannot be empty"));
    }

    Ok(output)
}

#[derive(Debug, Serialize)]
pub struct ValidateOutputResponse {
    pub id: Uuid,
    pub safe: bool,
    pub sanitized_output: Option<String>,
    pub issues: Vec<OutputIssue>,
    pub latency_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct OutputIssue {
    pub issue_type: String,
    pub description: String,
    pub severity: String,
}

// ============================================
// Batch Scanning Types
// ============================================

/// Maximum prompts per batch request
const MAX_BATCH_SIZE: usize = 50;

#[derive(Debug, Deserialize)]
pub struct BatchScanRequest {
    pub prompts: Vec<BatchPromptItem>,
    #[serde(default)]
    pub options: ScanOptions,
}

#[derive(Debug, Deserialize)]
pub struct BatchPromptItem {
    /// Optional client-provided ID to correlate results
    pub id: Option<String>,
    pub prompt: String,
}

#[derive(Debug, Serialize)]
pub struct BatchScanResponse {
    pub total: usize,
    pub successful: usize,
    pub failed: usize,
    pub results: Vec<BatchScanResultItem>,
    pub total_latency_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct BatchScanResultItem {
    /// Client-provided ID or auto-generated index
    pub id: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<ScanPromptResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================
// Cache Configuration
// ============================================

const CACHE_TTL_SECONDS: u64 = 300; // 5 minutes

// ============================================
// Handlers
// ============================================

/// Scan a prompt for security threats using ML-powered detection
///
/// This endpoint NEVER uses fallback heuristics. If the ML sidecar is unavailable,
/// it returns an error to ensure users always get accurate, ML-powered results.
///
/// **Auth: API Key Required**
/// This endpoint is for external applications protecting their LLMs from
/// prompt injection, jailbreaks, and other attacks.
/// Use X-API-Key header or Authorization: Bearer <api_key>
pub async fn scan_prompt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ScanPromptRequest>,
) -> Result<Json<ScanPromptResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require valid API key (for external apps)
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    tracing::debug!("Guard scan request from org: {}", api_key.organization_id);

    // Enforce rate limiting (uses per-key RPM from DB, default 1000)
    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Rate limit exceeded. {} requests per minute allowed. Retry after {} seconds.",
                                api_key.rate_limit_rpm, retry_after
                            ),
                            "RATE_LIMITED",
                        )
                        .with_details(format!("remaining: {}, retry_after: {}s", remaining, retry_after)),
                    ),
                ));
            }
            tracing::debug!(
                "Rate limit OK: {} remaining for key {}",
                remaining,
                api_key.id
            );
        }
        Err(e) => {
            // Redis failure - allow request but log warning
            tracing::warn!("Rate limit check failed (allowing request): {}", e);
        }
    }

    // Check monthly quota — look up plan-based limit from API key
    let api_key_id_str = format!("{}", api_key.id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota(&mut redis_conn, &api_key_id_str, monthly_limit).await {
        Ok((allowed, used, limit, days_left)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Monthly quota exceeded. {}/{} requests used. Resets in {} days.",
                                used, limit, days_left
                            ),
                            "QUOTA_EXCEEDED",
                        )
                        .with_details(format!(
                            "used: {}, limit: {}, resets_in_days: {}",
                            used, limit, days_left
                        )),
                    ),
                ));
            }
            tracing::debug!(
                "Monthly quota OK: {}/{} used for key {}",
                used,
                limit,
                api_key.id
            );
        }
        Err(e) => {
            tracing::warn!("Monthly quota check failed (allowing request): {}", e);
        }
    }

    let start = std::time::Instant::now();
    let prompt_hash = hash_prompt(&req.prompt);
    let cache_key = format!("guard:scan:{}", prompt_hash);
    let user_agent = extract_user_agent(&headers);

    // Build scan options JSON for logging
    let scan_options_json = serde_json::json!({
        "check_injection": req.options.check_injection,
        "check_toxicity": req.options.check_toxicity,
        "check_pii": req.options.check_pii,
        "sanitize": req.options.sanitize,
    });

    // Check Redis cache first (reuse redis_conn from rate limit check)
    match redis_conn.get::<_, Option<String>>(&cache_key).await {
        Ok(Some(cached_json)) => {
            match serde_json::from_str::<ScanPromptResponse>(&cached_json) {
                Ok(mut cached_response) => {
                    let response_id = Uuid::new_v4();
                    cached_response.id = response_id;
                    cached_response.cached = true;
                    // Keep the original ML scan latency from the cached response
                    // so logs and API responses reflect real inference cost.
                    // The `cached: true` flag already tells callers this was a cache hit.
                    cached_response.timestamp = Utc::now();

                    tracing::debug!("Cache hit for prompt hash: {}", prompt_hash);

                    // Extract threat categories from cached threats
                    let threat_categories: Vec<String> = cached_response
                        .threats
                        .iter()
                        .map(|t| t.threat_type.clone())
                        .collect();

                    // Log via write buffer (non-blocking, batched)
                    let threats_json =
                        serde_json::to_value(&cached_response.threats).unwrap_or_default();
                    let entry = GuardLogEntry::new_scan(
                        Some(api_key.organization_id),
                        Some(api_key.id),
                        prompt_hash.clone(),
                        cached_response.safe,
                        cached_response.risk_score,
                        threats_json,
                        cached_response.latency_ms as i32, // original ML latency preserved
                        true,
                        extract_ip(&headers).map(|s| s.to_string()),
                        Some(req.prompt.clone()),
                        threat_categories,
                        scan_options_json,
                        user_agent,
                        cached_response.sanitized_prompt.clone(),
                        Some(response_id),
                    );
                    state.write_buffer.queue(entry).await;

                    return Ok(Json(cached_response));
                }
                Err(e) => {
                    // Cache corrupted, log and continue to fresh scan
                    tracing::warn!("Failed to deserialize cached response: {}", e);
                    // Invalidate corrupted cache entry
                    let _: Result<(), _> = redis_conn.del(&cache_key).await;
                }
            }
        }
        Ok(None) => {
            // No cache entry, continue to ML scan
        }
        Err(e) => {
            // Redis error - log but continue (cache is optional optimization)
            tracing::warn!("Redis cache read failed: {}", e);
        }
    }

    // Get ML client - fail if unavailable
    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar connection failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    // Build scan options
    let options = GrpcScanOptions {
        check_injection: req.options.check_injection,
        check_toxicity: req.options.check_toxicity,
        check_pii: req.options.check_pii,
        sanitize: req.options.sanitize,
    };

    // Execute ML scan - fail if scan fails
    let result = client
        .scan_prompt(&req.prompt, options)
        .await
        .map_err(|e| {
            let error_msg = e.to_string();
            tracing::error!("ML scan failed: {}", error_msg);

            // Determine appropriate error code based on gRPC status
            let (status, code) = match e.code() {
                tonic::Code::DeadlineExceeded => (StatusCode::GATEWAY_TIMEOUT, "SCAN_TIMEOUT"),
                tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
                tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                tonic::Code::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "SCAN_FAILED"),
            };

            (
                status,
                Json(ErrorResponse::new("Failed to scan prompt", code).with_details(error_msg)),
            )
        })?;

    let latency_ms = start.elapsed().as_millis() as u64;

    // Build response from ML result
    let threats: Vec<ThreatDetection> = result
        .threats
        .into_iter()
        .map(|t| ThreatDetection {
            threat_type: t.threat_type,
            confidence: t.confidence,
            description: t.description,
            severity: t.severity,
        })
        .collect();

    // Extract threat categories for logging and response
    let threat_categories: Vec<String> = threats.iter().map(|t| t.threat_type.clone()).collect();

    let response_id = Uuid::new_v4();
    let response = ScanPromptResponse {
        id: response_id,
        safe: result.safe,
        sanitized_prompt: result.sanitized_prompt,
        threats,
        risk_score: result.risk_score,
        latency_ms,
        cached: false,
        timestamp: Utc::now(),
        threat_categories: if threat_categories.is_empty() {
            None
        } else {
            Some(threat_categories.clone())
        },
    };

    // Cache the result (best effort - don't fail if cache write fails)
    if let Ok(json) = serde_json::to_string(&response) {
        if let Err(e) = redis_conn
            .set_ex::<_, _, ()>(&cache_key, &json, CACHE_TTL_SECONDS)
            .await
        {
            tracing::warn!("Failed to cache scan result: {}", e);
        }
    }

    // Log via write buffer (non-blocking, batched) — richer data
    let threats_json = serde_json::to_value(&response.threats).unwrap_or_default();
    let entry = GuardLogEntry::new_scan(
        Some(api_key.organization_id),
        Some(api_key.id),
        prompt_hash,
        response.safe,
        response.risk_score,
        threats_json,
        response.latency_ms as i32,
        false,
        extract_ip(&headers).map(|s| s.to_string()),
        Some(req.prompt.clone()),
        threat_categories,
        scan_options_json,
        user_agent,
        response.sanitized_prompt.clone(),
        Some(response_id),
    );
    state.write_buffer.queue(entry).await;

    Ok(Json(response))
}

/// Extract client IP from headers (X-Forwarded-For or X-Real-IP)
fn extract_ip(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.split(',').next().unwrap_or(s).trim())
}

/// Look up plan-based monthly quota for an API key from the database.
/// Falls back to MONTHLY_QUOTA_BASIC if lookup fails.
async fn lookup_api_key_quota(db: &sqlx::PgPool, api_key_id: Uuid) -> u32 {
    use sqlx::Row;
    match sqlx::query("SELECT plan, monthly_quota FROM api_key WHERE id = $1")
        .bind(api_key_id)
        .fetch_optional(db)
        .await
    {
        Ok(Some(row)) => {
            // Prefer explicit monthly_quota column if set
            let quota: Option<i32> = row.get("monthly_quota");
            if let Some(q) = quota {
                return q as u32;
            }
            // Otherwise derive from plan
            let plan: Option<String> = row.get("plan");
            monthly_quota_for_plan(plan.as_deref().unwrap_or("basic"))
        }
        _ => MONTHLY_QUOTA_BASIC,
    }
}

/// Validate LLM output for security issues (PII, sensitive data, etc.)
///
/// This endpoint NEVER uses fallback. If the ML sidecar is unavailable,
/// it returns an error to ensure users always get accurate validation.
///
/// **Auth: API Key Required**
/// This endpoint is for external applications validating LLM responses
/// for PII leaks, sensitive data exposure, and other output issues.
/// Use X-API-Key header or Authorization: Bearer <api_key>
pub async fn validate_output(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ValidateOutputRequest>,
) -> Result<Json<ValidateOutputResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require valid API key (for external apps)
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    tracing::debug!(
        "Guard validate request from org: {}",
        api_key.organization_id
    );

    // Enforce rate limiting
    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Rate limit exceeded. {} requests per minute allowed. Retry after {} seconds.",
                                api_key.rate_limit_rpm, retry_after
                            ),
                            "RATE_LIMITED",
                        )
                        .with_details(format!(
                            "remaining: {}, retry_after: {}s",
                            remaining, retry_after
                        )),
                    ),
                ));
            }
            tracing::debug!(
                "Rate limit OK: {} remaining for key {}",
                remaining,
                api_key.id
            );
        }
        Err(e) => {
            tracing::warn!("Rate limit check failed (allowing request): {}", e);
        }
    }

    // Check monthly quota (plan-based)
    let api_key_id_str = format!("{}", api_key.id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota(&mut redis_conn, &api_key_id_str, monthly_limit).await {
        Ok((allowed, used, limit, days_left)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Monthly quota exceeded. {}/{} requests used. Resets in {} days.",
                                used, limit, days_left
                            ),
                            "QUOTA_EXCEEDED",
                        )
                        .with_details(format!(
                            "used: {}, limit: {}, resets_in_days: {}",
                            used, limit, days_left
                        )),
                    ),
                ));
            }
        }
        Err(e) => {
            tracing::warn!("Monthly quota check failed (allowing request): {}", e);
        }
    }

    let start = std::time::Instant::now();
    let user_agent = extract_user_agent(&headers);

    // Get ML client - fail if unavailable
    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar connection failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML validation service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    // Execute ML validation - fail if validation fails
    let result = client
        .scan_output(&req.output, req.original_prompt.as_deref())
        .await
        .map_err(|e| {
            let error_msg = e.to_string();
            tracing::error!("ML output validation failed: {}", error_msg);

            let (status, code) = match e.code() {
                tonic::Code::DeadlineExceeded => {
                    (StatusCode::GATEWAY_TIMEOUT, "VALIDATION_TIMEOUT")
                }
                tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
                tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
                tonic::Code::Unavailable => {
                    (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE")
                }
                _ => (StatusCode::INTERNAL_SERVER_ERROR, "VALIDATION_FAILED"),
            };

            (
                status,
                Json(ErrorResponse::new("Failed to validate output", code).with_details(error_msg)),
            )
        })?;

    let latency_ms = start.elapsed().as_millis() as u64;

    // Build response from ML result
    let issues: Vec<OutputIssue> = result
        .issues
        .into_iter()
        .map(|i| OutputIssue {
            issue_type: i.issue_type,
            description: i.description,
            severity: i.severity,
        })
        .collect();

    let response_id = Uuid::new_v4();
    let is_safe = result.safe;
    let response = ValidateOutputResponse {
        id: response_id,
        safe: is_safe,
        sanitized_output: result.sanitized_output,
        issues,
        latency_ms,
    };

    // Log validate request via write buffer
    let issue_categories: Vec<String> = response
        .issues
        .iter()
        .map(|i| i.issue_type.clone())
        .collect();
    let issues_json = serde_json::to_value(&response.issues).unwrap_or_default();
    let output_hash = hash_prompt(&req.output);

    let mut entry = GuardLogEntry::new_scan(
        Some(api_key.organization_id),
        Some(api_key.id),
        output_hash,
        is_safe,
        0.0, // validate doesn't produce a risk_score
        issues_json,
        latency_ms as i32,
        false,
        extract_ip(&headers).map(|s| s.to_string()),
        if !is_safe {
            Some(req.output.clone())
        } else {
            None
        },
        issue_categories,
        serde_json::json!({"type": "validate"}),
        user_agent,
        response.sanitized_output.clone(),
        Some(response_id),
    );
    entry.request_type = "validate".to_string();
    state.write_buffer.queue(entry).await;

    Ok(Json(response))
}

/// Batch scan multiple prompts in a single request
///
/// Scans up to 50 prompts in parallel for efficiency.
/// Each prompt is scanned independently and results are returned in order.
///
/// **Auth: API Key Required**
/// Use X-API-Key header or Authorization: Bearer <api_key>
pub async fn batch_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<BatchScanRequest>,
) -> Result<Json<BatchScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require valid API key
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    // Validate batch size
    if req.prompts.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "At least one prompt is required",
                "EMPTY_BATCH",
            )),
        ));
    }

    if req.prompts.len() > MAX_BATCH_SIZE {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                format!("Batch size exceeds maximum of {} prompts", MAX_BATCH_SIZE),
                "BATCH_TOO_LARGE",
            )),
        ));
    }

    // Check rate limit for entire batch (counts as N requests)
    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    let batch_size = req.prompts.len() as u32;

    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed || remaining < batch_size {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(
                        ErrorResponse::new(
                            format!(
                                "Rate limit exceeded. {} requests remaining, batch requires {}. Retry after {} seconds.",
                                remaining, batch_size, retry_after
                            ),
                            "RATE_LIMITED",
                        ),
                    ),
                ));
            }
        }
        Err(e) => {
            tracing::warn!("Rate limit check failed (allowing request): {}", e);
        }
    }

    // Check monthly quota (plan-based)
    let api_key_id_str = format!("{}", api_key.id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota_remaining(&mut redis_conn, &api_key_id_str, monthly_limit).await {
        Ok(remaining) => {
            if remaining < batch_size {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Monthly quota insufficient. {} requests remaining, batch requires {}.",
                            remaining, batch_size
                        ),
                        "QUOTA_EXCEEDED",
                    )),
                ));
            }
        }
        Err(e) => {
            tracing::warn!("Monthly quota check failed (allowing request): {}", e);
        }
    }

    // Increment monthly quota for the entire batch upfront
    if let Err(e) = increment_monthly_quota(&mut redis_conn, &api_key_id_str, batch_size).await {
        tracing::warn!("Monthly quota increment failed: {}", e);
    }

    let start = std::time::Instant::now();
    let user_agent = extract_user_agent(&headers);
    let client_ip = extract_ip(&headers).map(|s| s.to_string());

    // Get ML client
    let client = state.get_ml_client().await.map_err(|e| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    // Build scan options
    let options = GrpcScanOptions {
        check_injection: req.options.check_injection,
        check_toxicity: req.options.check_toxicity,
        check_pii: req.options.check_pii,
        sanitize: req.options.sanitize,
    };

    let scan_options_json = serde_json::json!({
        "check_injection": req.options.check_injection,
        "check_toxicity": req.options.check_toxicity,
        "check_pii": req.options.check_pii,
        "sanitize": req.options.sanitize,
        "batch": true,
    });

    // Scan all prompts in parallel
    let scan_futures: Vec<_> = req
        .prompts
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let prompt = item.prompt.clone();
            let id = item.id.clone().unwrap_or_else(|| idx.to_string());
            let opts = options.clone();
            let mut client_clone = client.clone();

            async move {
                // Validate prompt
                if prompt.trim().is_empty() {
                    return (
                        prompt,
                        BatchScanResultItem {
                            id,
                            success: false,
                            result: None,
                            error: Some("Prompt cannot be empty".to_string()),
                        },
                    );
                }

                if prompt.len() > 32 * 1024 {
                    return (
                        prompt,
                        BatchScanResultItem {
                            id,
                            success: false,
                            result: None,
                            error: Some("Prompt exceeds maximum length of 32KB".to_string()),
                        },
                    );
                }

                // Execute scan
                match client_clone.scan_prompt(&prompt, opts).await {
                    Ok(result) => {
                        let threats: Vec<ThreatDetection> = result
                            .threats
                            .into_iter()
                            .map(|t| ThreatDetection {
                                threat_type: t.threat_type,
                                confidence: t.confidence,
                                description: t.description,
                                severity: t.severity,
                            })
                            .collect();

                        let threat_cats: Vec<String> =
                            threats.iter().map(|t| t.threat_type.clone()).collect();

                        (
                            prompt,
                            BatchScanResultItem {
                                id,
                                success: true,
                                result: Some(ScanPromptResponse {
                                    id: Uuid::new_v4(),
                                    safe: result.safe,
                                    sanitized_prompt: result.sanitized_prompt,
                                    threats,
                                    risk_score: result.risk_score,
                                    latency_ms: 0,
                                    cached: false,
                                    timestamp: Utc::now(),
                                    threat_categories: if threat_cats.is_empty() {
                                        None
                                    } else {
                                        Some(threat_cats)
                                    },
                                }),
                                error: None,
                            },
                        )
                    }
                    Err(e) => (
                        prompt,
                        BatchScanResultItem {
                            id,
                            success: false,
                            result: None,
                            error: Some(e.message().to_string()),
                        },
                    ),
                }
            }
        })
        .collect();

    let results_with_prompts = join_all(scan_futures).await;

    let total_latency_ms = start.elapsed().as_millis() as u64;

    // Log each successful result via write buffer
    for (prompt, item) in &results_with_prompts {
        if let Some(ref scan_result) = item.result {
            let threats_json = serde_json::to_value(&scan_result.threats).unwrap_or_default();
            let threat_cats: Vec<String> = scan_result
                .threats
                .iter()
                .map(|t| t.threat_type.clone())
                .collect();
            let prompt_hash = hash_prompt(prompt);

            let mut entry = GuardLogEntry::new_scan(
                Some(api_key.organization_id),
                Some(api_key.id),
                prompt_hash,
                scan_result.safe,
                scan_result.risk_score,
                threats_json,
                total_latency_ms as i32, // batch total
                false,
                client_ip.clone(),
                Some(prompt.clone()),
                threat_cats,
                scan_options_json.clone(),
                user_agent.clone(),
                scan_result.sanitized_prompt.clone(),
                Some(scan_result.id),
            );
            entry.request_type = "batch".to_string();
            state.write_buffer.queue(entry).await;
        }
    }

    // Separate results from prompts for the response
    let results: Vec<BatchScanResultItem> = results_with_prompts
        .into_iter()
        .map(|(_, item)| item)
        .collect();

    let total = results.len();
    let successful = results.iter().filter(|r| r.success).count();
    let failed = total - successful;

    tracing::info!(
        "Batch scan completed: {} total, {} successful, {} failed, {}ms",
        total,
        successful,
        failed,
        total_latency_ms
    );

    Ok(Json(BatchScanResponse {
        total,
        successful,
        failed,
        results,
        total_latency_ms,
    }))
}

// ============================================
// Advanced Scan — Full Scanner Customisation
// ============================================

/// Request body for the advanced scan endpoint.
/// Clients can pick exactly which scanners to run, set per-scanner
/// thresholds and settings, and choose whether to scan the prompt,
/// the output, or both.
#[derive(Debug, Deserialize)]
pub struct AdvancedScanRequest {
    /// Prompt text (required for prompt_only / both modes)
    #[serde(default)]
    pub prompt: String,

    /// LLM output text (required for output_only / both modes)
    #[serde(default)]
    pub output: String,

    /// What to scan: "prompt_only", "output_only", or "both"
    #[serde(default)]
    pub scan_mode: ApiScanMode,

    /// Per-scanner configuration for input (prompt) scanners.
    /// Key = scanner name in snake_case (e.g. "prompt_injection").
    /// If omitted or empty, defaults are used when scan_mode includes prompt scanning.
    #[serde(default)]
    pub input_scanners: HashMap<String, ApiScannerConfig>,

    /// Per-scanner configuration for output scanners.
    /// Key = scanner name in snake_case (e.g. "toxicity").
    /// If omitted or empty, defaults are used when scan_mode includes output scanning.
    #[serde(default)]
    pub output_scanners: HashMap<String, ApiScannerConfig>,

    /// Return sanitised versions of prompt / output
    #[serde(default)]
    pub sanitize: bool,

    /// Stop after the first failing scanner (faster)
    #[serde(default)]
    pub fail_fast: bool,
}

/// Individual scanner result returned to the client
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AdvancedScannerResult {
    pub scanner_name: String,
    pub is_valid: bool,
    pub score: f32,
    pub description: String,
    pub severity: String,
    pub scanner_latency_ms: i32,
}

impl From<ScannerResultInfo> for AdvancedScannerResult {
    fn from(r: ScannerResultInfo) -> Self {
        Self {
            scanner_name: r.scanner_name,
            is_valid: r.is_valid,
            score: r.score,
            description: r.description,
            severity: r.severity,
            scanner_latency_ms: r.scanner_latency_ms,
        }
    }
}

/// Response body for the advanced scan endpoint
#[derive(Debug, Serialize)]
pub struct AdvancedScanResponse {
    pub id: Uuid,
    pub safe: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_prompt: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sanitized_output: Option<String>,

    pub risk_score: f32,

    pub scan_mode: ApiScanMode,

    /// Results from each input (prompt) scanner that was executed
    pub input_results: Vec<AdvancedScannerResult>,

    /// Results from each output scanner that was executed
    pub output_results: Vec<AdvancedScannerResult>,

    /// Total latency in ms
    pub latency_ms: u64,

    pub input_scanners_run: i32,
    pub output_scanners_run: i32,

    /// Merged threat categories (from all failing scanners)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threat_categories: Option<Vec<String>>,

    pub cached: bool,
    pub timestamp: DateTime<Utc>,
}

/// Advanced scan – full per-scanner customisation
///
/// Accepts per-scanner enable/disable, thresholds, and scanner-specific
/// settings.  The `scan_mode` field controls whether to scan the prompt,
/// the LLM output, or both.
///
/// **Auth: API Key Required**
pub async fn advanced_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AdvancedScanRequest>,
) -> Result<Json<AdvancedScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    // ── Auth ────────────────────────────────────────────────────
    let api_key = require_api_key_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    tracing::debug!(
        "Advanced scan request from org: {}, mode: {:?}",
        api_key.organization_id,
        req.scan_mode
    );

    // ── Validate inputs ────────────────────────────────────────
    match req.scan_mode {
        ApiScanMode::PromptOnly | ApiScanMode::Both => {
            if req.prompt.trim().is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new(
                        "Prompt is required for prompt_only or both scan modes",
                        "MISSING_PROMPT",
                    )),
                ));
            }
        }
        _ => {}
    }

    match req.scan_mode {
        ApiScanMode::OutputOnly | ApiScanMode::Both => {
            if req.output.trim().is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(ErrorResponse::new(
                        "Output is required for output_only or both scan modes",
                        "MISSING_OUTPUT",
                    )),
                ));
            }
        }
        _ => {}
    }

    const MAX_TEXT_LEN: usize = 64 * 1024;
    if req.prompt.len() > MAX_TEXT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Prompt exceeds maximum length of 64KB",
                "PROMPT_TOO_LONG",
            )),
        ));
    }
    if req.output.len() > MAX_TEXT_LEN {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Output exceeds maximum length of 64KB",
                "OUTPUT_TOO_LONG",
            )),
        ));
    }

    // ── Rate limiting ──────────────────────────────────────────
    let rl_key = rate_limit_key(Some(&format!("{}", api_key.id)), None);
    let mut redis_conn = state.redis.clone();
    match check_rate_limit(
        &mut redis_conn,
        &rl_key,
        api_key.rate_limit_rpm as u32,
        RATE_LIMIT_WINDOW_SECONDS,
    )
    .await
    {
        Ok((allowed, remaining, retry_after)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Rate limit exceeded. {} RPM allowed. Retry after {}s.",
                            api_key.rate_limit_rpm, retry_after
                        ),
                        "RATE_LIMITED",
                    )),
                ));
            }
            tracing::debug!(
                "Rate limit OK: {} remaining for key {}",
                remaining,
                api_key.id
            );
        }
        Err(e) => {
            tracing::warn!("Rate limit check failed (allowing request): {}", e);
        }
    }

    // ── Monthly quota ──────────────────────────────────────────
    let api_key_id_str = format!("{}", api_key.id);
    let monthly_limit = lookup_api_key_quota(&state.db, api_key.id).await;
    match check_monthly_quota(&mut redis_conn, &api_key_id_str, monthly_limit).await {
        Ok((allowed, used, limit, days_left)) => {
            if !allowed {
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse::new(
                        format!(
                            "Monthly quota exceeded. {}/{} used. Resets in {} days.",
                            used, limit, days_left
                        ),
                        "QUOTA_EXCEEDED",
                    )),
                ));
            }
        }
        Err(e) => {
            tracing::warn!("Monthly quota check failed (allowing request): {}", e);
        }
    }

    // ── Build gRPC options ─────────────────────────────────────
    let start = std::time::Instant::now();
    let user_agent = extract_user_agent(&headers);

    let grpc_input_scanners: HashMap<String, GrpcScannerConfigEntry> = req
        .input_scanners
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect();

    let grpc_output_scanners: HashMap<String, GrpcScannerConfigEntry> = req
        .output_scanners
        .into_iter()
        .map(|(k, v)| (k, v.into()))
        .collect();

    let grpc_opts = GrpcAdvancedScanOptions {
        prompt: req.prompt.clone(),
        output: req.output.clone(),
        scan_mode: req.scan_mode.into(),
        input_scanners: grpc_input_scanners,
        output_scanners: grpc_output_scanners,
        sanitize: req.sanitize,
        fail_fast: req.fail_fast,
    };

    // ── Get ML client ──────────────────────────────────────────
    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar connection failed: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "ML scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    // ── Execute scan ───────────────────────────────────────────
    let result = client.advanced_scan(grpc_opts).await.map_err(|e| {
        let error_msg = e.to_string();
        tracing::error!("ML advanced scan failed: {}", error_msg);

        let (status, code) = match e.code() {
            tonic::Code::DeadlineExceeded => (StatusCode::GATEWAY_TIMEOUT, "SCAN_TIMEOUT"),
            tonic::Code::ResourceExhausted => (StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED"),
            tonic::Code::InvalidArgument => (StatusCode::BAD_REQUEST, "INVALID_REQUEST"),
            tonic::Code::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "ML_SERVICE_UNAVAILABLE"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "SCAN_FAILED"),
        };

        (
            status,
            Json(ErrorResponse::new("Advanced scan failed", code).with_details(error_msg)),
        )
    })?;

    let latency_ms = start.elapsed().as_millis() as u64;

    // ── Build threat categories from all failing scanners ──────
    let mut threat_categories: Vec<String> = Vec::new();
    for r in &result.input_results {
        if !r.is_valid {
            threat_categories.push(r.scanner_name.clone());
        }
    }
    for r in &result.output_results {
        if !r.is_valid {
            threat_categories.push(r.scanner_name.clone());
        }
    }

    let response_id = Uuid::new_v4();
    let response = AdvancedScanResponse {
        id: response_id,
        safe: result.safe,
        sanitized_prompt: result.sanitized_prompt,
        sanitized_output: result.sanitized_output,
        risk_score: result.risk_score,
        scan_mode: result.scan_mode.into(),
        input_results: result
            .input_results
            .into_iter()
            .map(AdvancedScannerResult::from)
            .collect(),
        output_results: result
            .output_results
            .into_iter()
            .map(AdvancedScannerResult::from)
            .collect(),
        latency_ms,
        input_scanners_run: result.input_scanners_run,
        output_scanners_run: result.output_scanners_run,
        threat_categories: if threat_categories.is_empty() {
            None
        } else {
            Some(threat_categories.clone())
        },
        cached: false,
        timestamp: Utc::now(),
    };

    // ── Log via write buffer ───────────────────────────────────
    let scan_mode_str = match req.scan_mode {
        ApiScanMode::PromptOnly => "advanced_prompt",
        ApiScanMode::OutputOnly => "advanced_output",
        ApiScanMode::Both => "advanced_both",
    };

    let hash_input = if !req.prompt.is_empty() {
        &req.prompt
    } else {
        &req.output
    };
    let prompt_hash = hash_prompt(hash_input);

    let threats_json = serde_json::json!({
        "input_results": &response.input_results,
        "output_results": &response.output_results,
    });

    let scan_options_json = serde_json::json!({
        "scan_mode": scan_mode_str,
        "sanitize": req.sanitize,
        "fail_fast": req.fail_fast,
        "input_scanners_run": response.input_scanners_run,
        "output_scanners_run": response.output_scanners_run,
    });

    let mut entry = GuardLogEntry::new_scan(
        Some(api_key.organization_id),
        Some(api_key.id),
        prompt_hash,
        response.safe,
        response.risk_score,
        threats_json,
        latency_ms as i32,
        false,
        extract_ip(&headers).map(|s| s.to_string()),
        if !response.safe {
            Some(req.prompt.clone())
        } else {
            None
        },
        threat_categories,
        scan_options_json,
        user_agent,
        response.sanitized_prompt.clone(),
        Some(response_id),
    );
    entry.request_type = scan_mode_str.to_string();
    state.write_buffer.queue(entry).await;

    Ok(Json(response))
}
