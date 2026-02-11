use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

use super::AppState;
use crate::grpc::ml_client::ModelConfig as GrpcModelConfig;
use crate::middleware::{require_session_from_headers, ErrorResponse};

// ============================================
// Constants
// ============================================

/// Maximum number of concurrent scans allowed
const MAX_CONCURRENT_SCANS: usize = 10;

/// Maximum poll time for a scan (45 minutes for comprehensive scans)
const MAX_POLL_DURATION_SECS: u64 = 45 * 60;

/// Poll interval in seconds
const POLL_INTERVAL_SECS: u64 = 5;

/// Maximum vulnerabilities to return per page
const MAX_VULNERABILITIES_PER_PAGE: i64 = 100;

// Global counter for active scans
static ACTIVE_SCANS: AtomicUsize = AtomicUsize::new(0);

// ============================================
// Request/Response Types
// ============================================

#[derive(Debug, Deserialize)]
pub struct StartScanRequest {
    pub model_config: ModelConfig,
    pub scan_type: ScanType,
    #[serde(default)]
    pub probes: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModelConfig {
    #[serde(deserialize_with = "validate_provider")]
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

fn validate_provider<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let provider = String::deserialize(deserializer)?;
    let valid_providers = ["openai", "anthropic", "huggingface", "ollama", "custom"];

    if !valid_providers.contains(&provider.to_lowercase().as_str()) {
        return Err(serde::de::Error::custom(format!(
            "Invalid provider '{}'. Valid providers: {:?}",
            provider, valid_providers
        )));
    }

    Ok(provider)
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Quick,
    Standard,
    Comprehensive,
    Custom,
}

impl ScanType {
    fn as_str(&self) -> &str {
        match self {
            ScanType::Quick => "quick",
            ScanType::Standard => "standard",
            ScanType::Comprehensive => "comprehensive",
            ScanType::Custom => "custom",
        }
    }

    fn estimated_duration_seconds(&self) -> u32 {
        match self {
            ScanType::Quick => 60,
            ScanType::Standard => 300,
            ScanType::Comprehensive => 900,
            ScanType::Custom => 300,
        }
    }

    fn max_duration_seconds(&self) -> u64 {
        match self {
            ScanType::Quick => 5 * 60,
            ScanType::Standard => 15 * 60,
            ScanType::Comprehensive => 45 * 60,
            ScanType::Custom => 30 * 60,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StartScanResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub estimated_duration_seconds: u32,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ScanStatusResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub progress: u8,
    pub probes_completed: u32,
    pub probes_total: u32,
    pub vulnerabilities_found: u32,
    pub started_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_per_page")]
    pub per_page: u32,
}

fn default_page() -> u32 {
    1
}
fn default_per_page() -> u32 {
    50
}

#[derive(Debug, Serialize)]
pub struct ScanResultsResponse {
    pub scan_id: Uuid,
    pub status: String,
    pub summary: ScanSummary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub pagination: PaginationInfo,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct PaginationInfo {
    pub page: u32,
    pub per_page: u32,
    pub total_items: u32,
    pub total_pages: u32,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub total_probes: u32,
    pub passed: u32,
    pub failed: u32,
    pub risk_score: f32,
    pub severity_breakdown: SeverityBreakdown,
}

#[derive(Debug, Serialize)]
pub struct SeverityBreakdown {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
}

#[derive(Debug, Serialize)]
pub struct Vulnerability {
    pub id: Uuid,
    pub probe_name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub attack_prompt: String,
    pub model_response: String,
    pub recommendation: String,
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
                "Organization not found. Please access the dashboard first to create your organization.",
                "ORG_NOT_FOUND",
            )),
        )),
    }
}

/// Start a new vulnerability scan (Garak)
///
/// This endpoint creates a scan job and starts it asynchronously.
/// The scan runs against the ML sidecar - if unavailable, the scan fails properly.
///
/// **Auth: Session Required (Logged-in Users Only)**
/// This endpoint is for authenticated users running vulnerability scans
/// on their own LLM models via the Orafinite dashboard.
pub async fn start_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<StartScanRequest>,
) -> Result<Json<StartScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require valid session (authenticated users only)
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    // Get user's organization
    let org_id = get_user_org_id(&state.db, &user.user_id).await?;

    tracing::info!(
        "Scan started by user: {} ({}) for org: {}",
        user.email,
        user.user_id,
        org_id
    );

    // Check concurrent scan limit
    let current_scans = ACTIVE_SCANS.load(Ordering::SeqCst);
    if current_scans >= MAX_CONCURRENT_SCANS {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse::new(
                format!("Maximum concurrent scans ({}) reached. Please wait for existing scans to complete.", MAX_CONCURRENT_SCANS),
                "TOO_MANY_SCANS"
            ))
        ));
    }

    // Validate API key is provided for non-local providers
    if req.model_config.provider != "ollama" && req.model_config.api_key.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "API key is required for this provider",
                "MISSING_API_KEY",
            )),
        ));
    }

    // Verify ML sidecar is available before creating scan
    let mut client = state.get_ml_client().await.map_err(|e| {
        tracing::error!("ML sidecar unavailable: {}", e);
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "Scanning service is currently unavailable",
                    "ML_SERVICE_UNAVAILABLE",
                )
                .with_details(e),
            ),
        )
    })?;

    // Health check the ML sidecar
    if let Err(e) = client.health_check().await {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                ErrorResponse::new(
                    "Scanning service health check failed",
                    "ML_SERVICE_UNHEALTHY",
                )
                .with_details(e.to_string()),
            ),
        ));
    }

    let scan_id = Uuid::new_v4();
    let scan_type_str = req.scan_type.as_str();
    let now = Utc::now();

    // Insert scan record into database (with organization_id and created_by from session)
    sqlx::query(
        r#"
        INSERT INTO scan (id, organization_id, scan_type, status, progress, created_by, created_at)
        VALUES ($1, $2, $3, 'queued', 0, $4, $5)
        "#,
    )
    .bind(scan_id)
    .bind(org_id)
    .bind(scan_type_str)
    .bind(&user.user_id)
    .bind(now.naive_utc())
    .execute(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to create scan record: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to create scan record", "DB_INSERT_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    // Increment active scan counter
    ACTIVE_SCANS.fetch_add(1, Ordering::SeqCst);

    // Start the scan asynchronously
    let state_clone = state.clone();
    let model_config = req.model_config.clone();
    let probes = req.probes.clone();
    let scan_type = req.scan_type.clone();

    tokio::spawn(async move {
        run_garak_scan(state_clone, scan_id, model_config, probes, scan_type).await;
        // Decrement counter when done
        ACTIVE_SCANS.fetch_sub(1, Ordering::SeqCst);
    });

    Ok(Json(StartScanResponse {
        scan_id,
        status: "queued".to_string(),
        estimated_duration_seconds: req.scan_type.estimated_duration_seconds(),
        created_at: now,
    }))
}

async fn run_garak_scan(
    state: AppState,
    scan_id: Uuid,
    model_config: ModelConfig,
    probes: Vec<String>,
    scan_type: ScanType,
) {
    // Update status to running
    if let Err(e) = sqlx::query("UPDATE scan SET status = 'running', started_at = $2 WHERE id = $1")
        .bind(scan_id)
        .bind(Utc::now().naive_utc())
        .execute(&state.db)
        .await
    {
        tracing::error!("Failed to update scan status to running: {}", e);
        return;
    }

    // Get ML client
    let mut client = match state.get_ml_client().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                "Failed to connect to ML sidecar for scan {}: {}",
                scan_id,
                e
            );
            mark_scan_failed(
                &state,
                scan_id,
                &format!("ML service connection failed: {}", e),
            )
            .await;
            return;
        }
    };

    // Start the Garak scan
    let grpc_config = GrpcModelConfig {
        provider: model_config.provider,
        model: model_config.model,
        api_key: model_config.api_key,
        base_url: model_config.base_url,
    };

    let remote_scan_id = match client
        .start_garak_scan(grpc_config, probes, scan_type.as_str())
        .await
    {
        Ok(id) => id,
        Err(e) => {
            tracing::error!("Failed to start Garak scan {}: {}", scan_id, e);
            mark_scan_failed(&state, scan_id, &format!("Failed to start scan: {}", e)).await;
            return;
        }
    };

    tracing::info!(
        "Started Garak scan {} with remote ID: {}",
        scan_id,
        remote_scan_id
    );

    // Poll for status updates with timeout based on scan type
    poll_scan_status(
        state,
        scan_id,
        remote_scan_id,
        scan_type.max_duration_seconds(),
    )
    .await;
}

async fn mark_scan_failed(state: &AppState, scan_id: Uuid, error_message: &str) {
    if let Err(e) =
        sqlx::query("UPDATE scan SET status = 'failed', error_message = $2 WHERE id = $1")
            .bind(scan_id)
            .bind(error_message)
            .execute(&state.db)
            .await
    {
        tracing::error!("Failed to mark scan {} as failed: {}", scan_id, e);
    }
}

async fn poll_scan_status(
    state: AppState,
    scan_id: Uuid,
    remote_scan_id: String,
    max_duration_secs: u64,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(POLL_INTERVAL_SECS));
    let max_polls = max_duration_secs / POLL_INTERVAL_SECS;
    let mut poll_count = 0;
    let mut consecutive_failures = 0;
    const MAX_CONSECUTIVE_FAILURES: u32 = 5;

    loop {
        interval.tick().await;
        poll_count += 1;

        // Check timeout
        if poll_count > max_polls {
            tracing::warn!(
                "Scan {} timed out after {} seconds",
                scan_id,
                max_duration_secs
            );
            mark_scan_failed(
                &state,
                scan_id,
                &format!("Scan timed out after {} seconds", max_duration_secs),
            )
            .await;
            break;
        }

        // Get ML client
        let mut client = match state.get_ml_client().await {
            Ok(c) => {
                consecutive_failures = 0;
                c
            }
            Err(e) => {
                consecutive_failures += 1;
                tracing::warn!(
                    "Failed to get ML client (attempt {}): {}",
                    consecutive_failures,
                    e
                );

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    mark_scan_failed(&state, scan_id, "Lost connection to ML service").await;
                    break;
                }
                continue;
            }
        };

        // Get scan status
        let status_response = match client.get_garak_status(&remote_scan_id).await {
            Ok(s) => s,
            Err(e) => {
                consecutive_failures += 1;
                tracing::warn!(
                    "Failed to get scan status (attempt {}): {}",
                    consecutive_failures,
                    e
                );

                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                    mark_scan_failed(
                        &state,
                        scan_id,
                        &format!("Failed to get scan status: {}", e),
                    )
                    .await;
                    break;
                }
                continue;
            }
        };

        consecutive_failures = 0;

        // Update progress in database
        if let Err(e) = sqlx::query(
            r#"
            UPDATE scan
            SET progress = $2,
                probes_completed = $3,
                probes_total = $4,
                vulnerabilities_found = $5
            WHERE id = $1
            "#,
        )
        .bind(scan_id)
        .bind(status_response.progress)
        .bind(status_response.probes_completed)
        .bind(status_response.probes_total)
        .bind(status_response.vulnerabilities_found)
        .execute(&state.db)
        .await
        {
            tracing::warn!("Failed to update scan progress: {}", e);
        }

        match status_response.status.as_str() {
            "completed" => {
                // Store vulnerabilities
                for vuln in &status_response.vulnerabilities {
                    if let Err(e) = sqlx::query(
                        r#"
                        INSERT INTO scan_result (scan_id, probe_name, category, severity, description, attack_prompt, model_response, recommendation)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                        "#
                    )
                    .bind(scan_id)
                    .bind(&vuln.probe_name)
                    .bind(&vuln.category)
                    .bind(&vuln.severity)
                    .bind(&vuln.description)
                    .bind(&vuln.attack_prompt)
                    .bind(&vuln.model_response)
                    .bind(&vuln.recommendation)
                    .execute(&state.db)
                    .await {
                        tracing::error!("Failed to store vulnerability: {}", e);
                    }
                }

                // Calculate risk score
                let risk_score = calculate_risk_score(&status_response.vulnerabilities);

                // Mark as completed
                if let Err(e) = sqlx::query(
                    "UPDATE scan SET status = 'completed', risk_score = $2, completed_at = $3 WHERE id = $1"
                )
                .bind(scan_id)
                .bind(risk_score)
                .bind(Utc::now().naive_utc())
                .execute(&state.db)
                .await {
                    tracing::error!("Failed to mark scan as completed: {}", e);
                }

                tracing::info!(
                    "Scan {} completed with {} vulnerabilities, risk score: {}",
                    scan_id,
                    status_response.vulnerabilities_found,
                    risk_score
                );
                break;
            }
            "failed" => {
                mark_scan_failed(&state, scan_id, &status_response.error_message).await;
                tracing::error!("Scan {} failed: {}", scan_id, status_response.error_message);
                break;
            }
            _ => {
                // Still running, continue polling
            }
        }
    }
}

fn calculate_risk_score(vulnerabilities: &[crate::grpc::ml_client::VulnerabilityInfo]) -> f32 {
    if vulnerabilities.is_empty() {
        return 0.0;
    }

    let mut score = 0.0f32;
    for vuln in vulnerabilities {
        score += match vuln.severity.as_str() {
            "critical" => 1.0,
            "high" => 0.75,
            "medium" => 0.5,
            "low" => 0.25,
            _ => 0.1,
        };
    }

    (score / vulnerabilities.len() as f32).min(1.0)
}

// ============================================
// List Scans
// ============================================

#[derive(Debug, Deserialize)]
pub struct ListScansParams {
    #[serde(default = "default_scan_limit")]
    pub limit: i64,
}

fn default_scan_limit() -> i64 {
    20
}

#[derive(Debug, Serialize)]
pub struct ScanListItem {
    pub id: Uuid,
    pub organization_id: Option<Uuid>,
    pub model_config_id: Option<Uuid>,
    pub scan_type: String,
    pub status: String,
    pub progress: i32,
    pub probes_total: i32,
    pub probes_completed: i32,
    pub vulnerabilities_found: i32,
    pub risk_score: Option<f32>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_by: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListScansResponse {
    pub scans: Vec<ScanListItem>,
}

/// List scans for the current user
///
/// **Auth: Session Required (Logged-in Users Only)**
pub async fn list_scans(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<ListScansParams>,
) -> Result<Json<ListScansResponse>, (StatusCode, Json<ErrorResponse>)> {
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    let limit = params.limit.min(100).max(1);

    let rows = sqlx::query(
        r#"
        SELECT id, organization_id, model_config_id, scan_type, status, progress,
               probes_total, probes_completed, vulnerabilities_found, risk_score,
               error_message, started_at, completed_at, created_by, created_at
        FROM scan
        WHERE created_by = $1
        ORDER BY created_at DESC
        LIMIT $2
        "#,
    )
    .bind(&user.user_id)
    .bind(limit)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Failed to list scans: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Failed to list scans",
                "DB_QUERY_FAILED",
            )),
        )
    })?;

    let scans: Vec<ScanListItem> = rows
        .into_iter()
        .map(|row| ScanListItem {
            id: row.get("id"),
            organization_id: row.get("organization_id"),
            model_config_id: row.get("model_config_id"),
            scan_type: row.get("scan_type"),
            status: row.get("status"),
            progress: row.get("progress"),
            probes_total: row.get("probes_total"),
            probes_completed: row.get("probes_completed"),
            vulnerabilities_found: row.get("vulnerabilities_found"),
            risk_score: row.get("risk_score"),
            error_message: row.get("error_message"),
            started_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("started_at")
                .map(|dt| dt.and_utc()),
            completed_at: row
                .get::<Option<chrono::NaiveDateTime>, _>("completed_at")
                .map(|dt| dt.and_utc()),
            created_by: row.get("created_by"),
            created_at: row.get::<chrono::NaiveDateTime, _>("created_at").and_utc(),
        })
        .collect();

    Ok(Json(ListScansResponse { scans }))
}

/// Get the current status of a scan
///
/// **Auth: Session Required (Logged-in Users Only)**
pub async fn get_scan_status(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
) -> Result<Json<ScanStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require valid session (authenticated users only)
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
        SELECT id, status, progress, probes_completed, probes_total,
               vulnerabilities_found, started_at, created_at, error_message
        FROM scan WHERE id = $1 AND created_by = $2
        "#,
    )
    .bind(scan_id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching scan status: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch scan status", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    match row {
        Some(row) => {
            let status: String = row.get("status");
            let progress: i32 = row.get("progress");
            let probes_completed: i32 = row.get("probes_completed");
            let probes_total: i32 = row.get("probes_total");
            let vulnerabilities_found: i32 = row.get("vulnerabilities_found");
            let started_at: Option<chrono::NaiveDateTime> = row.get("started_at");
            let created_at: chrono::NaiveDateTime = row.get("created_at");
            let error_message: Option<String> = row.get("error_message");

            Ok(Json(ScanStatusResponse {
                scan_id,
                status,
                progress: progress as u8,
                probes_completed: probes_completed as u32,
                probes_total: probes_total as u32,
                vulnerabilities_found: vulnerabilities_found as u32,
                started_at: started_at.map(|dt| dt.and_utc()),
                updated_at: created_at.and_utc(),
                error_message,
            }))
        }
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
        )),
    }
}

/// Get the results of a completed scan with pagination
///
/// **Auth: Session Required (Logged-in Users Only)**
pub async fn get_scan_results(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(scan_id): Path<Uuid>,
    Query(pagination): Query<PaginationParams>,
) -> Result<Json<ScanResultsResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Require valid session (authenticated users only)
    let user = require_session_from_headers(&state.db, &headers)
        .await
        .map_err(|(status, json)| {
            (
                status,
                Json(ErrorResponse::new(json.error.clone(), json.code.clone())),
            )
        })?;

    // Validate pagination params
    let page = pagination.page.max(1);
    let per_page = pagination
        .per_page
        .min(MAX_VULNERABILITIES_PER_PAGE as u32)
        .max(1);
    let offset = ((page - 1) * per_page) as i64;

    // Get scan info (with ownership check)
    let scan = sqlx::query(
        r#"
        SELECT id, status, probes_total, risk_score, completed_at, error_message
        FROM scan WHERE id = $1 AND created_by = $2
        "#,
    )
    .bind(scan_id)
    .bind(&user.user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching scan: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch scan", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?
    .ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("Scan not found", "SCAN_NOT_FOUND")),
        )
    })?;

    let status: String = scan.get("status");
    let probes_total: i32 = scan.get("probes_total");
    let risk_score: Option<f32> = scan.get("risk_score");
    let completed_at: Option<chrono::NaiveDateTime> = scan.get("completed_at");

    // Check if scan is completed
    if status != "completed" && status != "failed" {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                format!(
                    "Scan is still {}. Results are only available for completed scans.",
                    status
                ),
                "SCAN_NOT_COMPLETE",
            )),
        ));
    }

    // Get total vulnerability count
    let count_row = sqlx::query("SELECT COUNT(*) as count FROM scan_result WHERE scan_id = $1")
        .bind(scan_id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            tracing::error!("Database error counting vulnerabilities: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ErrorResponse::new("Failed to count vulnerabilities", "DB_QUERY_FAILED")
                        .with_details(e.to_string()),
                ),
            )
        })?;

    let total_items: i64 = count_row.get("count");
    let total_pages = ((total_items as f64) / (per_page as f64)).ceil() as u32;

    // Get vulnerabilities with pagination
    let vuln_rows = sqlx::query(
        r#"
        SELECT id, probe_name, category, severity, description,
               attack_prompt, model_response, recommendation
        FROM scan_result
        WHERE scan_id = $1
        ORDER BY
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            probe_name
        LIMIT $2 OFFSET $3
        "#,
    )
    .bind(scan_id)
    .bind(per_page as i64)
    .bind(offset)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching vulnerabilities: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch vulnerabilities", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    // Get severity breakdown (from all vulnerabilities, not just current page)
    let severity_rows = sqlx::query(
        r#"
        SELECT severity, COUNT(*) as count
        FROM scan_result
        WHERE scan_id = $1
        GROUP BY severity
        "#,
    )
    .bind(scan_id)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        tracing::error!("Database error fetching severity breakdown: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(
                ErrorResponse::new("Failed to fetch severity breakdown", "DB_QUERY_FAILED")
                    .with_details(e.to_string()),
            ),
        )
    })?;

    let mut severity_breakdown = SeverityBreakdown {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
    };

    for row in severity_rows {
        let severity: String = row.get("severity");
        let count: i64 = row.get("count");
        match severity.as_str() {
            "critical" => severity_breakdown.critical = count as u32,
            "high" => severity_breakdown.high = count as u32,
            "medium" => severity_breakdown.medium = count as u32,
            "low" => severity_breakdown.low = count as u32,
            _ => {}
        }
    }

    let vulnerabilities: Vec<Vulnerability> = vuln_rows
        .into_iter()
        .map(|row| Vulnerability {
            id: row.get("id"),
            probe_name: row.get("probe_name"),
            category: row.get("category"),
            severity: row.get("severity"),
            description: row.get("description"),
            attack_prompt: row.get("attack_prompt"),
            model_response: row.get("model_response"),
            recommendation: row.get("recommendation"),
        })
        .collect();

    let failed = total_items as u32;
    let passed = (probes_total as u32).saturating_sub(failed);

    Ok(Json(ScanResultsResponse {
        scan_id,
        status,
        summary: ScanSummary {
            total_probes: probes_total as u32,
            passed,
            failed,
            risk_score: risk_score.unwrap_or(0.0),
            severity_breakdown,
        },
        vulnerabilities,
        pagination: PaginationInfo {
            page,
            per_page,
            total_items: total_items as u32,
            total_pages,
        },
        completed_at: completed_at.map(|dt| dt.and_utc()),
    }))
}
