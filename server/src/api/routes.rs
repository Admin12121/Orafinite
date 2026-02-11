use axum::{
    routing::{delete, get, post, put},
    Router,
};

use super::AppState;
use super::{api_keys, auth, events, guard, guard_logs, models, organization, scan};

/// V1 API routes
///
/// ## Public Routes (no auth required)
/// - POST /auth/verify - Verify session token (used by Next.js)
/// - POST /auth/api-key/verify - Verify API key
///
/// ## LLM Guard Routes (API Key Required)
/// - POST /guard/scan - Scan prompt for injection/jailbreak attacks (legacy simple API)
/// - POST /guard/validate - Validate LLM output for PII/sensitive data (legacy simple API)
/// - POST /guard/advanced-scan - Advanced scan with full per-scanner customization
///
/// ## Garak Scanner Routes (Session Required)
/// - POST /scan/start - Start vulnerability scan
/// - GET  /scan/list - List user's scans
/// - GET  /scan/{scan_id} - Get scan status
/// - GET  /scan/{scan_id}/results - Get scan results
///
/// ## API Key Management (Session Required)
/// - POST /api-keys - Create API key
/// - GET  /api-keys - List API keys
/// - DELETE /api-keys/{key_id} - Revoke API key
///
/// ## Model Configuration (Session Required)
/// - POST /models - Create model config
/// - GET  /models - List model configs
/// - DELETE /models/{model_id} - Delete model config
/// - PUT  /models/{model_id}/default - Set default model
///
/// ## Organization (Session Required)
/// - POST /organization - Get or create organization
/// - GET  /organization - Get current organization
///
/// ## Guard Logs (Session Required)
/// - GET  /guard/logs - List guard logs
/// - GET  /guard/stats - Get guard statistics
pub fn v1_routes() -> Router<AppState> {
    Router::new()
        // ========================================
        // Public: Auth verification endpoints
        // ========================================
        .route("/auth/verify", post(auth::verify_session))
        .route("/auth/api-key/verify", post(auth::verify_api_key))
        // ========================================
        // LLM Guard: API Key auth (external apps)
        // ========================================
        .route("/guard/scan", post(guard::scan_prompt))
        .route("/guard/batch", post(guard::batch_scan))
        .route("/guard/validate", post(guard::validate_output))
        .route("/guard/advanced-scan", post(guard::advanced_scan))
        // ========================================
        // Guard Logs: Session auth (dashboard)
        // ========================================
        .route("/guard/logs", get(guard_logs::list_guard_logs))
        .route("/guard/stats", get(guard_logs::get_guard_stats))
        // ========================================
        // Guard Events: SSE real-time stream
        // ========================================
        .route("/guard/events", get(events::guard_events))
        // ========================================
        // Garak Scanner: Session auth (users)
        // ========================================
        .route("/scan/start", post(scan::start_scan))
        .route("/scan/list", get(scan::list_scans))
        .route("/scan/{scan_id}", get(scan::get_scan_status))
        .route("/scan/{scan_id}/results", get(scan::get_scan_results))
        // ========================================
        // API Key Management: Session auth
        // ========================================
        .route("/api-keys", post(api_keys::create_api_key))
        .route("/api-keys", get(api_keys::list_api_keys))
        .route("/api-keys/{key_id}", delete(api_keys::revoke_api_key))
        // ========================================
        // Model Configuration: Session auth
        // ========================================
        .route("/models", post(models::create_model_config))
        .route("/models", get(models::list_model_configs))
        .route("/models/{model_id}", delete(models::delete_model_config))
        .route("/models/{model_id}/default", put(models::set_default_model))
        // ========================================
        // Organization: Session auth
        // ========================================
        .route(
            "/organization",
            post(organization::get_or_create_organization),
        )
        .route("/organization", get(organization::get_current_organization))
}
