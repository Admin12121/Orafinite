// gRPC client for Python ML sidecar

use tonic::transport::Channel;
use std::time::Duration;

// Include generated protobuf code
pub mod ml_service {
    tonic::include_proto!("ml_service");
}

use ml_service::ml_service_client::MlServiceClient;
use ml_service::{
    ScanRequest, OutputScanRequest, GarakRequest, GarakStatusRequest,
    Empty,
};

// ============================================
// Configuration Constants
// ============================================

/// Connection timeout for establishing gRPC channel
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Default request timeout for quick operations (health check, status)
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// Timeout for prompt scanning (ML inference can take time)
const SCAN_TIMEOUT_SECS: u64 = 60;

/// Timeout for starting a Garak scan
const GARAK_START_TIMEOUT_SECS: u64 = 30;

/// Timeout for getting Garak status
const GARAK_STATUS_TIMEOUT_SECS: u64 = 15;

// ============================================
// Client Implementation
// ============================================

#[derive(Clone)]
pub struct MlClient {
    client: MlServiceClient<Channel>,
}

impl MlClient {
    /// Create a new ML client with connection to the sidecar
    ///
    /// This establishes a gRPC channel with configured timeouts.
    /// The connection is NOT lazy - it will fail immediately if the sidecar is unreachable.
    pub async fn new(addr: &str) -> Result<Self, tonic::transport::Error> {
        let endpoint = tonic::transport::Endpoint::from_shared(addr.to_string())?
            .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .tcp_keepalive(Some(Duration::from_secs(30)))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .keep_alive_timeout(Duration::from_secs(20))
            .keep_alive_while_idle(true);

        let channel = endpoint.connect().await?;
        let client = MlServiceClient::new(channel);

        Ok(Self { client })
    }

    /// Health check for ML sidecar
    ///
    /// Returns health status and version information.
    /// This should be called to verify the sidecar is ready before processing requests.
    pub async fn health_check(&mut self) -> Result<HealthInfo, tonic::Status> {
        let mut request = tonic::Request::new(Empty {});
        request.set_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let response = self.client.health_check(request).await?;
        let res = response.into_inner();

        Ok(HealthInfo {
            healthy: res.healthy,
            version: res.version,
        })
    }

    /// Scan a prompt using LLM Guard
    ///
    /// Performs ML-powered security scanning on the provided prompt.
    /// This is the primary endpoint for real-time prompt protection.
    ///
    /// # Errors
    /// Returns tonic::Status with appropriate error codes:
    /// - DeadlineExceeded: Scan took too long
    /// - Unavailable: ML sidecar is down
    /// - Internal: Processing error in sidecar
    pub async fn scan_prompt(&mut self, prompt: &str, options: ScanOptions) -> Result<ScanResult, tonic::Status> {
        let mut request = tonic::Request::new(ScanRequest {
            prompt: prompt.to_string(),
            check_injection: options.check_injection,
            check_toxicity: options.check_toxicity,
            check_pii: options.check_pii,
            sanitize: options.sanitize,
        });
        request.set_timeout(Duration::from_secs(SCAN_TIMEOUT_SECS));

        let response = self.client.scan_prompt(request).await?;
        let res = response.into_inner();

        Ok(ScanResult {
            safe: res.safe,
            sanitized_prompt: if res.sanitized_prompt.is_empty() { None } else { Some(res.sanitized_prompt) },
            risk_score: res.risk_score,
            threats: res.threats.into_iter().map(|t| Threat {
                threat_type: t.threat_type,
                confidence: t.confidence,
                description: t.description,
                severity: t.severity,
            }).collect(),
        })
    }

    /// Scan output using LLM Guard
    ///
    /// Validates LLM-generated output for security issues.
    pub async fn scan_output(&mut self, output: &str, original_prompt: Option<&str>) -> Result<OutputScanResult, tonic::Status> {
        let mut request = tonic::Request::new(OutputScanRequest {
            output: output.to_string(),
            original_prompt: original_prompt.unwrap_or("").to_string(),
        });
        request.set_timeout(Duration::from_secs(SCAN_TIMEOUT_SECS));

        let response = self.client.scan_output(request).await?;
        let res = response.into_inner();

        Ok(OutputScanResult {
            safe: res.safe,
            sanitized_output: if res.sanitized_output.is_empty() { None } else { Some(res.sanitized_output) },
            issues: res.issues.into_iter().map(|i| OutputIssue {
                issue_type: i.issue_type,
                description: i.description,
                severity: i.severity,
            }).collect(),
        })
    }

    /// Start a Garak vulnerability scan
    ///
    /// Initiates an asynchronous vulnerability scan against the specified model.
    /// Returns a scan ID that can be used to poll for status.
    pub async fn start_garak_scan(
        &mut self,
        model_config: ModelConfig,
        probes: Vec<String>,
        scan_type: &str,
    ) -> Result<String, tonic::Status> {
        let mut request = tonic::Request::new(GarakRequest {
            provider: model_config.provider,
            model: model_config.model,
            api_key: model_config.api_key.unwrap_or_default(),
            base_url: model_config.base_url.unwrap_or_default(),
            probes,
            scan_type: scan_type.to_string(),
        });
        request.set_timeout(Duration::from_secs(GARAK_START_TIMEOUT_SECS));

        let response = self.client.start_garak_scan(request).await?;
        Ok(response.into_inner().scan_id)
    }

    /// Get status of a Garak scan
    ///
    /// Polls the current status of a running or completed scan.
    pub async fn get_garak_status(&mut self, scan_id: &str) -> Result<GarakStatusResult, tonic::Status> {
        let mut request = tonic::Request::new(GarakStatusRequest {
            scan_id: scan_id.to_string(),
        });
        request.set_timeout(Duration::from_secs(GARAK_STATUS_TIMEOUT_SECS));

        let response = self.client.get_garak_status(request).await?;
        let res = response.into_inner();

        Ok(GarakStatusResult {
            scan_id: res.scan_id,
            status: res.status,
            progress: res.progress,
            probes_completed: res.probes_completed,
            probes_total: res.probes_total,
            vulnerabilities_found: res.vulnerabilities_found,
            vulnerabilities: res.vulnerabilities.into_iter().map(|v| VulnerabilityInfo {
                probe_name: v.probe_name,
                category: v.category,
                severity: v.severity,
                description: v.description,
                attack_prompt: v.attack_prompt,
                model_response: v.model_response,
                recommendation: v.recommendation,
            }).collect(),
            error_message: res.error_message,
        })
    }
}

// ============================================
// Data Types
// ============================================

#[derive(Debug)]
pub struct HealthInfo {
    pub healthy: bool,
    pub version: String,
}

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub check_injection: bool,
    pub check_toxicity: bool,
    pub check_pii: bool,
    pub sanitize: bool,
}

#[derive(Debug)]
pub struct ScanResult {
    pub safe: bool,
    pub sanitized_prompt: Option<String>,
    pub risk_score: f32,
    pub threats: Vec<Threat>,
}

#[derive(Debug)]
pub struct Threat {
    pub threat_type: String,
    pub confidence: f32,
    pub description: String,
    pub severity: String,
}

#[derive(Debug)]
pub struct OutputScanResult {
    pub safe: bool,
    pub sanitized_output: Option<String>,
    pub issues: Vec<OutputIssue>,
}

#[derive(Debug)]
pub struct OutputIssue {
    pub issue_type: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub provider: String,
    pub model: String,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
}

#[derive(Debug)]
pub struct GarakStatusResult {
    pub scan_id: String,
    pub status: String,
    pub progress: i32,
    pub probes_completed: i32,
    pub probes_total: i32,
    pub vulnerabilities_found: i32,
    pub vulnerabilities: Vec<VulnerabilityInfo>,
    pub error_message: String,
}

#[derive(Debug)]
pub struct VulnerabilityInfo {
    pub probe_name: String,
    pub category: String,
    pub severity: String,
    pub description: String,
    pub attack_prompt: String,
    pub model_response: String,
    pub recommendation: String,
}
