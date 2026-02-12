// gRPC client for Python ML sidecar

use std::collections::HashMap;
use std::time::Duration;
use tonic::transport::Channel;

// Include generated protobuf code
pub mod ml_service {
    tonic::include_proto!("ml_service");
}

use ml_service::ml_service_client::MlServiceClient;
use ml_service::{
    AdvancedScanRequest, Empty, GarakRequest, GarakStatusRequest, OutputScanRequest,
    ScanMode as ProtoScanMode, ScanRequest, ScannerConfig,
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

/// Timeout for advanced scanning (may run both input + output scanners)
const ADVANCED_SCAN_TIMEOUT_SECS: u64 = 120;

/// Timeout for starting a Garak scan
const GARAK_START_TIMEOUT_SECS: u64 = 30;

/// Timeout for getting Garak status
const GARAK_STATUS_TIMEOUT_SECS: u64 = 15;

// ============================================
// Scan Mode (mirrors proto ScanMode)
// ============================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanMode {
    PromptOnly,
    OutputOnly,
    Both,
}

impl Default for ScanMode {
    fn default() -> Self {
        ScanMode::PromptOnly
    }
}

impl ScanMode {
    /// Convert to proto enum i32 value
    fn to_proto_i32(self) -> i32 {
        match self {
            ScanMode::PromptOnly => ProtoScanMode::PromptOnly as i32,
            ScanMode::OutputOnly => ProtoScanMode::OutputOnly as i32,
            ScanMode::Both => ProtoScanMode::Both as i32,
        }
    }

    /// Convert from proto i32 value
    pub fn from_proto_i32(v: i32) -> Self {
        match v {
            1 => ScanMode::OutputOnly,
            2 => ScanMode::Both,
            _ => ScanMode::PromptOnly,
        }
    }
}

// ============================================
// Per-Scanner Configuration Entry
// ============================================

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScannerConfigEntry {
    /// Whether this scanner is enabled
    pub enabled: bool,

    /// Detection threshold (0.0 - 1.0)
    #[serde(default = "default_threshold")]
    pub threshold: f32,

    /// Scanner-specific settings as a JSON string.
    /// e.g. for BanTopics: {"topics": ["violence","religion"]}
    #[serde(default)]
    pub settings_json: String,
}

fn default_threshold() -> f32 {
    0.5
}

impl Default for ScannerConfigEntry {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: 0.5,
            settings_json: String::new(),
        }
    }
}

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
    /// Returns health status, version, and lists of available scanners.
    pub async fn health_check(&mut self) -> Result<HealthInfo, tonic::Status> {
        let mut request = tonic::Request::new(Empty {});
        request.set_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS));

        let response = self.client.health_check(request).await?;
        let res = response.into_inner();

        Ok(HealthInfo {
            healthy: res.healthy,
            version: res.version,
            available_input_scanners: res.available_input_scanners,
            available_output_scanners: res.available_output_scanners,
        })
    }

    /// Scan a prompt using LLM Guard (legacy simple API)
    ///
    /// Performs ML-powered security scanning on the provided prompt.
    /// Uses the basic boolean toggle options (injection, toxicity, PII).
    ///
    /// # Errors
    /// Returns tonic::Status with appropriate error codes:
    /// - DeadlineExceeded: Scan took too long
    /// - Unavailable: ML sidecar is down
    /// - Internal: Processing error in sidecar
    pub async fn scan_prompt(
        &mut self,
        prompt: &str,
        options: ScanOptions,
    ) -> Result<ScanResult, tonic::Status> {
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
            sanitized_prompt: if res.sanitized_prompt.is_empty() {
                None
            } else {
                Some(res.sanitized_prompt)
            },
            risk_score: res.risk_score,
            threats: res
                .threats
                .into_iter()
                .map(|t| Threat {
                    threat_type: t.threat_type,
                    confidence: t.confidence,
                    description: t.description,
                    severity: t.severity,
                })
                .collect(),
        })
    }

    /// Scan output using LLM Guard (legacy simple API)
    ///
    /// Validates LLM-generated output for security issues.
    pub async fn scan_output(
        &mut self,
        output: &str,
        original_prompt: Option<&str>,
    ) -> Result<OutputScanResult, tonic::Status> {
        let mut request = tonic::Request::new(OutputScanRequest {
            output: output.to_string(),
            original_prompt: original_prompt.unwrap_or("").to_string(),
        });
        request.set_timeout(Duration::from_secs(SCAN_TIMEOUT_SECS));

        let response = self.client.scan_output(request).await?;
        let res = response.into_inner();

        Ok(OutputScanResult {
            safe: res.safe,
            sanitized_output: if res.sanitized_output.is_empty() {
                None
            } else {
                Some(res.sanitized_output)
            },
            issues: res
                .issues
                .into_iter()
                .map(|i| OutputIssue {
                    issue_type: i.issue_type,
                    description: i.description,
                    severity: i.severity,
                })
                .collect(),
        })
    }

    /// Advanced scan with full per-scanner configuration (new API)
    ///
    /// Supports all LLM Guard input and output scanners with per-scanner
    /// enable/disable, thresholds, and scanner-specific settings.
    /// Also supports scan_mode to choose prompt-only, output-only, or both.
    ///
    /// # Arguments
    /// * `options` - Advanced scan options including scanner configs and scan mode
    ///
    /// # Errors
    /// Returns tonic::Status with appropriate error codes.
    pub async fn advanced_scan(
        &mut self,
        options: AdvancedScanOptions,
    ) -> Result<AdvancedScanResult, tonic::Status> {
        // Convert input scanner configs to proto map
        let input_scanners: HashMap<String, ScannerConfig> = options
            .input_scanners
            .into_iter()
            .map(|(name, cfg)| {
                (
                    name,
                    ScannerConfig {
                        enabled: cfg.enabled,
                        threshold: cfg.threshold,
                        settings_json: cfg.settings_json,
                    },
                )
            })
            .collect();

        // Convert output scanner configs to proto map
        let output_scanners: HashMap<String, ScannerConfig> = options
            .output_scanners
            .into_iter()
            .map(|(name, cfg)| {
                (
                    name,
                    ScannerConfig {
                        enabled: cfg.enabled,
                        threshold: cfg.threshold,
                        settings_json: cfg.settings_json,
                    },
                )
            })
            .collect();

        let mut request = tonic::Request::new(AdvancedScanRequest {
            prompt: options.prompt,
            output: options.output,
            scan_mode: options.scan_mode.to_proto_i32(),
            input_scanners,
            output_scanners,
            sanitize: options.sanitize,
            fail_fast: options.fail_fast,
        });
        request.set_timeout(Duration::from_secs(ADVANCED_SCAN_TIMEOUT_SECS));

        let response = self.client.advanced_scan(request).await?;
        let res = response.into_inner();

        Ok(AdvancedScanResult {
            safe: res.safe,
            sanitized_prompt: if res.sanitized_prompt.is_empty() {
                None
            } else {
                Some(res.sanitized_prompt)
            },
            sanitized_output: if res.sanitized_output.is_empty() {
                None
            } else {
                Some(res.sanitized_output)
            },
            risk_score: res.risk_score,
            input_results: res
                .input_results
                .into_iter()
                .map(|r| ScannerResultInfo {
                    scanner_name: r.scanner_name,
                    is_valid: r.is_valid,
                    score: r.score,
                    description: r.description,
                    severity: r.severity,
                    scanner_latency_ms: r.scanner_latency_ms,
                })
                .collect(),
            output_results: res
                .output_results
                .into_iter()
                .map(|r| ScannerResultInfo {
                    scanner_name: r.scanner_name,
                    is_valid: r.is_valid,
                    score: r.score,
                    description: r.description,
                    severity: r.severity,
                    scanner_latency_ms: r.scanner_latency_ms,
                })
                .collect(),
            latency_ms: res.latency_ms,
            scan_mode: ScanMode::from_proto_i32(res.scan_mode),
            input_scanners_run: res.input_scanners_run,
            output_scanners_run: res.output_scanners_run,
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
    pub async fn get_garak_status(
        &mut self,
        scan_id: &str,
    ) -> Result<GarakStatusResult, tonic::Status> {
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
            vulnerabilities: res
                .vulnerabilities
                .into_iter()
                .map(|v| VulnerabilityInfo {
                    probe_name: v.probe_name,
                    category: v.category,
                    severity: v.severity,
                    description: v.description,
                    attack_prompt: v.attack_prompt,
                    model_response: v.model_response,
                    recommendation: v.recommendation,
                })
                .collect(),
            error_message: res.error_message,
        })
    }
}

// ============================================
// Data Types — Legacy
// ============================================

#[derive(Debug)]
pub struct HealthInfo {
    pub healthy: bool,
    pub version: String,
    pub available_input_scanners: Vec<String>,
    pub available_output_scanners: Vec<String>,
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

// ============================================
// Data Types — Advanced Scan
// ============================================

/// Options for the advanced scan endpoint.
/// Carries per-scanner configs, scan mode, and text to scan.
#[derive(Debug, Clone)]
pub struct AdvancedScanOptions {
    /// Prompt text to scan (required for PromptOnly / Both)
    pub prompt: String,

    /// Output text to scan (required for OutputOnly / Both)
    pub output: String,

    /// What to scan: prompt only, output only, or both
    pub scan_mode: ScanMode,

    /// Per-scanner configuration for input (prompt) scanners.
    /// Key = scanner name in snake_case (e.g. "prompt_injection").
    /// Only entries with enabled=true will run.
    pub input_scanners: HashMap<String, ScannerConfigEntry>,

    /// Per-scanner configuration for output scanners.
    /// Key = scanner name in snake_case (e.g. "toxicity").
    /// Only entries with enabled=true will run.
    pub output_scanners: HashMap<String, ScannerConfigEntry>,

    /// Whether to return sanitized versions of prompt/output
    pub sanitize: bool,

    /// Whether to stop after first failing scanner (faster)
    pub fail_fast: bool,
}

impl Default for AdvancedScanOptions {
    fn default() -> Self {
        Self {
            prompt: String::new(),
            output: String::new(),
            scan_mode: ScanMode::PromptOnly,
            input_scanners: HashMap::new(),
            output_scanners: HashMap::new(),
            sanitize: false,
            fail_fast: false,
        }
    }
}

/// Result of an advanced scan call.
#[derive(Debug)]
pub struct AdvancedScanResult {
    /// Overall safety verdict (true only if ALL scanners passed)
    pub safe: bool,

    /// Sanitized prompt (if sanitize=true and scan_mode includes prompt)
    pub sanitized_prompt: Option<String>,

    /// Sanitized output (if sanitize=true and scan_mode includes output)
    pub sanitized_output: Option<String>,

    /// Overall risk score (max of failing scanner scores)
    pub risk_score: f32,

    /// Results from each input (prompt) scanner that was executed
    pub input_results: Vec<ScannerResultInfo>,

    /// Results from each output scanner that was executed
    pub output_results: Vec<ScannerResultInfo>,

    /// Total scan latency in milliseconds
    pub latency_ms: i32,

    /// Which scan mode was executed
    pub scan_mode: ScanMode,

    /// Number of input scanners that were run
    pub input_scanners_run: i32,

    /// Number of output scanners that were run
    pub output_scanners_run: i32,
}

/// Result from a single scanner execution.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScannerResultInfo {
    /// Scanner name (e.g. "prompt_injection", "toxicity")
    pub scanner_name: String,

    /// Whether this scanner passed (true = safe)
    pub is_valid: bool,

    /// Scanner-specific score
    pub score: f32,

    /// Human-readable description
    pub description: String,

    /// Severity level: critical, high, medium, low
    pub severity: String,

    /// Scanner execution time in milliseconds
    pub scanner_latency_ms: i32,
}

// ============================================
// Data Types — Garak
// ============================================

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
