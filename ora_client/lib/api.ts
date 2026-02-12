import { getSessionToken } from "./session";

// Rust API base URL
const API_BASE_URL = process.env.RUST_API_URL || "http://localhost:8080";

// ============================================================
// Scanner Metadata Constants
// ============================================================

/** All available input (prompt) scanner names */
export const ALL_INPUT_SCANNERS = [
  "anonymize",
  "ban_code",
  "ban_competitors",
  "ban_substrings",
  "ban_topics",
  "code",
  "gibberish",
  "invisible_text",
  "language",
  "prompt_injection",
  "regex",
  "secrets",
  "sentiment",
  "token_limit",
  "toxicity",
] as const;

/** All available output scanner names */
export const ALL_OUTPUT_SCANNERS = [
  "ban_code",
  "ban_competitors",
  "ban_substrings",
  "ban_topics",
  "bias",
  "code",
  "deanonymize",
  "json",
  "language",
  "language_same",
  "malicious_urls",
  "no_refusal",
  "reading_time",
  "factual_consistency",
  "gibberish",
  "regex",
  "relevance",
  "sensitive",
  "sentiment",
  "toxicity",
  "url_reachability",
] as const;

export type InputScannerName = (typeof ALL_INPUT_SCANNERS)[number];
export type OutputScannerName = (typeof ALL_OUTPUT_SCANNERS)[number];

/** Human-readable labels and descriptions for every scanner */
export const SCANNER_META: Record<
  string,
  {
    label: string;
    description: string;
    category: string;
    requiresSettings?: boolean;
    settingsHint?: string;
  }
> = {
  // ── Input scanners ──────────────────────────────────────
  anonymize: {
    label: "Anonymize (PII)",
    description:
      "Detects and redacts personally identifiable information such as names, emails, phone numbers, SSNs, and credit cards.",
    category: "Privacy",
    settingsHint:
      '{"entity_types":["PERSON","EMAIL","PHONE_NUMBER"],"use_faker":false,"language":"en"}',
  },
  ban_code: {
    label: "Ban Code",
    description:
      "Detects and blocks code snippets in specific programming languages.",
    category: "Content",
    settingsHint: '{"languages":["python","javascript"],"is_blocked":true}',
  },
  ban_competitors: {
    label: "Ban Competitors",
    description:
      "Identifies and optionally redacts mentions of competitor organizations.",
    category: "Business",
    requiresSettings: true,
    settingsHint: '{"competitors":["CompanyA","CompanyB"],"redact":false}',
  },
  ban_substrings: {
    label: "Ban Substrings",
    description:
      "Blocks prompts containing specified banned substrings or words.",
    category: "Content",
    requiresSettings: true,
    settingsHint:
      '{"substrings":["badword1","badword2"],"match_type":"word","case_sensitive":false}',
  },
  ban_topics: {
    label: "Ban Topics",
    description:
      "Uses zero-shot classification to block specific topics like violence, religion, etc.",
    category: "Content",
    requiresSettings: true,
    settingsHint: '{"topics":["violence","religion","politics"]}',
  },
  code: {
    label: "Code Detection",
    description:
      "Detects code in the prompt. Can allow or block specific languages.",
    category: "Content",
    settingsHint: '{"languages":["python"],"is_blocked":false}',
  },
  gibberish: {
    label: "Gibberish",
    description:
      "Detects nonsensical or gibberish input that could waste LLM resources.",
    category: "Quality",
  },
  invisible_text: {
    label: "Invisible Text",
    description:
      "Detects invisible unicode characters that may be used for prompt injection.",
    category: "Security",
  },
  language: {
    label: "Language",
    description: "Ensures the prompt is in an allowed language.",
    category: "Quality",
    settingsHint: '{"valid_languages":["en","es","fr"]}',
  },
  prompt_injection: {
    label: "Prompt Injection",
    description:
      "Detects prompt injection and jailbreak attempts using ML classification.",
    category: "Security",
  },
  regex: {
    label: "Regex Pattern",
    description:
      "Matches custom regex patterns to detect or redact specific content.",
    category: "Custom",
    requiresSettings: true,
    settingsHint:
      '{"patterns":["\\\\d{3}-\\\\d{2}-\\\\d{4}"],"match_type":"search","redact":true}',
  },
  secrets: {
    label: "Secrets",
    description:
      "Detects API keys, tokens, passwords, and other secrets in the prompt.",
    category: "Security",
  },
  sentiment: {
    label: "Sentiment",
    description: "Analyzes prompt sentiment and flags overly negative content.",
    category: "Quality",
  },
  token_limit: {
    label: "Token Limit",
    description:
      "Ensures the prompt does not exceed a maximum token count (DoS protection).",
    category: "Security",
    settingsHint: '{"limit":4096,"encoding_name":"cl100k_base"}',
  },
  toxicity: {
    label: "Toxicity",
    description: "Detects toxic, offensive, or hateful content.",
    category: "Safety",
  },
  // ── Output scanners ─────────────────────────────────────
  bias: {
    label: "Bias",
    description: "Detects biased or prejudiced content in LLM output.",
    category: "Safety",
  },
  deanonymize: {
    label: "Deanonymize",
    description:
      "Restores previously anonymized entities back to their original values.",
    category: "Privacy",
  },
  json: {
    label: "JSON Validation",
    description:
      "Validates that the output is well-formed JSON and optionally repairs it.",
    category: "Quality",
    settingsHint: '{"required_elements":0,"repair":true}',
  },
  language_same: {
    label: "Language Same",
    description: "Ensures the output language matches the input language.",
    category: "Quality",
  },
  malicious_urls: {
    label: "Malicious URLs",
    description: "Detects malicious or phishing URLs in the output.",
    category: "Security",
  },
  no_refusal: {
    label: "No Refusal",
    description:
      "Detects when the LLM refuses to answer a legitimate question.",
    category: "Quality",
  },
  reading_time: {
    label: "Reading Time",
    description: "Ensures the output can be read within a maximum time limit.",
    category: "Quality",
    settingsHint: '{"max_seconds":60,"truncate":false}',
  },
  factual_consistency: {
    label: "Factual Consistency",
    description:
      "Checks if the output is factually consistent with the input prompt.",
    category: "Quality",
  },
  relevance: {
    label: "Relevance",
    description: "Checks if the output is relevant to the input prompt.",
    category: "Quality",
  },
  sensitive: {
    label: "Sensitive Data",
    description:
      "Detects sensitive information (PII, credentials) leaking in the output.",
    category: "Privacy",
    settingsHint: '{"entity_types":["PERSON","EMAIL"],"redact":true}',
  },
  url_reachability: {
    label: "URL Reachability",
    description:
      "Checks whether URLs in the output are reachable and return valid status codes.",
    category: "Quality",
    settingsHint: '{"success_status_codes":[200,301,302]}',
  },
};

// API error type
export class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public code?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

// API response wrapper
type ApiResponse<T> =
  | {
      data: T;
      error: null;
    }
  | {
      data: null;
      error: ApiError;
    };

/**
 * Authenticated API client for Rust backend
 * Automatically includes Bearer token from session
 */
export async function apiClient<T>(
  endpoint: string,
  options: RequestInit = {},
): Promise<ApiResponse<T>> {
  const token = await getSessionToken();

  if (!token) {
    return {
      data: null,
      error: new ApiError("Not authenticated", 401, "UNAUTHORIZED"),
    };
  }

  const url = `${API_BASE_URL}${endpoint}`;
  const headers = new Headers(options.headers);

  // Add authorization header
  headers.set("Authorization", `Bearer ${token}`);
  headers.set("Content-Type", "application/json");

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      return {
        data: null,
        error: new ApiError(
          errorBody.error || `API error: ${response.status}`,
          response.status,
          errorBody.code,
        ),
      };
    }

    const data = await response.json();
    return { data, error: null };
  } catch (err) {
    return {
      data: null,
      error: new ApiError(
        err instanceof Error ? err.message : "Network error",
        0,
        "NETWORK_ERROR",
      ),
    };
  }
}

/**
 * API client with custom API key auth (for Guard endpoints)
 */
export async function apiClientWithKey<T>(
  endpoint: string,
  apiKey: string,
  options: RequestInit = {},
): Promise<ApiResponse<T>> {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = new Headers(options.headers);

  headers.set("X-API-Key", apiKey);
  headers.set("Content-Type", "application/json");

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      return {
        data: null,
        error: new ApiError(
          errorBody.error || `API error: ${response.status}`,
          response.status,
          errorBody.code,
        ),
      };
    }

    const data = await response.json();
    return { data, error: null };
  } catch (err) {
    return {
      data: null,
      error: new ApiError(
        err instanceof Error ? err.message : "Network error",
        0,
        "NETWORK_ERROR",
      ),
    };
  }
}

// Convenience methods for common HTTP methods

export const api = {
  get: <T>(endpoint: string) => apiClient<T>(endpoint, { method: "GET" }),

  post: <T>(endpoint: string, body?: unknown) =>
    apiClient<T>(endpoint, {
      method: "POST",
      body: body ? JSON.stringify(body) : undefined,
    }),

  put: <T>(endpoint: string, body?: unknown) =>
    apiClient<T>(endpoint, {
      method: "PUT",
      body: body ? JSON.stringify(body) : undefined,
    }),

  delete: <T>(endpoint: string) => apiClient<T>(endpoint, { method: "DELETE" }),
};

// ============================================================
// Typed API endpoints
// ============================================================

// --- Guard API (legacy simple) ---

export interface ScanPromptRequest {
  prompt: string;
  options?: {
    check_injection?: boolean;
    check_toxicity?: boolean;
    check_pii?: boolean;
    sanitize?: boolean;
  };
}

export interface ThreatDetection {
  threat_type: string;
  confidence: number;
  description: string;
  severity: string;
}

export interface ScanPromptResponse {
  id: string;
  safe: boolean;
  sanitized_prompt?: string;
  threats: ThreatDetection[];
  risk_score: number;
  latency_ms: number;
  cached: boolean;
  timestamp: string;
  threat_categories?: string[];
}

// --- Guard API (advanced scan) ---

export type ApiScanMode = "prompt_only" | "output_only" | "both";

export interface ApiScannerConfig {
  enabled: boolean;
  threshold: number;
  settings_json: string;
}

export interface AdvancedScanRequest {
  prompt?: string;
  output?: string;
  scan_mode: ApiScanMode;
  input_scanners: Record<string, ApiScannerConfig>;
  output_scanners: Record<string, ApiScannerConfig>;
  sanitize?: boolean;
  fail_fast?: boolean;
}

export interface AdvancedScannerResult {
  scanner_name: string;
  is_valid: boolean;
  score: number;
  description: string;
  severity: string;
  scanner_latency_ms: number;
}

export interface AdvancedScanResponse {
  id: string;
  safe: boolean;
  sanitized_prompt?: string;
  sanitized_output?: string;
  risk_score: number;
  scan_mode: ApiScanMode;
  input_results: AdvancedScannerResult[];
  output_results: AdvancedScannerResult[];
  latency_ms: number;
  input_scanners_run: number;
  output_scanners_run: number;
  threat_categories?: string[];
  cached: boolean;
  timestamp: string;
}

// --- Guard Logs ---

export interface GuardLogItem {
  id: string;
  organization_id: string;
  api_key_id: string | null;
  prompt_hash: string;
  is_safe: boolean;
  risk_score: number | null;
  threats_detected: unknown;
  threat_categories: string[] | null;
  latency_ms: number | null;
  cached: boolean | null;
  ip_address: string | null;
  request_type: string | null;
  user_agent: string | null;
  scan_options: unknown | null;
  response_id: string | null;
  /** Full prompt text — only populated for threats (null for safe prompts) */
  prompt_text: string | null;
  sanitized_prompt: string | null;
  created_at: string;
}

export interface PaginationMeta {
  page: number;
  per_page: number;
  total_items: number;
  total_pages: number;
  next_cursor: string | null;
  has_next: boolean;
  has_prev: boolean;
}

export interface ListGuardLogsResponse {
  logs: GuardLogItem[];
  pagination: PaginationMeta;
}

export interface TypeBreakdown {
  request_type: string;
  count: number;
}

export interface CategoryCount {
  category: string;
  count: number;
}

export interface GuardStatsResponse {
  total_scans: number;
  threats_blocked: number;
  safe_prompts: number;
  avg_latency: number;
  by_type?: TypeBreakdown[];
  top_categories?: CategoryCount[];
}

// --- Scan API ---

export interface StartScanRequest {
  model_config: {
    provider: string;
    model: string;
    api_key?: string;
    base_url?: string;
  };
  scan_type: string;
  probes: string[];
}

export interface StartScanResponse {
  scan_id: string;
  status: string;
  estimated_duration_seconds: number;
  created_at: string;
}

export interface ScanStatusResponse {
  scan_id: string;
  status: string;
  progress: number;
  probes_completed: number;
  probes_total: number;
  vulnerabilities_found: number;
  started_at: string | null;
  updated_at: string;
  error_message: string | null;
}

export interface ScanListItem {
  id: string;
  organization_id: string | null;
  model_config_id: string | null;
  scan_type: string;
  status: string;
  progress: number;
  probes_total: number;
  probes_completed: number;
  vulnerabilities_found: number;
  risk_score: number | null;
  error_message: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_by: string | null;
  created_at: string;
}

export interface ListScansResponse {
  scans: ScanListItem[];
}

export interface ScanResultsResponse {
  scan_id: string;
  status: string;
  summary: {
    total_probes: number;
    passed: number;
    failed: number;
    risk_score: number;
    severity_breakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
    };
  };
  vulnerabilities: Array<{
    id: string;
    probe_name: string;
    category: string;
    severity: string;
    description: string;
    attack_prompt: string;
    model_response: string;
    recommendation: string;
  }>;
  pagination: {
    page: number;
    per_page: number;
    total_items: number;
    total_pages: number;
  };
  completed_at: string | null;
}

// --- API Keys ---

export interface CreateApiKeyRequest {
  name: string;
  scopes?: string[];
}

export interface CreateApiKeyResponse {
  id: string;
  key: string;
  prefix: string;
  name: string;
  scopes: string[];
  created_at: string;
}

export interface ApiKeyItem {
  id: string;
  organization_id: string;
  name: string;
  key_prefix: string;
  scopes: string[] | null;
  rate_limit_rpm: number | null;
  last_used_at: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  created_by: string;
  created_at: string;
}

export interface ListApiKeysResponse {
  keys: ApiKeyItem[];
}

export interface RevokeApiKeyResponse {
  success: boolean;
}

// --- Model Configs ---

export interface CreateModelConfigRequest {
  name: string;
  provider: string;
  model: string;
  api_key?: string;
  base_url?: string;
  is_default?: boolean;
}

export interface ModelConfigItem {
  id: string;
  organization_id: string;
  name: string;
  provider: string;
  model: string;
  base_url: string | null;
  settings: unknown;
  is_default: boolean | null;
  created_at: string;
  updated_at: string;
}

export interface ListModelConfigsResponse {
  models: ModelConfigItem[];
}

export interface DeleteResponse {
  success: boolean;
}

// --- Organization ---

export interface OrganizationResponse {
  id: string;
  name: string;
  slug: string;
  owner_id: string;
  plan: string | null;
  created_at: string;
  updated_at: string;
}

// ============================================================
// Typed API methods
// ============================================================

// --- Guard Log Query Params ---

export interface ListGuardLogsParams {
  page?: number;
  per_page?: number;
  status?: "safe" | "threat";
  request_type?: "scan" | "validate" | "batch";
  category?: string;
  ip?: string;
  cursor?: string;
  from?: string;
  to?: string;
}

function buildLogsQuery(params: ListGuardLogsParams = {}): string {
  const q = new URLSearchParams();
  if (params.page) q.set("page", String(params.page));
  if (params.per_page) q.set("per_page", String(params.per_page));
  if (params.status) q.set("status", params.status);
  if (params.request_type) q.set("request_type", params.request_type);
  if (params.category) q.set("category", params.category);
  if (params.ip) q.set("ip", params.ip);
  if (params.cursor) q.set("cursor", params.cursor);
  if (params.from) q.set("from", params.from);
  if (params.to) q.set("to", params.to);
  const qs = q.toString();
  return qs ? `?${qs}` : "";
}

export const guardApi = {
  scanPrompt: (apiKey: string, data: ScanPromptRequest) =>
    apiClientWithKey<ScanPromptResponse>("/v1/guard/scan", apiKey, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  advancedScan: (apiKey: string, data: AdvancedScanRequest) =>
    apiClientWithKey<AdvancedScanResponse>("/v1/guard/advanced-scan", apiKey, {
      method: "POST",
      body: JSON.stringify(data),
    }),
  listLogs: (params: ListGuardLogsParams = {}) =>
    api.get<ListGuardLogsResponse>(`/v1/guard/logs${buildLogsQuery(params)}`),
  getStats: (period?: string) =>
    api.get<GuardStatsResponse>(
      period ? `/v1/guard/stats?period=${period}` : "/v1/guard/stats",
    ),
};

export const scanApi = {
  startScan: (data: StartScanRequest) =>
    api.post<StartScanResponse>("/v1/scan/start", data),
  listScans: (limit = 20) =>
    api.get<ListScansResponse>(`/v1/scan/list?limit=${limit}`),
  getScanStatus: (scanId: string) =>
    api.get<ScanStatusResponse>(`/v1/scan/${scanId}`),
  getScanResults: (scanId: string, page = 1, perPage = 50) =>
    api.get<ScanResultsResponse>(
      `/v1/scan/${scanId}/results?page=${page}&per_page=${perPage}`,
    ),
};

export const apiKeysApi = {
  create: (data: CreateApiKeyRequest) =>
    api.post<CreateApiKeyResponse>("/v1/api-keys", data),
  list: () => api.get<ListApiKeysResponse>("/v1/api-keys"),
  revoke: (keyId: string) =>
    api.delete<RevokeApiKeyResponse>(`/v1/api-keys/${keyId}`),
};

export const modelsApi = {
  create: (data: CreateModelConfigRequest) =>
    api.post<ModelConfigItem>("/v1/models", data),
  list: () => api.get<ListModelConfigsResponse>("/v1/models"),
  delete: (modelId: string) =>
    api.delete<DeleteResponse>(`/v1/models/${modelId}`),
  setDefault: (modelId: string) =>
    api.put<DeleteResponse>(`/v1/models/${modelId}/default`),
};

export const organizationApi = {
  getOrCreate: () => api.post<OrganizationResponse>("/v1/organization"),
  getCurrent: () => api.get<OrganizationResponse | null>("/v1/organization"),
};
