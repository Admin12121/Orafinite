"use server";

import {
  guardApi,
  apiClientWithKey,
  type ScanPromptResponse,
  type GuardStatsResponse,
} from "@/lib/api";

export interface GuardLog {
  id: string;
  organizationId: string;
  apiKeyId: string | null;
  promptHash: string;
  isSafe: boolean;
  riskScore: number | null;
  threatsDetected: unknown;
  latencyMs: number | null;
  cached: boolean | null;
  ipAddress: string | null;
  createdAt: string;
}

export interface ScanPromptInput {
  prompt: string;
  apiKey: string;
  options?: {
    checkInjection?: boolean;
    checkToxicity?: boolean;
    checkPii?: boolean;
    sanitize?: boolean;
  };
}

export interface ScanPromptResult {
  id: string;
  safe: boolean;
  sanitizedPrompt?: string;
  threats: Array<{
    threatType: string;
    confidence: number;
    description: string;
    severity: string;
  }>;
  riskScore: number;
  latencyMs: number;
  cached: boolean;
}

/**
 * Scan a prompt using the Guard API (for testing in dashboard)
 * Calls Rust API: POST /v1/guard/scan (with API key auth)
 */
export async function scanPrompt(
  input: ScanPromptInput,
): Promise<ScanPromptResult | { error: string }> {
  const { data, error } = await apiClientWithKey<ScanPromptResponse>(
    "/v1/guard/scan",
    input.apiKey,
    {
      method: "POST",
      body: JSON.stringify({
        prompt: input.prompt,
        options: {
          check_injection: input.options?.checkInjection ?? true,
          check_toxicity: input.options?.checkToxicity ?? true,
          check_pii: input.options?.checkPii ?? true,
          sanitize: input.options?.sanitize ?? false,
        },
      }),
    },
  );

  if (error) {
    return { error: error.message };
  }

  return {
    id: data.id,
    safe: data.safe,
    sanitizedPrompt: data.sanitized_prompt,
    threats: data.threats.map((t) => ({
      threatType: t.threat_type,
      confidence: t.confidence,
      description: t.description,
      severity: t.severity,
    })),
    riskScore: data.risk_score,
    latencyMs: data.latency_ms,
    cached: data.cached,
  };
}

/**
 * List guard logs for the current organization
 * Calls Rust API: GET /v1/guard/logs
 */
export async function listGuardLogs(limit = 50): Promise<GuardLog[]> {
  const { data, error } = await guardApi.listLogs(limit);
  if (error) {
    console.error("Failed to list guard logs:", error.message);
    return [];
  }
  return data.logs.map((log) => ({
    id: log.id,
    organizationId: log.organization_id,
    apiKeyId: log.api_key_id,
    promptHash: log.prompt_hash,
    isSafe: log.is_safe,
    riskScore: log.risk_score,
    threatsDetected: log.threats_detected,
    latencyMs: log.latency_ms,
    cached: log.cached,
    ipAddress: log.ip_address,
    createdAt: log.created_at,
  }));
}

/**
 * Get guard statistics
 * Calls Rust API: GET /v1/guard/stats
 * @param period Optional time filter: "today", "24h", "48h", "3d", "7d"
 */
export async function getGuardStats(period?: string): Promise<{
  totalScans: number;
  threatsBlocked: number;
  safePrompts: number;
  avgLatency: number;
}> {
  const { data, error } = await guardApi.getStats(period);
  if (error) {
    console.error("Failed to get guard stats:", error.message);
    return { totalScans: 0, threatsBlocked: 0, safePrompts: 0, avgLatency: 0 };
  }
  return {
    totalScans: data.total_scans,
    threatsBlocked: data.threats_blocked,
    safePrompts: data.safe_prompts,
    avgLatency: data.avg_latency,
  };
}
