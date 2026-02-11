"use server";

import { scanApi } from "@/lib/api";

export interface Scan {
  id: string;
  organizationId: string | null;
  modelConfigId: string | null;
  scanType: string;
  status: string;
  progress: number;
  probesTotal: number;
  probesCompleted: number;
  vulnerabilitiesFound: number;
  riskScore: number | null;
  errorMessage: string | null;
  startedAt: string | null;
  completedAt: string | null;
  createdBy: string | null;
  createdAt: string;
}

export interface ScanResult {
  id: string;
  probeName: string;
  category: string;
  severity: string;
  description: string;
  attackPrompt: string;
  modelResponse: string;
  recommendation: string;
}

export interface StartScanInput {
  modelConfigId?: string;
  scanType: "quick" | "standard" | "comprehensive" | "custom";
  provider: string;
  model: string;
  apiKey?: string;
  baseUrl?: string;
}

/**
 * Start a new vulnerability scan via Rust API
 * Calls Rust API: POST /v1/scan/start
 */
export async function startScan(input: StartScanInput): Promise<
  | {
      scanId: string;
      status: string;
      estimatedDuration: number;
    }
  | { error: string }
> {
  const { data, error } = await scanApi.startScan({
    model_config: {
      provider: input.provider,
      model: input.model,
      api_key: input.apiKey,
      base_url: input.baseUrl,
    },
    scan_type: input.scanType,
    probes: [],
  });

  if (error) {
    return { error: error.message };
  }

  return {
    scanId: data.scan_id,
    status: data.status,
    estimatedDuration: data.estimated_duration_seconds,
  };
}

/**
 * Get scan status via Rust API
 * Calls Rust API: GET /v1/scan/{scanId}
 */
export async function getScanStatus(scanId: string): Promise<
  | {
      scanId: string;
      status: string;
      progress: number;
      probesCompleted: number;
      probesTotal: number;
      vulnerabilitiesFound: number;
      errorMessage?: string;
    }
  | { error: string }
> {
  const { data, error } = await scanApi.getScanStatus(scanId);

  if (error) {
    return { error: error.message };
  }

  return {
    scanId: data.scan_id,
    status: data.status,
    progress: data.progress,
    probesCompleted: data.probes_completed,
    probesTotal: data.probes_total,
    vulnerabilitiesFound: data.vulnerabilities_found,
    errorMessage: data.error_message ?? undefined,
  };
}

/**
 * List recent scans for the current user
 * Calls Rust API: GET /v1/scan/list
 */
export async function listScans(limit = 20): Promise<Scan[]> {
  const { data, error } = await scanApi.listScans(limit);
  if (error) {
    console.error("Failed to list scans:", error.message);
    return [];
  }
  return data.scans.map((s) => ({
    id: s.id,
    organizationId: s.organization_id,
    modelConfigId: s.model_config_id,
    scanType: s.scan_type,
    status: s.status,
    progress: s.progress,
    probesTotal: s.probes_total,
    probesCompleted: s.probes_completed,
    vulnerabilitiesFound: s.vulnerabilities_found,
    riskScore: s.risk_score,
    errorMessage: s.error_message,
    startedAt: s.started_at,
    completedAt: s.completed_at,
    createdBy: s.created_by,
    createdAt: s.created_at,
  }));
}

/**
 * Get scan results
 * Calls Rust API: GET /v1/scan/{scanId}/results
 */
export async function getScanResults(scanId: string): Promise<ScanResult[]> {
  const { data, error } = await scanApi.getScanResults(scanId);
  if (error) {
    console.error("Failed to get scan results:", error.message);
    return [];
  }
  return data.vulnerabilities.map((v) => ({
    id: v.id,
    probeName: v.probe_name,
    category: v.category,
    severity: v.severity,
    description: v.description,
    attackPrompt: v.attack_prompt,
    modelResponse: v.model_response,
    recommendation: v.recommendation,
  }));
}
