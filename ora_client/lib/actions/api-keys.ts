"use server";

import { apiKeysApi } from "@/lib/api";

export interface ApiKey {
  id: string;
  organizationId: string;
  name: string;
  keyPrefix: string;
  scopes: string[] | null;
  rateLimitRpm: number | null;
  lastUsedAt: string | null;
  expiresAt: string | null;
  revokedAt: string | null;
  createdBy: string;
  createdAt: string;
}

/**
 * Create a new API key
 * Calls Rust API: POST /v1/api-keys
 */
export async function createApiKey(
  name: string,
  scopes: string[] = [],
): Promise<{ key: string; id: string }> {
  const { data, error } = await apiKeysApi.create({ name, scopes });
  if (error) {
    throw new Error(error.message);
  }
  return { key: data.key, id: data.id };
}

/**
 * List all API keys for the current organization
 * Calls Rust API: GET /v1/api-keys
 */
export async function listApiKeys(): Promise<ApiKey[]> {
  const { data, error } = await apiKeysApi.list();
  if (error) {
    console.error("Failed to list API keys:", error.message);
    return [];
  }
  return data.keys.map((k) => ({
    id: k.id,
    organizationId: k.organization_id,
    name: k.name,
    keyPrefix: k.key_prefix,
    scopes: k.scopes,
    rateLimitRpm: k.rate_limit_rpm,
    lastUsedAt: k.last_used_at,
    expiresAt: k.expires_at,
    revokedAt: k.revoked_at,
    createdBy: k.created_by,
    createdAt: k.created_at,
  }));
}

/**
 * Revoke an API key
 * Calls Rust API: DELETE /v1/api-keys/{keyId}
 */
export async function revokeApiKey(keyId: string): Promise<boolean> {
  const { data, error } = await apiKeysApi.revoke(keyId);
  if (error) {
    throw new Error(error.message);
  }
  return data.success;
}
