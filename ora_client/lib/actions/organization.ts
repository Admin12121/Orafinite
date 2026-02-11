"use server";

import { organizationApi, type OrganizationResponse } from "@/lib/api";

export type Organization = OrganizationResponse;

/**
 * Get or create organization for current user
 * Calls Rust API: POST /v1/organization
 */
export async function getOrCreateOrganization(): Promise<Organization | null> {
  const { data, error } = await organizationApi.getOrCreate();
  if (error) {
    console.error("Failed to get/create organization:", error.message);
    return null;
  }
  return data;
}

/**
 * Get current user's organization
 * Calls Rust API: GET /v1/organization
 */
export async function getCurrentOrganization(): Promise<Organization | null> {
  const { data, error } = await organizationApi.getCurrent();
  if (error) {
    if (error.status === 404) return null;
    throw new Error(error.message);
  }
  return data;
}
