import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { headers } from "next/headers";

/**
 * POST /api/guard/events/ticket
 *
 * Next.js API proxy that creates an SSE ticket by:
 * 1. Authenticating the user via Better Auth (server-side, using cookies)
 * 2. Calling the Rust API's ticket endpoint with the real DB session token
 *    as a Bearer token (which the Rust API trusts)
 * 3. Returning ONLY the one-time ticket to the browser
 *
 * Security notes:
 * - The session token stays server-side (Next.js → Rust API over internal
 *   Docker network). It NEVER reaches the browser.
 * - The browser only receives a one-time ticket (random UUID, 30s TTL,
 *   single-use, deleted from Redis on first redemption via GETDEL).
 * - Upstream error bodies are NOT forwarded — only sanitized messages are
 *   returned, preventing any accidental token or internal detail leakage.
 */

const RUST_API_URL = process.env.RUST_API_URL || "http://localhost:8080";

/** Sanitized error messages returned to the browser — never expose internals */
const SAFE_ERRORS: Record<number, { error: string; code: string }> = {
  401: { error: "Not authenticated", code: "SESSION_REQUIRED" },
  403: { error: "Access denied", code: "FORBIDDEN" },
  404: { error: "Ticket service unavailable", code: "NOT_FOUND" },
  429: { error: "Too many requests", code: "RATE_LIMITED" },
  500: { error: "Ticket creation failed", code: "TICKET_ERROR" },
};

function safeError(status: number) {
  return (
    SAFE_ERRORS[status] ?? {
      error: "Ticket creation failed",
      code: "TICKET_ERROR",
    }
  );
}

export async function POST() {
  try {
    // 1. Authenticate via Better Auth (reads cookies server-side)
    const session = await auth.api.getSession({
      headers: await headers(),
    });

    if (!session?.session?.token) {
      return NextResponse.json(
        { error: "Not authenticated", code: "SESSION_REQUIRED" },
        { status: 401 },
      );
    }

    const sessionToken = session.session.token;

    // 2. Call Rust API to create SSE ticket using the real DB session token.
    //    This is a server-to-server call over the internal Docker network —
    //    the session token never leaves the backend.
    const res = await fetch(`${RUST_API_URL}/v1/guard/events/ticket`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${sessionToken}`,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      // Log the real error server-side for debugging, but never send it
      // to the browser (could contain internal details or token echoes).
      const upstream = await res.text().catch(() => "<unreadable>");
      console.error(
        "[api/guard/events/ticket] Upstream %d: %s",
        res.status,
        upstream,
      );
      const mapped = safeError(res.status);
      return NextResponse.json(mapped, { status: res.status });
    }

    // 3. Return ONLY the ticket and expiry — nothing else from upstream
    const data = await res.json();
    return NextResponse.json({
      ticket: data.ticket,
      expires_in: data.expires_in,
    });
  } catch (err) {
    console.error("[api/guard/events/ticket] Error:", err);
    return NextResponse.json(
      { error: "Internal server error", code: "INTERNAL_ERROR" },
      { status: 500 },
    );
  }
}
