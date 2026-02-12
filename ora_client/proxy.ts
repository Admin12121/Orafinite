import { NextResponse, type NextRequest } from "next/server";

// Routes that require authentication
const protectedRoutes = [
  "/dashboard",
  "/credentials",
  "/models",
  "/scanner",
  "/guard",
  "/reports",
  "/logs",
];

// Routes that should redirect to dashboard if already authenticated
const authRoutes = ["/login"];

// Rust API base URL (internal, not exposed to browser)
const API_BASE_URL = process.env.RUST_API_URL || "http://localhost:8080";

/**
 * Validate a session token against the Rust API.
 * Returns true only if the backend confirms the token is valid and not expired.
 */
async function validateSession(sessionToken: string): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/v1/auth/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ session_token: sessionToken }),
      // Short timeout so middleware doesn't block too long
      signal: AbortSignal.timeout(3000),
    });

    if (!res.ok) {
      return false;
    }

    const data: { valid: boolean } = await res.json();
    return data.valid === true;
  } catch {
    // Network error or timeout — fail closed (treat as unauthenticated)
    return false;
  }
}

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Check if route requires authentication
  const isProtectedRoute = protectedRoutes.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`),
  );

  // Check if route is an auth route (login, signup)
  const isAuthRoute = authRoutes.some(
    (route) => pathname === route || pathname.startsWith(`${route}/`),
  );

  // Skip validation for routes that are neither protected nor auth routes
  if (!isProtectedRoute && !isAuthRoute) {
    return NextResponse.next();
  }

  // Get session from Better Auth cookie
  const sessionCookie = request.cookies.get("better-auth.session_token");
  const tokenValue = sessionCookie?.value;

  // No cookie at all — definitely not authenticated
  let isAuthenticated = false;

  if (tokenValue) {
    // Validate the token against the Rust API instead of just trusting its existence
    isAuthenticated = await validateSession(tokenValue);
  }

  // Redirect unauthenticated users away from protected routes
  if (isProtectedRoute && !isAuthenticated) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("callbackUrl", pathname);
    return NextResponse.redirect(loginUrl);
  }

  // Redirect authenticated users away from auth routes
  if (isAuthRoute && isAuthenticated) {
    return NextResponse.redirect(new URL("/dashboard", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public folder
     * - api routes (handled separately)
     */
    "/((?!_next/static|_next/image|favicon.ico|public|api).*)",
  ],
};
