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

/**
 * Validate a session by calling Better Auth's own get-session endpoint.
 * This avoids any dependency on the Rust API for auth flow and validates
 * directly against the source of truth (Better Auth / Next.js).
 *
 * Safe from infinite loops because /api routes are excluded from the
 * middleware matcher.
 */
async function validateSession(request: NextRequest): Promise<boolean> {
  try {
    // Build the internal URL to Better Auth's get-session endpoint
    const sessionUrl = new URL("/api/auth/get-session", request.url);

    const res = await fetch(sessionUrl.toString(), {
      method: "GET",
      headers: {
        // Forward all cookies from the incoming request so Better Auth
        // can read its session_token / session_data cookies
        cookie: request.headers.get("cookie") || "",
      },
      // Short timeout so middleware doesn't block too long
      signal: AbortSignal.timeout(5000),
    });

    if (!res.ok) {
      return false;
    }

    const data = await res.json();

    // Better Auth returns { session: {...}, user: {...} } when valid,
    // or null / empty when invalid
    return !!(data?.session && data?.user);
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

  // Quick check: if no session cookie at all, skip the fetch entirely
  const sessionCookie = request.cookies.get("better-auth.session_token");
  if (!sessionCookie?.value) {
    if (isProtectedRoute) {
      const loginUrl = new URL("/login", request.url);
      loginUrl.searchParams.set("callbackUrl", pathname);
      return NextResponse.redirect(loginUrl);
    }
    // On auth routes with no cookie, just let them through
    return NextResponse.next();
  }

  // Validate the session against Better Auth's own endpoint
  const isAuthenticated = await validateSession(request);

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
     * - api routes (handled separately — also prevents middleware loops)
     */
    "/((?!_next/static|_next/image|favicon.ico|public|api).*)",
  ],
};
