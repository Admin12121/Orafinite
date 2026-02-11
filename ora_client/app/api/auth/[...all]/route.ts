import { auth } from "@/lib/auth";
import { toNextJsHandler } from "better-auth/next-js";

// Better Auth catch-all API route handler
// Handles all auth endpoints: /api/auth/*
export const { GET, POST } = toNextJsHandler(auth);
