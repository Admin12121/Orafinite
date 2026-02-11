import { defineConfig } from "drizzle-kit";

// Drizzle config for introspection only
// DO NOT run `drizzle-kit push` or `drizzle-kit migrate` from Next.js
// Rust owns all database migrations
export default defineConfig({
  schema: "./db/schema.ts",
  out: "./drizzle",
  dialect: "postgresql",
  dbCredentials: {
    url: process.env.DATABASE_URL!,
  },
  // Introspection settings
  introspect: {
    casing: "camel",
  },
  // Verbose output for debugging
  verbose: true,
  strict: true,
});
