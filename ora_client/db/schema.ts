// Drizzle schema mirroring Rust migrations (001–007)
// This is READ-ONLY — Rust owns all database migrations.
// DO NOT run drizzle-kit push or migrate from Next.js.
// To regenerate after a new Rust migration, run: `npx drizzle-kit pull`
//
// Tables covered:
//   001_initial_schema.sql      — user, session, account, verification, two_factor, passkey, organization, …
//   007_esewa_payments.sql      — payment, subscription (+ payment_status / subscription_status enums)

import {
  pgTable,
  text,
  boolean,
  timestamp,
  integer,
  index,
  unique,
  pgEnum,
} from "drizzle-orm/pg-core";

// ============================================================
// Better Auth Tables (core + plugins)
// ============================================================

// User table (Better Auth core)
export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name"),
  email: text("email").unique().notNull(),
  emailVerified: boolean("email_verified").default(false),
  image: text("image"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),

  // 2FA fields (Better Auth plugin)
  twoFactorEnabled: boolean("two_factor_enabled").default(false),
});

// Session table (Better Auth core)
export const session = pgTable(
  "session",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    token: text("token").unique().notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_session_token").on(table.token),
    index("idx_session_user_id").on(table.userId),
    index("idx_session_expires").on(table.expiresAt),
  ],
);

// Account table (Better Auth - OAuth providers)
export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at"),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at"),
    scope: text("scope"),
    idToken: text("id_token"),
    password: text("password"), // For credential-based auth
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_account_user_id").on(table.userId),
    unique("account_provider_unique").on(table.providerId, table.accountId),
  ],
);

// Verification table (Better Auth - email verification, password reset)
export const verification = pgTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: timestamp("expires_at").notNull(),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [index("idx_verification_identifier").on(table.identifier)],
);

// Two Factor table (Better Auth 2FA plugin)
export const twoFactor = pgTable(
  "two_factor",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    secret: text("secret"),
    backupCodes: text("backup_codes"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [index("idx_two_factor_user_id").on(table.userId)],
);

// Passkey table (Better Auth passkey plugin)
export const passkey = pgTable(
  "passkey",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    name: text("name"),
    publicKey: text("public_key").notNull(),
    credentialId: text("credential_id").notNull(),
    counter: integer("counter").notNull().default(0),
    deviceType: text("device_type"),
    backedUp: boolean("backed_up").default(false),
    transports: text("transports"),
    aaguid: text("aaguid"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_passkey_user_id").on(table.userId),
    index("idx_passkey_credential_id").on(table.credentialId),
  ],
);

// ============================================================
// eSewa Payment & Subscription Tables
// Mirrors: server/migrations/007_esewa_payments.sql
// READ-ONLY — do not modify here; update the Rust migration
// and then run `npx drizzle-kit pull` to regenerate.
// ============================================================

// Payment status enum
export const paymentStatusEnum = pgEnum("payment_status", [
  "pending",
  "completed",
  "failed",
  "refunded",
  "expired",
]);

// Subscription status enum
export const subscriptionStatusEnum = pgEnum("subscription_status", [
  "active",
  "expired",
  "cancelled",
  "past_due",
]);

// Payment table — tracks every eSewa transaction
export const payment = pgTable(
  "payment",
  {
    id: text("id").primaryKey(), // UUID
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    /** eSewa transaction UUID sent during initiation */
    transactionUuid: text("transaction_uuid").unique().notNull(),
    /** eSewa product code (e.g. "EPAYTEST" for sandbox, real code in prod) */
    productCode: text("product_code").notNull(),
    /** Plan being purchased: "starter" | "pro" | "enterprise" */
    planId: text("plan_id").notNull(),
    /** Amount in NPR (paisa-free integer, e.g. 6500 = रू6,500) */
    amount: integer("amount").notNull(),
    /** Tax amount in NPR */
    taxAmount: integer("tax_amount").notNull().default(0),
    /** Total amount (amount + tax) */
    totalAmount: integer("total_amount").notNull(),
    /** Payment status */
    status: paymentStatusEnum("status").notNull().default("pending"),
    /** eSewa reference ID returned after successful payment */
    esewaRefId: text("esewa_ref_id"),
    /** Raw eSewa response (base64 decoded JSON) for audit */
    esewaResponseRaw: text("esewa_response_raw"),
    /** Billing period start */
    periodStart: timestamp("period_start"),
    /** Billing period end (typically +30 days) */
    periodEnd: timestamp("period_end"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_payment_user_id").on(table.userId),
    index("idx_payment_transaction_uuid").on(table.transactionUuid),
    index("idx_payment_status").on(table.status),
  ],
);

// Subscription table — tracks active subscription state per user
export const subscription = pgTable(
  "subscription",
  {
    id: text("id").primaryKey(), // UUID
    userId: text("user_id")
      .notNull()
      .unique()
      .references(() => user.id, { onDelete: "cascade" }),
    /** Current plan: "free_trial" | "starter" | "pro" | "enterprise" */
    planId: text("plan_id").notNull().default("free_trial"),
    /** Subscription status */
    status: subscriptionStatusEnum("status").notNull().default("active"),
    /** The payment ID that activated this subscription */
    currentPaymentId: text("current_payment_id").references(() => payment.id),
    /** When the current period started */
    currentPeriodStart: timestamp("current_period_start")
      .notNull()
      .defaultNow(),
    /** When the current period ends */
    currentPeriodEnd: timestamp("current_period_end").notNull(),
    /** Whether auto-renew is on (for future use) */
    autoRenew: boolean("auto_renew").notNull().default(false),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    index("idx_subscription_user_id").on(table.userId),
    index("idx_subscription_status").on(table.status),
    index("idx_subscription_period_end").on(table.currentPeriodEnd),
  ],
);

// ============================================================
// Schema exports for Better Auth adapter
// ============================================================

export const schema = {
  user,
  session,
  account,
  verification,
  twoFactor,
  passkey,
  payment,
  subscription,
};

// Type exports
export type User = typeof user.$inferSelect;
export type Session = typeof session.$inferSelect;
export type Account = typeof account.$inferSelect;
export type Verification = typeof verification.$inferSelect;
export type TwoFactor = typeof twoFactor.$inferSelect;
export type Passkey = typeof passkey.$inferSelect;
export type Payment = typeof payment.$inferSelect;
export type Subscription = typeof subscription.$inferSelect;
