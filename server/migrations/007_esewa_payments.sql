-- ============================================================
-- Migration 007: eSewa Payment & Subscription Tables
-- ============================================================
-- Adds tables to track eSewa payment transactions and user
-- subscription state. These tables are owned by Rust (sqlx)
-- and mirrored read-only by Drizzle in Next.js via `drizzle-kit pull`.
--
-- Flow:
--   1. User selects plan on frontend
--   2. Next.js API creates a "pending" payment row + redirects to eSewa
--   3. eSewa redirects back; Next.js verifies signature + updates payment
--   4. Subscription row is created/updated to reflect active plan
-- ============================================================

-- ── Enum: payment_status ─────────────────────────────────────

DO $$ BEGIN
    CREATE TYPE payment_status AS ENUM (
        'pending',
        'completed',
        'failed',
        'refunded',
        'expired'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- ── Enum: subscription_status ────────────────────────────────

DO $$ BEGIN
    CREATE TYPE subscription_status AS ENUM (
        'active',
        'expired',
        'cancelled',
        'past_due'
    );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

-- ── Table: payment ───────────────────────────────────────────
-- Tracks every eSewa transaction (one row per payment attempt)

CREATE TABLE IF NOT EXISTS payment (
    id                TEXT PRIMARY KEY,                           -- UUID as text (matches Better Auth ID style)
    user_id           TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    transaction_uuid  TEXT UNIQUE NOT NULL,                       -- Unique ID sent to eSewa
    product_code      TEXT NOT NULL,                              -- eSewa product code ("EPAYTEST" / production code)
    plan_id           TEXT NOT NULL,                              -- Plan being purchased: "starter" | "pro" | "enterprise"
    amount            INTEGER NOT NULL,                           -- Amount in NPR (e.g. 6500 = रू6,500)
    tax_amount        INTEGER NOT NULL DEFAULT 0,                 -- Tax in NPR
    total_amount      INTEGER NOT NULL,                           -- amount + tax_amount
    status            payment_status NOT NULL DEFAULT 'pending',  -- Current payment status
    esewa_ref_id      TEXT,                                       -- eSewa reference ID (returned after success)
    esewa_response_raw TEXT,                                      -- Raw eSewa response JSON for audit trail
    period_start      TIMESTAMP,                                  -- Billing period start (set on completion)
    period_end        TIMESTAMP,                                  -- Billing period end (set on completion)
    created_at        TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payment_user_id           ON payment(user_id);
CREATE INDEX IF NOT EXISTS idx_payment_transaction_uuid  ON payment(transaction_uuid);
CREATE INDEX IF NOT EXISTS idx_payment_status            ON payment(status);
CREATE INDEX IF NOT EXISTS idx_payment_created_at        ON payment(created_at);

-- ── Table: subscription ──────────────────────────────────────
-- One row per user — tracks the active subscription state.
-- Created on first successful payment; updated on renewals.

CREATE TABLE IF NOT EXISTS subscription (
    id                    TEXT PRIMARY KEY,                                -- UUID as text
    user_id               TEXT NOT NULL UNIQUE REFERENCES "user"(id) ON DELETE CASCADE,
    plan_id               TEXT NOT NULL DEFAULT 'free_trial',              -- "free_trial" | "starter" | "pro" | "enterprise"
    status                subscription_status NOT NULL DEFAULT 'active',  -- Current subscription status
    current_payment_id    TEXT REFERENCES payment(id),                     -- Payment that activated this period
    current_period_start  TIMESTAMP NOT NULL DEFAULT NOW(),               -- When current billing period started
    current_period_end    TIMESTAMP NOT NULL,                             -- When current billing period ends
    auto_renew            BOOLEAN NOT NULL DEFAULT FALSE,                 -- For future auto-renewal support
    created_at            TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscription_user_id     ON subscription(user_id);
CREATE INDEX IF NOT EXISTS idx_subscription_status      ON subscription(status);
CREATE INDEX IF NOT EXISTS idx_subscription_period_end  ON subscription(current_period_end);
