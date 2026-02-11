-- Migration 003: Richer guard logs, higher rate limits, pagination support
--
-- Changes:
-- 1. Add detailed columns to guard_log for threat analysis
-- 2. Increase default rate_limit_rpm from 60 to 1000
-- 3. Add composite indexes for efficient pagination queries

-- ============================================
-- RICHER GUARD LOGS
-- ============================================

-- Store the actual prompt text for threats (NULL for safe prompts to save space)
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS prompt_text TEXT;

-- Store threat categories as an array (e.g. ['injection', 'jailbreak'])
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS threat_categories TEXT[] DEFAULT '{}';

-- Store what scan options were used
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS scan_options JSONB DEFAULT '{}';

-- Store user agent for forensics
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS user_agent TEXT;

-- Request type: 'scan', 'validate', 'batch'
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS request_type TEXT DEFAULT 'scan';

-- Store the sanitized prompt if sanitization was requested
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS sanitized_prompt TEXT;

-- Response ID for correlation
ALTER TABLE guard_log ADD COLUMN IF NOT EXISTS response_id UUID;

-- ============================================
-- INDEXES FOR PAGINATION & QUERYING
-- ============================================

-- Composite index for efficient paginated queries (org + created_at DESC)
CREATE INDEX IF NOT EXISTS idx_guard_log_org_created
    ON guard_log(organization_id, created_at DESC);

-- Index for filtering by safety status within an org
CREATE INDEX IF NOT EXISTS idx_guard_log_org_safe
    ON guard_log(organization_id, is_safe, created_at DESC);

-- Index for filtering by request type
CREATE INDEX IF NOT EXISTS idx_guard_log_request_type
    ON guard_log(request_type);

-- Index for threat category queries (GIN for array containment)
CREATE INDEX IF NOT EXISTS idx_guard_log_threat_categories
    ON guard_log USING GIN(threat_categories);

-- ============================================
-- HIGHER DEFAULT RATE LIMITS
-- ============================================

-- Increase default rate_limit_rpm from 60 to 1000 for production use
ALTER TABLE api_key ALTER COLUMN rate_limit_rpm SET DEFAULT 1000;

-- Update existing keys that still have the old default of 60
UPDATE api_key SET rate_limit_rpm = 1000 WHERE rate_limit_rpm = 60;

-- ============================================
-- ADD PLAN-BASED RATE LIMIT TIERS
-- ============================================

-- Add plan column to api_key for per-key plan overrides
ALTER TABLE api_key ADD COLUMN IF NOT EXISTS plan TEXT DEFAULT 'basic';

-- Add monthly_quota column so each key can have its own quota
ALTER TABLE api_key ADD COLUMN IF NOT EXISTS monthly_quota INTEGER DEFAULT 100000;
