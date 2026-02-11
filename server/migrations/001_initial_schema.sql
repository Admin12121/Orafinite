-- Orafinite Database Schema
-- Compatible with Better Auth (Next.js) + SQLx (Rust)

-- ============================================
-- BETTER AUTH TABLES (Required for Next.js auth)
-- ============================================

-- User table (Better Auth core)
CREATE TABLE IF NOT EXISTS "user" (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    image TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    -- 2FA fields (Better Auth plugin)
    two_factor_enabled BOOLEAN DEFAULT FALSE
);

-- Session table (Better Auth core)
CREATE TABLE IF NOT EXISTS session (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_session_token ON session(token);
CREATE INDEX idx_session_user_id ON session(user_id);
CREATE INDEX idx_session_expires ON session(expires_at);

-- Account table (Better Auth - OAuth providers)
CREATE TABLE IF NOT EXISTS account (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    account_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    access_token TEXT,
    refresh_token TEXT,
    access_token_expires_at TIMESTAMP,
    refresh_token_expires_at TIMESTAMP,
    scope TEXT,
    id_token TEXT,
    password TEXT,  -- For credential-based auth
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),

    UNIQUE(provider_id, account_id)
);

CREATE INDEX idx_account_user_id ON account(user_id);

-- Verification table (Better Auth - email verification, password reset)
CREATE TABLE IF NOT EXISTS verification (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_verification_identifier ON verification(identifier);

-- Two Factor table (Better Auth 2FA plugin)
CREATE TABLE IF NOT EXISTS two_factor (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    secret TEXT,
    backup_codes TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_two_factor_user_id ON two_factor(user_id);

-- Passkey table (Better Auth passkey plugin)
CREATE TABLE IF NOT EXISTS passkey (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    name TEXT,
    public_key TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT,
    backed_up BOOLEAN DEFAULT FALSE,
    transports TEXT,
    aaguid TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_passkey_user_id ON passkey(user_id);
CREATE INDEX idx_passkey_credential_id ON passkey(credential_id);

-- ============================================
-- ORAFINITE CUSTOM TABLES
-- ============================================

-- Organizations
CREATE TABLE IF NOT EXISTS organization (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    owner_id TEXT NOT NULL REFERENCES "user"(id),
    plan TEXT DEFAULT 'free',
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_organization_owner ON organization(owner_id);
CREATE INDEX idx_organization_slug ON organization(slug);

-- Organization Members
CREATE TABLE IF NOT EXISTS organization_member (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member',  -- owner, admin, member
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),

    UNIQUE(organization_id, user_id)
);

CREATE INDEX idx_org_member_org ON organization_member(organization_id);
CREATE INDEX idx_org_member_user ON organization_member(user_id);

-- API Keys
CREATE TABLE IF NOT EXISTS api_key (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,  -- First 8 chars for display (ora_xxxx)
    key_hash TEXT UNIQUE NOT NULL,  -- SHA256 hash of full key
    scopes TEXT[] DEFAULT '{}',
    rate_limit_rpm INTEGER DEFAULT 60,
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP,
    created_by TEXT NOT NULL REFERENCES "user"(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_key_org ON api_key(organization_id);
CREATE INDEX idx_api_key_hash ON api_key(key_hash);

-- LLM Model Configurations
CREATE TABLE IF NOT EXISTS model_config (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,  -- openai, anthropic, huggingface, ollama, custom
    model TEXT NOT NULL,
    api_key_encrypted TEXT,  -- Encrypted API key for the LLM
    base_url TEXT,
    settings JSONB DEFAULT '{}',
    is_default BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_model_config_org ON model_config(organization_id);

-- Vulnerability Scans
CREATE TABLE IF NOT EXISTS scan (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    model_config_id UUID REFERENCES model_config(id),
    scan_type TEXT NOT NULL,  -- quick, standard, comprehensive, custom
    status TEXT NOT NULL DEFAULT 'queued',  -- queued, running, completed, failed, cancelled
    progress INTEGER DEFAULT 0,
    probes_total INTEGER DEFAULT 0,
    probes_completed INTEGER DEFAULT 0,
    vulnerabilities_found INTEGER DEFAULT 0,
    risk_score REAL,
    error_message TEXT,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    created_by TEXT NOT NULL REFERENCES "user"(id),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_org ON scan(organization_id);
CREATE INDEX idx_scan_status ON scan(status);

-- Scan Results (Vulnerabilities found)
CREATE TABLE IF NOT EXISTS scan_result (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    probe_name TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,  -- critical, high, medium, low
    description TEXT NOT NULL,
    attack_prompt TEXT,
    model_response TEXT,
    recommendation TEXT,
    raw_data JSONB,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_result_scan ON scan_result(scan_id);
CREATE INDEX idx_scan_result_severity ON scan_result(severity);

-- Guard Scan Logs (Real-time protection logs)
CREATE TABLE IF NOT EXISTS guard_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    api_key_id UUID REFERENCES api_key(id),
    prompt_hash TEXT NOT NULL,  -- Hash of prompt for dedup
    is_safe BOOLEAN NOT NULL,
    risk_score REAL,
    threats_detected JSONB DEFAULT '[]',
    latency_ms INTEGER,
    cached BOOLEAN DEFAULT FALSE,
    ip_address TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_guard_log_org ON guard_log(organization_id);
CREATE INDEX idx_guard_log_created ON guard_log(created_at);
CREATE INDEX idx_guard_log_safe ON guard_log(is_safe);

-- Usage tracking for billing
CREATE TABLE IF NOT EXISTS usage_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    guard_scans INTEGER DEFAULT 0,
    vulnerability_scans INTEGER DEFAULT 0,
    api_requests INTEGER DEFAULT 0,

    UNIQUE(organization_id, date)
);

CREATE INDEX idx_usage_log_org_date ON usage_log(organization_id, date);
