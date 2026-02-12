-- Enhanced Scan Tracking Migration
-- Adds verbose per-probe execution logs, retest support, and richer scan_result fields

-- ============================================
-- Scan Execution Logs (verbose per-probe logs)
-- ============================================
-- Stores detailed execution information for each probe run during a scan.
-- This powers the verbose log viewer in the dashboard.

CREATE TABLE IF NOT EXISTS scan_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    probe_name TEXT NOT NULL,
    probe_class TEXT,                    -- full garak class path e.g. garak.probes.dan.Dan_11_0
    status TEXT NOT NULL DEFAULT 'running', -- running, passed, failed, error, skipped
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP,
    duration_ms INTEGER,                 -- execution time in milliseconds
    prompts_sent INTEGER DEFAULT 0,      -- number of attack prompts sent to the LLM
    prompts_passed INTEGER DEFAULT 0,    -- prompts the model handled safely
    prompts_failed INTEGER DEFAULT 0,    -- prompts that revealed a vulnerability
    detector_name TEXT,                  -- detector used for evaluation
    detector_scores JSONB DEFAULT '[]',  -- array of raw detector scores
    error_message TEXT,                  -- error details if status = 'error'
    log_entries JSONB DEFAULT '[]',      -- array of verbose log messages [{ts, level, msg}]
    raw_config JSONB,                    -- probe config / parameters used
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scan_log_scan ON scan_log(scan_id);
CREATE INDEX idx_scan_log_status ON scan_log(status);
CREATE INDEX idx_scan_log_probe ON scan_log(probe_name);

-- ============================================
-- Scan Retest Results
-- ============================================
-- Stores results from re-running a specific vulnerability to confirm it.
-- Each retest runs the same probe+prompt against the model and records the outcome.

CREATE TABLE IF NOT EXISTS scan_retest (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    original_result_id UUID NOT NULL REFERENCES scan_result(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    probe_name TEXT NOT NULL,
    attempt_number INTEGER NOT NULL DEFAULT 1,  -- 1st retest, 2nd retest, etc.
    status TEXT NOT NULL DEFAULT 'pending',      -- pending, running, vulnerable, safe, error
    attack_prompt TEXT,                          -- the exact prompt used
    model_response TEXT,                         -- the model's response
    detector_score REAL,                         -- detector confidence score
    is_vulnerable BOOLEAN,                       -- true if vuln confirmed on this attempt
    duration_ms INTEGER,                         -- execution time
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMP
);

CREATE INDEX idx_scan_retest_original ON scan_retest(original_result_id);
CREATE INDEX idx_scan_retest_scan ON scan_retest(scan_id);

-- ============================================
-- Enhance scan_result with additional fields
-- ============================================

-- Success rate / confidence from the detector (0.0 - 1.0)
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS success_rate REAL;

-- Which garak detector flagged the vulnerability
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS detector_name TEXT;

-- Number of attempts/prompts that triggered this vulnerability
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS attempts_count INTEGER DEFAULT 1;

-- How many times this vuln has been retested
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS retest_count INTEGER DEFAULT 0;

-- How many retests confirmed the vulnerability
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS retest_confirmed INTEGER DEFAULT 0;

-- Whether this vulnerability is confirmed (NULL = not retested, true/false = retested)
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS confirmed BOOLEAN;

-- Full garak probe class path
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS probe_class TEXT;

-- Duration of the probe execution that found this vuln (ms)
ALTER TABLE scan_result ADD COLUMN IF NOT EXISTS probe_duration_ms INTEGER;

-- ============================================
-- Enhance scan with provider/model tracking
-- ============================================
-- Store what was scanned so we can retest without needing the original config

ALTER TABLE scan ADD COLUMN IF NOT EXISTS provider TEXT;
ALTER TABLE scan ADD COLUMN IF NOT EXISTS model TEXT;
ALTER TABLE scan ADD COLUMN IF NOT EXISTS base_url TEXT;
-- NOTE: api_key is NOT stored here for security. Retests require the user to provide it again
-- or use a model_config reference.

-- ============================================
-- Indexes for common query patterns
-- ============================================

-- For fetching confirmed vs unconfirmed vulnerabilities
CREATE INDEX IF NOT EXISTS idx_scan_result_confirmed ON scan_result(confirmed) WHERE confirmed IS NOT NULL;

-- For fetching vulnerabilities by success rate (highest risk first)
CREATE INDEX IF NOT EXISTS idx_scan_result_success_rate ON scan_result(success_rate DESC NULLS LAST);
