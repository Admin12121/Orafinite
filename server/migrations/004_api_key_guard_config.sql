-- ============================================
-- Migration 004: Per-API-Key Guard Configuration
-- ============================================
-- Adds a JSONB column `guard_config` to the `api_key` table so each
-- API key can store its own protection profile (scan mode, which
-- scanners to run, thresholds, settings, and global options).
--
-- Example guard_config value:
-- {
--   "scan_mode": "prompt_only",
--   "input_scanners": {
--     "prompt_injection": { "enabled": true, "threshold": 0.5, "settings_json": "" },
--     "toxicity":        { "enabled": true, "threshold": 0.5, "settings_json": "" }
--   },
--   "output_scanners": {
--     "bias":       { "enabled": true, "threshold": 0.5, "settings_json": "" },
--     "sensitive":  { "enabled": true, "threshold": 0.5, "settings_json": "" }
--   },
--   "sanitize": false,
--   "fail_fast": false
-- }
--
-- When guard_config IS NULL the key has no protection profile and the
-- caller must provide scanner configuration per-request (legacy behaviour).
-- When guard_config IS NOT NULL, the stored config is used automatically:
--   - scan_mode = "prompt_only" | "output_only" → no X-Scan-Type header needed
--   - scan_mode = "both" → caller sends X-Scan-Type: prompt | output | both

-- Add the column (nullable — existing keys keep working without config)
ALTER TABLE api_key
    ADD COLUMN IF NOT EXISTS guard_config JSONB DEFAULT NULL;

-- Add a GIN index so we can efficiently query keys by config properties
-- (e.g. find all keys with a specific scan_mode)
CREATE INDEX IF NOT EXISTS idx_api_key_guard_config
    ON api_key USING gin (guard_config)
    WHERE guard_config IS NOT NULL;

-- Optional: add a CHECK constraint to validate the top-level shape.
-- We only enforce that scan_mode is one of the three allowed values
-- when the column is populated.
ALTER TABLE api_key
    ADD CONSTRAINT chk_guard_config_scan_mode
    CHECK (
        guard_config IS NULL
        OR guard_config->>'scan_mode' IN ('prompt_only', 'output_only', 'both')
    );

COMMENT ON COLUMN api_key.guard_config IS
    'Per-key guard protection profile (scan_mode, input/output scanners, options). NULL means no default config — caller must specify per request.';
