-- Migration: Add remote_scan_id to scan table
-- The ML sidecar assigns its own UUID when a scan starts. We need to store it
-- so the cancel endpoint can tell the sidecar exactly which scan to stop.

ALTER TABLE scan ADD COLUMN IF NOT EXISTS remote_scan_id TEXT;

-- Index for quick lookup when polling or cancelling by remote ID
CREATE INDEX IF NOT EXISTS idx_scan_remote_id ON scan(remote_scan_id) WHERE remote_scan_id IS NOT NULL;
