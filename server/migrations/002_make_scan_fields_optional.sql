-- Migration: Make scan fields optional for v1 API
-- This allows scans to work without full auth in development

-- Drop the foreign key constraints temporarily
ALTER TABLE scan DROP CONSTRAINT IF EXISTS scan_organization_id_fkey;
ALTER TABLE scan DROP CONSTRAINT IF EXISTS scan_created_by_fkey;

-- Make columns nullable
ALTER TABLE scan ALTER COLUMN organization_id DROP NOT NULL;
ALTER TABLE scan ALTER COLUMN created_by DROP NOT NULL;

-- Re-add foreign keys with ON DELETE SET NULL
ALTER TABLE scan ADD CONSTRAINT scan_organization_id_fkey
    FOREIGN KEY (organization_id) REFERENCES organization(id) ON DELETE SET NULL;
