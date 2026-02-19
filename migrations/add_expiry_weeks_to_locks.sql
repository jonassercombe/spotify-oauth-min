-- Migration: Add expiry_weeks column to playlist_item_locks table
-- This allows per-song expiry settings that can override the master playlist expiry

-- Add expiry_weeks column (nullable, numeric)
ALTER TABLE playlist_item_locks 
ADD COLUMN IF NOT EXISTS expiry_weeks NUMERIC;

-- Add comment for documentation
COMMENT ON COLUMN playlist_item_locks.expiry_weeks IS 
  'Number of weeks until this track expires. If set, overrides the master playlist auto_remove_weeks. NULL means use master expiry.';

-- Optional: Add index if you plan to query by expiry_weeks frequently
-- CREATE INDEX IF NOT EXISTS idx_playlist_item_locks_expiry_weeks 
-- ON playlist_item_locks(expiry_weeks) 
-- WHERE expiry_weeks IS NOT NULL;
