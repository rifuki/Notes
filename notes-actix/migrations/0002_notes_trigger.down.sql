-- Add down migration script here
DROP TRIGGER IF EXISTS update_notes_update_at ON notes;
DROP FUNCTION IF EXISTS update_updated_at_column();