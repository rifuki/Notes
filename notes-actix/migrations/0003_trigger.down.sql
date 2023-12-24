-- Add down migration script here
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_notes_updated_at ON notes;
DROP FUNCTION IF EXISTS update_updated_at_columns();