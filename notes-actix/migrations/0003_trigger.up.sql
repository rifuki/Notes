-- Add up migration script here
CREATE OR REPLACE FUNCTION update_updated_at_columns()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_TABLE_NAME = 'notes' THEN 
        NEW.updated_at := CURRENT_TIMESTAMP;
        RETURN NEW;
    ELSIF TG_TABLE_NAME = 'users' THEN
        NEW.updated_at := CURRENT_TIMESTAMP;
        RETURN NEW;
    END IF;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER update_notes_updated_at
BEFORE UPDATE ON notes
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_columns();

CREATE OR REPLACE TRIGGER update_users_updated_at
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_columns();