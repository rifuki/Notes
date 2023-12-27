-- Add up migration script here
CREATE TABLE IF NOT EXISTS notes (
    id SERIAL,
    title VARCHAR(255) NOT NULL,
    body TEXT NOT NULL,
    user_id INT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);