CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    ssn VARCHAR(11),
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (name, email, ssn, phone) VALUES
    ('Alice Johnson', 'alice@example.com', '111-22-3333', '+1-555-111-2222'),
    ('Charlie Brown', 'charlie@peanuts.com', '444-55-6666', '+1-555-444-5555'),
    ('Diana Prince', 'diana@amazons.org', '777-88-9999', '+44 20 1234 5678');
