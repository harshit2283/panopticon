CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL,
    ssn VARCHAR(11),
    phone VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (name, email, ssn, phone) VALUES
    ('John Doe', 'john@example.com', '123-45-6789', '+1-555-123-4567'),
    ('Jane Smith', 'jane.smith@company.org', '987-65-4321', '+1-555-987-6543'),
    ('Bob Wilson', 'bob@test.io', '456-78-9012', '+44 20 7946 0958');

-- Ensure integration traffic generator credentials work from remote containers
-- and use mysql_native_password to avoid auth plugin/client compatibility issues.
CREATE USER IF NOT EXISTS 'test'@'%' IDENTIFIED BY 'testpass';
ALTER USER 'test'@'%' IDENTIFIED WITH mysql_native_password BY 'testpass';
GRANT ALL PRIVILEGES ON testdb.* TO 'test'@'%';
FLUSH PRIVILEGES;
