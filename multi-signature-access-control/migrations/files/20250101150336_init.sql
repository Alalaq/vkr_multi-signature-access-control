-- +goose Up
-- +goose StatementBegin
CREATE TABLE roles (
                       id VARCHAR(255) PRIMARY KEY,
                       name VARCHAR(255) UNIQUE NOT NULL,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE users (
                       id VARCHAR(255) PRIMARY KEY,
                       role_id  VARCHAR(255),
                       username VARCHAR(255) UNIQUE NOT NULL,
                       email VARCHAR(255) UNIQUE NOT NULL,
                       hash_password VARCHAR(255) NOT NULL,
                       hash_public_key VARCHAR(255) UNIQUE NOT NULL,
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
                       FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);

CREATE TABLE permission_requests (
                             id VARCHAR(255) PRIMARY KEY,
                             requester_id VARCHAR(255) NOT NULL,
                             requestee_id VARCHAR(255) NOT NULL,
                             resource VARCHAR(255) NOT NULL,
                             created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                             is_signed BOOLEAN DEFAULT FALSE,
                             is_answered BOOLEAN DEFAULT FALSE,
                             FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
                             FOREIGN KEY (requestee_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE permissions (
                          id VARCHAR(255) PRIMARY KEY,
                          role_id VARCHAR(255) NOT NULL,
                          resource VARCHAR(255) NOT NULL,
                          access_level VARCHAR(255) NOT NULL,
                          required_signatures INTEGER NOT NULL,
                          FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS signatures_logs;
DROP TABLE IF EXISTS permission_requests;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
-- +goose StatementEnd
