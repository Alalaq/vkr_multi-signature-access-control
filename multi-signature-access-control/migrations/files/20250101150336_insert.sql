-- +goose Up
-- +goose StatementBegin
INSERT INTO roles (id, name)
VALUES
    ('8ec8bb2c-d50a-4d9b-9534-dc3be0e11b4f', 'MANAGER'),
    ('a123bfe6-d39f-42b2-b1e2-c7f7f4fc184d', 'EMPLOYEE'),
    ('f0bce51b-8c3d-4f76-bf1d-38308c4699a7', 'ADMIN');


--
-- Insert permissions for the 'ADMIN' role
INSERT INTO permissions (id, role_id, resource, access_level, required_signatures)
VALUES
    (UUID(), 'f0bce51b-8c3d-4f76-bf1d-38308c4699a7', 'users', 'high_access', 0),  -- ADMIN: High access to 'users'
    (UUID(), 'f0bce51b-8c3d-4f76-bf1d-38308c4699a7', 'get_all', 'high_access', 0);  -- ADMIN: High access to 'get_all'

-- Insert permissions for the 'MANAGER' role
INSERT INTO permissions (id, role_id, resource, access_level, required_signatures)
VALUES
    (UUID(), '8ec8bb2c-d50a-4d9b-9534-dc3be0e11b4f', 'users', 'low_access', 2),  -- MANAGER: Low access to 'users'
    (UUID(), '8ec8bb2c-d50a-4d9b-9534-dc3be0e11b4f', 'get_all', 'high_access', 0);  -- MANAGER: High access to 'get_all'

-- Insert permissions for the 'EMPLOYEE' role
INSERT INTO permissions (id, role_id, resource, access_level, required_signatures)
VALUES
    (UUID(), 'a123bfe6-d39f-42b2-b1e2-c7f7f4fc184d', 'users', 'no_access', 0),  -- EMPLOYEE: No access to 'users'
    (UUID(), 'a123bfe6-d39f-42b2-b1e2-c7f7f4fc184d', 'get_all', 'low_access', 3);  -- EMPLOYEE: Low access to 'get_all'


-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- +goose StatementEnd
