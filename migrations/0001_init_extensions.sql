-- +goose Up
-- Extensions used across the schema.
-- `citext` gives us case-insensitive email columns without manual lower() everywhere.
-- `pgcrypto` provides gen_random_uuid() for primary keys.
CREATE EXTENSION IF NOT EXISTS citext;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- +goose Down
DROP EXTENSION IF EXISTS pgcrypto;
DROP EXTENSION IF EXISTS citext;
