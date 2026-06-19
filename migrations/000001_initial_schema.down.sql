-- Reverses 000001_initial_schema.up.sql.
-- ORDER matters: drop dependents (vault_items, sessions) before users.

DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS vault_items;
DROP TABLE IF EXISTS users;
