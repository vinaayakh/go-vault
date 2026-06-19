-- Run after migrations to grant the least-privilege app role DML access.
-- Execute as the superuser (vault_root) once migrations are applied.
--
-- Usage: psql "$DATABASE_URL" -f deploy/grant-app-role.sql

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON vault_items TO vault_app;
-- sessions is Phase 3; grant SELECT, INSERT, DELETE when it becomes active.
GRANT SELECT ON sessions TO vault_app;
