-- Run after migrations to grant the least-privilege app role DML access.
-- Execute as the superuser (vault_root) once migrations are applied.
--
-- Usage: psql "$DATABASE_URL" -f deploy/grant-app-role.sql

GRANT SELECT, INSERT, UPDATE, DELETE ON users TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON vault_items TO vault_app;
GRANT SELECT, INSERT, DELETE ON sessions TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_codes TO vault_app;
GRANT SELECT, INSERT, DELETE ON mfa_challenges TO vault_app;
GRANT SELECT, INSERT ON audit_events TO vault_app;
GRANT SELECT, INSERT ON user_device_hashes TO vault_app;
