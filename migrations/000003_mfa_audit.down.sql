DROP TABLE IF EXISTS user_device_hashes;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS mfa_challenges;
DROP TABLE IF EXISTS recovery_codes;
ALTER TABLE users DROP COLUMN IF EXISTS protected_totp_secret;
ALTER TABLE users DROP COLUMN IF EXISTS totp_enabled;
