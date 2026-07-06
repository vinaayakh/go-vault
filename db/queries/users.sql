-- name: GetUserByID :one
SELECT id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key,
       totp_enabled, protected_totp_secret, created_at
FROM users
WHERE id = $1
LIMIT 1;

-- name: GetUserByEmail :one
SELECT id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key,
       totp_enabled, protected_totp_secret, created_at
FROM users
WHERE email = $1
LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key,
          totp_enabled, protected_totp_secret, created_at;

-- name: UpdateUserProtectedKey :one
UPDATE users
SET protected_symmetric_key = $2
WHERE id = $1
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key,
          totp_enabled, protected_totp_secret, created_at;

-- name: UpdateUserAuthCredentials :one
UPDATE users
SET auth_hash = $2,
    auth_hash_salt = $3,
    kdf_params = $4,
    protected_symmetric_key = $5
WHERE id = $1
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key,
          totp_enabled, protected_totp_secret, created_at;

-- name: DeleteUser :execrows
DELETE FROM users WHERE id = $1;

-- name: EnableUserTOTP :execrows
UPDATE users
SET totp_enabled = TRUE, protected_totp_secret = $2
WHERE id = $1;

-- name: DisableUserTOTP :execrows
UPDATE users
SET totp_enabled = FALSE, protected_totp_secret = NULL
WHERE id = $1;

-- name: GetUserTOTPStatus :one
SELECT totp_enabled, protected_totp_secret FROM users WHERE id = $1 LIMIT 1;
