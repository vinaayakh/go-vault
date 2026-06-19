-- name: GetUserByEmail :one
SELECT id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at
FROM users
WHERE email = $1
LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at;

-- name: UpdateUserProtectedKey :one
UPDATE users
SET protected_symmetric_key = $2
WHERE id = $1
RETURNING id, email, kdf_params, auth_hash, auth_hash_salt, protected_symmetric_key, created_at;
