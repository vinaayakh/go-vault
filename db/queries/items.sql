-- name: CreateItem :one
INSERT INTO vault_items (user_id, ciphertext, item_type)
VALUES ($1, $2, $3)
RETURNING id, user_id, ciphertext, item_type, revision, updated_at;

-- name: GetItem :one
SELECT id, user_id, ciphertext, item_type, revision, updated_at
FROM vault_items
WHERE id = $1 AND user_id = $2
LIMIT 1;

-- name: ListItems :many
SELECT id, user_id, ciphertext, item_type, revision, updated_at
FROM vault_items
WHERE user_id = $1
ORDER BY updated_at DESC;

-- name: UpdateItem :one
UPDATE vault_items
SET
    ciphertext = $4,
    item_type  = COALESCE(sqlc.narg('item_type'), item_type),
    revision   = revision + 1,
    updated_at = NOW()
WHERE id = $1
  AND user_id = $2
  AND revision = $3
RETURNING id, user_id, ciphertext, item_type, revision, updated_at;

-- name: ItemExists :one
SELECT 1::int AS one FROM vault_items WHERE id = $1 AND user_id = $2 LIMIT 1;

-- name: DeleteItem :execrows
DELETE FROM vault_items
WHERE id = $1 AND user_id = $2;
