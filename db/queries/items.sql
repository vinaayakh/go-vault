-- name: CreateItem :one
INSERT INTO vault_items (user_id, ciphertext, item_type)
VALUES ($1, $2, $3)
RETURNING id, user_id, ciphertext, item_type, revision, updated_at;

-- name: GetItem :one
-- user_id guard ensures users cannot access each other's items.
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
-- Optimistic concurrency: only updates if the stored revision matches current_revision.
-- Returns the updated row, or no rows if id/user_id not found or revision mismatch.
UPDATE vault_items
SET
    ciphertext = $4,
    item_type  = COALESCE($5, item_type),
    revision   = revision + 1,
    updated_at = NOW()
WHERE id = $1
  AND user_id = $2
  AND revision = $3
RETURNING id, user_id, ciphertext, item_type, revision, updated_at;

-- name: DeleteItem :execrows
DELETE FROM vault_items
WHERE id = $1 AND user_id = $2;
