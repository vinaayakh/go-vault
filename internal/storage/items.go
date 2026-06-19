package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// VaultItem is the in-memory representation of a vault_items row.
// Only ciphertext + metadata is stored — no plaintext, ever.
type VaultItem struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Ciphertext string
	ItemType   string
	Revision   int
	UpdatedAt  time.Time
}

// ItemsRepo provides injection-safe access to the vault_items table.
// All queries use pgx parameterized placeholders ($1, $2, …).
type ItemsRepo struct {
	pool *pgxpool.Pool
}

const createItemSQL = `
INSERT INTO vault_items (user_id, ciphertext, item_type)
VALUES ($1, $2, $3)
RETURNING id, user_id, ciphertext, item_type, revision, updated_at`

// Create stores a new encrypted item and returns the persisted record.
func (r *ItemsRepo) Create(ctx context.Context, userID uuid.UUID, ciphertext, itemType string) (*VaultItem, error) {
	item := &VaultItem{}
	err := r.pool.QueryRow(ctx, createItemSQL, userID, ciphertext, itemType).Scan(
		&item.ID, &item.UserID, &item.Ciphertext, &item.ItemType, &item.Revision, &item.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create item: %w", err)
	}
	return item, nil
}

const getItemSQL = `
SELECT id, user_id, ciphertext, item_type, revision, updated_at
FROM vault_items
WHERE id = $1 AND user_id = $2
LIMIT 1`

// Get fetches one item by ID, guarded by userID to prevent cross-user access.
// Returns ErrNotFound when the item does not exist or belongs to another user.
func (r *ItemsRepo) Get(ctx context.Context, id, userID uuid.UUID) (*VaultItem, error) {
	item := &VaultItem{}
	err := r.pool.QueryRow(ctx, getItemSQL, id, userID).Scan(
		&item.ID, &item.UserID, &item.Ciphertext, &item.ItemType, &item.Revision, &item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get item: %w", err)
	}
	return item, nil
}

const listItemsSQL = `
SELECT id, user_id, ciphertext, item_type, revision, updated_at
FROM vault_items
WHERE user_id = $1
ORDER BY updated_at DESC`

// List returns all items belonging to userID, ordered by most-recently-updated.
func (r *ItemsRepo) List(ctx context.Context, userID uuid.UUID) ([]*VaultItem, error) {
	rows, err := r.pool.Query(ctx, listItemsSQL, userID)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer rows.Close()

	var items []*VaultItem
	for rows.Next() {
		item := &VaultItem{}
		if err := rows.Scan(
			&item.ID, &item.UserID, &item.Ciphertext, &item.ItemType, &item.Revision, &item.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan item row: %w", err)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list items rows: %w", err)
	}
	return items, nil
}

const updateItemSQL = `
UPDATE vault_items
SET
    ciphertext = $4,
    item_type  = COALESCE($5, item_type),
    revision   = revision + 1,
    updated_at = NOW()
WHERE id = $1
  AND user_id = $2
  AND revision = $3
RETURNING id, user_id, ciphertext, item_type, revision, updated_at`

// Update replaces ciphertext (and optionally item_type) using optimistic concurrency.
// currentRevision must match the stored revision; returns ErrConflict if not.
// Returns ErrNotFound when the id/userID pair does not exist.
// newItemType may be empty string to keep the existing value (COALESCE handles this).
func (r *ItemsRepo) Update(
	ctx context.Context,
	id, userID uuid.UUID,
	currentRevision int,
	newCiphertext, newItemType string,
) (*VaultItem, error) {
	// Pass nil for newItemType when empty so COALESCE($5, item_type) keeps the existing value.
	var itemTypeArg any
	if newItemType != "" {
		itemTypeArg = newItemType
	}

	item := &VaultItem{}
	err := r.pool.QueryRow(ctx, updateItemSQL,
		id, userID, currentRevision, newCiphertext, itemTypeArg,
	).Scan(
		&item.ID, &item.UserID, &item.Ciphertext, &item.ItemType, &item.Revision, &item.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// Could be: item doesn't exist OR revision mismatch.
		// Check if the item exists (without exposing which case it is to the handler).
		exists, checkErr := r.itemExists(ctx, id, userID)
		if checkErr != nil {
			return nil, fmt.Errorf("update item existence check: %w", checkErr)
		}
		if !exists {
			return nil, ErrNotFound
		}
		return nil, ErrConflict
	}
	if err != nil {
		return nil, fmt.Errorf("update item: %w", err)
	}
	return item, nil
}

const itemExistsSQL = `SELECT 1 FROM vault_items WHERE id = $1 AND user_id = $2 LIMIT 1`

func (r *ItemsRepo) itemExists(ctx context.Context, id, userID uuid.UUID) (bool, error) {
	var one int
	err := r.pool.QueryRow(ctx, itemExistsSQL, id, userID).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

const deleteItemSQL = `
DELETE FROM vault_items
WHERE id = $1 AND user_id = $2`

// Delete removes an item. Returns ErrNotFound when no row was deleted
// (item doesn't exist or belongs to another user).
func (r *ItemsRepo) Delete(ctx context.Context, id, userID uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, deleteItemSQL, id, userID)
	if err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
