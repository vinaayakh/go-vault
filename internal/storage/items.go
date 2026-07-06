package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

// VaultItem is the in-memory representation of a vault_items row.
type VaultItem struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Ciphertext string
	ItemType   string
	Revision   int
	UpdatedAt  time.Time
}

// ItemsRepo provides injection-safe access to vault_items via sqlc.
type ItemsRepo struct {
	q *sqlcgen.Queries
}

// Create stores a new encrypted item.
func (r *ItemsRepo) Create(ctx context.Context, userID uuid.UUID, ciphertext, itemType string) (*VaultItem, error) {
	item, err := r.q.CreateItem(ctx, userID, ciphertext, itemType)
	if err != nil {
		return nil, fmt.Errorf("create item: %w", err)
	}
	return itemFromRow(item), nil
}

// Get fetches one item by ID guarded by userID.
func (r *ItemsRepo) Get(ctx context.Context, id, userID uuid.UUID) (*VaultItem, error) {
	item, err := r.q.GetItem(ctx, id, userID)
	if err != nil {
		return nil, mapNotFound(fmt.Errorf("get item: %w", err))
	}
	return itemFromRow(item), nil
}

// List returns all items for a user.
func (r *ItemsRepo) List(ctx context.Context, userID uuid.UUID) ([]*VaultItem, error) {
	rows, err := r.q.ListItems(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	items := make([]*VaultItem, 0, len(rows))
	for _, row := range rows {
		items = append(items, itemFromRow(row))
	}
	return items, nil
}

// Update replaces ciphertext with optimistic concurrency.
func (r *ItemsRepo) Update(
	ctx context.Context,
	id, userID uuid.UUID,
	currentRevision int,
	newCiphertext, newItemType string,
) (*VaultItem, error) {
	var itemTypeArg any
	if newItemType != "" {
		itemTypeArg = newItemType
	}
	rev, err := revisionAsInt32(currentRevision)
	if err != nil {
		return nil, err
	}
	item, err := r.q.UpdateItem(ctx, sqlcgen.UpdateItemParams{
		ID:         id,
		UserID:     userID,
		Revision:   rev,
		Ciphertext: newCiphertext,
		ItemType:   itemTypeArg,
	})
	if errors.Is(err, pgx.ErrNoRows) {
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
	return itemFromRow(item), nil
}

func (r *ItemsRepo) itemExists(ctx context.Context, id, userID uuid.UUID) (bool, error) {
	_, err := r.q.ItemExists(ctx, id, userID)
	if mapNotFound(err) == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// Delete removes an item.
func (r *ItemsRepo) Delete(ctx context.Context, id, userID uuid.UUID) error {
	n, err := r.q.DeleteItem(ctx, id, userID)
	if err != nil {
		return fmt.Errorf("delete item: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
