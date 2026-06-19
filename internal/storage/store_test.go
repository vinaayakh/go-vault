//go:build integration

// Integration tests for the storage layer. They require a live PostgreSQL
// database. Set TEST_DATABASE_URL to a connection string before running:
//
//	TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/storage/...
//
// In CI the database is spun up as a service container; see .github/workflows/ci.yml.
package storage_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/storage"
)

func testStore(t *testing.T) *storage.Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}
	store, err := storage.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func testUser(t *testing.T, store *storage.Store) *storage.User {
	t.Helper()
	kdf := json.RawMessage(`{"type":"argon2id","version":19,"memory_kib":65536,"iterations":3,"parallelism":1}`)
	email := "test+" + uuid.New().String() + "@example.com"
	user, err := store.Users.Create(context.Background(),
		email, kdf,
		[]byte("fakehash"), []byte("fakesalt"),
		"base64protectedkey==",
	)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	return user
}

// TestItemCRUD covers the happy path: create → list → update → delete.
func TestItemCRUD(t *testing.T) {
	store := testStore(t)
	user := testUser(t, store)
	ctx := context.Background()

	// Create
	item, err := store.Items.Create(ctx, user.ID, "dGVzdA==", "login")
	if err != nil {
		t.Fatalf("create item: %v", err)
	}
	if item.Revision != 1 {
		t.Errorf("initial revision = %d, want 1", item.Revision)
	}

	// List
	items, err := store.Items.List(ctx, user.ID)
	if err != nil {
		t.Fatalf("list items: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("list returned %d items, want 1", len(items))
	}

	// Get
	got, err := store.Items.Get(ctx, item.ID, user.ID)
	if err != nil {
		t.Fatalf("get item: %v", err)
	}
	if got.Ciphertext != "dGVzdA==" {
		t.Errorf("ciphertext = %q, want %q", got.Ciphertext, "dGVzdA==")
	}

	// Update with correct revision
	updated, err := store.Items.Update(ctx, item.ID, user.ID, 1, "dXBkYXRlZA==", "note")
	if err != nil {
		t.Fatalf("update item: %v", err)
	}
	if updated.Revision != 2 {
		t.Errorf("updated revision = %d, want 2", updated.Revision)
	}
	if updated.ItemType != "note" {
		t.Errorf("updated item_type = %q, want %q", updated.ItemType, "note")
	}

	// Delete
	if err := store.Items.Delete(ctx, item.ID, user.ID); err != nil {
		t.Fatalf("delete item: %v", err)
	}

	// Confirm deletion: list should be empty
	items, err = store.Items.List(ctx, user.ID)
	if err != nil {
		t.Fatalf("list after delete: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("expected 0 items after delete, got %d", len(items))
	}
}

// TestOptimisticConcurrency verifies that a stale revision returns ErrConflict,
// and that the item is unchanged.
func TestOptimisticConcurrency(t *testing.T) {
	store := testStore(t)
	user := testUser(t, store)
	ctx := context.Background()

	item, err := store.Items.Create(ctx, user.ID, "dGVzdA==", "login")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// Advance revision to 2.
	if _, err := store.Items.Update(ctx, item.ID, user.ID, 1, "bmV3", ""); err != nil {
		t.Fatalf("first update: %v", err)
	}

	// Retry with stale revision 1 — must conflict.
	_, err = store.Items.Update(ctx, item.ID, user.ID, 1, "c3RhbGU=", "")
	if !errors.Is(err, storage.ErrConflict) {
		t.Errorf("stale revision: got %v, want ErrConflict", err)
	}
}

// TestNotFoundErrors verifies ErrNotFound for non-existent items.
func TestNotFoundErrors(t *testing.T) {
	store := testStore(t)
	user := testUser(t, store)
	ctx := context.Background()
	ghost := uuid.New()

	if _, err := store.Items.Get(ctx, ghost, user.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Get missing item: got %v, want ErrNotFound", err)
	}
	if err := store.Items.Delete(ctx, ghost, user.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("Delete missing item: got %v, want ErrNotFound", err)
	}
}

// TestSQLInjectionSafety stores a SQL-injection payload as ciphertext and
// confirms it round-trips as literal text (parameterized queries prevent execution).
func TestSQLInjectionSafety(t *testing.T) {
	store := testStore(t)
	user := testUser(t, store)
	ctx := context.Background()

	// Encode the payload so it passes the base64 check in the handler.
	// We're testing storage directly here, so we use a valid base64 string
	// whose decoded bytes happen to contain SQL characters.
	payload := "JzsgRFJPUCBUQUJMRSB2YXVsdF9pdGVtczsgLS0="

	item, err := store.Items.Create(ctx, user.ID, payload, "note")
	if err != nil {
		t.Fatalf("create with injection payload: %v", err)
	}

	got, err := store.Items.Get(ctx, item.ID, user.ID)
	if err != nil {
		t.Fatalf("get back: %v", err)
	}
	if got.Ciphertext != payload {
		t.Errorf("ciphertext mismatch: got %q, want %q", got.Ciphertext, payload)
	}

	// The vault_items table must still exist after the round-trip.
	items, err := store.Items.List(ctx, user.ID)
	if err != nil {
		t.Fatalf("list after injection test: %v", err)
	}
	if len(items) == 0 {
		t.Error("vault_items table appears empty — possible SQL injection or truncation")
	}
}

// TestCrossUserIsolation confirms that a user cannot access another user's items.
func TestCrossUserIsolation(t *testing.T) {
	store := testStore(t)
	alice := testUser(t, store)
	bob := testUser(t, store)
	ctx := context.Background()

	item, err := store.Items.Create(ctx, alice.ID, "dGVzdA==", "login")
	if err != nil {
		t.Fatalf("alice create: %v", err)
	}

	// Bob should not be able to get or delete Alice's item.
	if _, err := store.Items.Get(ctx, item.ID, bob.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("bob Get alice's item: got %v, want ErrNotFound", err)
	}
	if err := store.Items.Delete(ctx, item.ID, bob.ID); !errors.Is(err, storage.ErrNotFound) {
		t.Errorf("bob Delete alice's item: got %v, want ErrNotFound", err)
	}
}
