package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

// Server implements gen.ServerInterface — the set of handlers generated from
// api/openapi.yaml. In Phase 2 it holds a logger and the storage layer;
// Phase 3 will add a session/auth dependency.
type Server struct {
	log   *slog.Logger
	store *storage.Store
}

// NewServer constructs the API handler set.
func NewServer(log *slog.Logger, store *storage.Store) *Server {
	return &Server{log: log, store: store}
}

// Ensure *Server satisfies the generated contract at compile time.
var _ gen.ServerInterface = (*Server)(nil)

// GetHealth implements GET /api/health — a no-auth liveness probe.
func (s *Server) GetHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, gen.HealthResponse{Status: "ok"})
}

// GetReady implements GET /api/ready — a readiness probe that checks DB connectivity.
// Distinct from GetHealth: orchestrators gate traffic on readiness but must not
// fail liveness on a transient DB blip.
func (s *Server) GetReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		s.log.Error("readiness check failed", "error", err,
			"request_id", r.Context().Value(requestIDKey))
		writeJSON(w, http.StatusServiceUnavailable, gen.Error{Error: "database unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, gen.ReadyResponse{Ready: true})
}

// ListItems implements GET /api/items.
func (s *Server) ListItems(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusForbidden, gen.Error{Error: "authentication required"})
		return
	}

	items, err := s.store.Items.List(r.Context(), userID)
	if err != nil {
		s.logInternalError(r, "list items", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to list items"})
		return
	}

	resp := make([]gen.Item, 0, len(items))
	for _, it := range items {
		resp = append(resp, storageItemToGen(it))
	}
	writeJSON(w, http.StatusOK, resp)
}

// CreateItem implements POST /api/items.
func (s *Server) CreateItem(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusForbidden, gen.Error{Error: "authentication required"})
		return
	}

	var body gen.NewItem
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}

	if err := validateCiphertext(body.Ciphertext); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}
	if !gen.NewItemItemType(body.ItemType).Valid() {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "invalid item_type"})
		return
	}

	item, err := s.store.Items.Create(r.Context(), userID, body.Ciphertext, string(body.ItemType))
	if err != nil {
		s.logInternalError(r, "create item", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to create item"})
		return
	}
	writeJSON(w, http.StatusCreated, storageItemToGen(item))
}

// UpdateItem implements PUT /api/items/{id}.
func (s *Server) UpdateItem(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusForbidden, gen.Error{Error: "authentication required"})
		return
	}

	var body gen.UpdateItem
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}

	if err := validateCiphertext(body.Ciphertext); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}
	if body.CurrentRevision < 1 {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "current_revision must be >= 1"})
		return
	}

	var newItemType string
	if body.ItemType != nil {
		if !gen.UpdateItemItemType(*body.ItemType).Valid() {
			writeJSON(w, http.StatusBadRequest, gen.Error{Error: "invalid item_type"})
			return
		}
		newItemType = string(*body.ItemType)
	}

	item, err := s.store.Items.Update(r.Context(), id, userID, body.CurrentRevision, body.Ciphertext, newItemType)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, gen.Error{Error: "item not found"})
		return
	}
	if errors.Is(err, storage.ErrConflict) {
		writeJSON(w, http.StatusConflict, gen.Error{Error: "revision conflict: fetch the latest version before retrying"})
		return
	}
	if err != nil {
		s.logInternalError(r, "update item", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to update item"})
		return
	}
	writeJSON(w, http.StatusOK, storageItemToGen(item))
}

// DeleteItem implements DELETE /api/items/{id}.
func (s *Server) DeleteItem(w http.ResponseWriter, r *http.Request, id openapi_types.UUID) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusForbidden, gen.Error{Error: "authentication required"})
		return
	}

	err := s.store.Items.Delete(r.Context(), id, userID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusNotFound, gen.Error{Error: "item not found"})
		return
	}
	if err != nil {
		s.logInternalError(r, "delete item", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to delete item"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetSync implements GET /api/sync — returns the full vault snapshot.
// Full-snapshot model (v0): all items every time; no incremental sync.
func (s *Server) GetSync(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusForbidden, gen.Error{Error: "authentication required"})
		return
	}

	user, err := s.store.Users.GetByID(r.Context(), userID)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusForbidden, gen.Error{Error: "user not found"})
		return
	}
	if err != nil {
		s.logInternalError(r, "sync: get user", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to load user"})
		return
	}

	items, err := s.store.Items.List(r.Context(), userID)
	if err != nil {
		s.logInternalError(r, "sync: list items", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to load items"})
		return
	}

	var kdfParams gen.KDFParams
	if err := json.Unmarshal(user.KDFParams, &kdfParams); err != nil {
		s.logInternalError(r, "sync: unmarshal kdf_params", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to load user params"})
		return
	}

	genItems := make([]gen.Item, 0, len(items))
	for _, it := range items {
		genItems = append(genItems, storageItemToGen(it))
	}

	writeJSON(w, http.StatusOK, gen.SyncResponse{
		ProtectedSymmetricKey: user.ProtectedSymmetricKey,
		KdfParams:             kdfParams,
		Items:                 genItems,
	})
}

// storageItemToGen converts a storage.VaultItem to the generated gen.Item type.
func storageItemToGen(it *storage.VaultItem) gen.Item {
	return gen.Item{
		Id:         it.ID,
		ItemType:   gen.ItemItemType(it.ItemType),
		Ciphertext: it.Ciphertext,
		Revision:   it.Revision,
		UpdatedAt:  it.UpdatedAt,
	}
}

// decodeJSON parses the request body as JSON into dst. Returns a user-safe
// error message on failure — never logs the raw body (may contain ciphertext).
func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid request body")
	}
	return nil
}

// validateCiphertext checks that the ciphertext field is non-empty and valid
// standard base64. It does NOT attempt to decode the content — that's the
// client's job. The check exists only to reject obviously malformed input early.
func validateCiphertext(ct string) error {
	if ct == "" {
		return errors.New("ciphertext must not be empty")
	}
	if _, err := base64.StdEncoding.DecodeString(ct); err != nil {
		return errors.New("ciphertext must be valid base64 (standard, padded)")
	}
	return nil
}

// logInternalError logs the full error detail server-side (with request ID for
// correlation) without exposing it to the client.
func (s *Server) logInternalError(r *http.Request, op string, err error) {
	s.log.Error("internal error",
		"op", op,
		"error", err,
		"request_id", r.Context().Value(requestIDKey),
	)
}

// writeJSON encodes v as JSON with the given status. Encoding errors are logged
// (not surfaced to the client) since the header is already committed.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("failed to encode JSON response", "error", err)
	}
}
