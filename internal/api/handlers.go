package api

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
	"github.com/vinaayakh/secure-vault/internal/audit"
	"github.com/vinaayakh/secure-vault/internal/auth"
	"github.com/vinaayakh/secure-vault/internal/crypto"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

const mfaChallengeTTL = 5 * time.Minute

// Server implements gen.ServerInterface — the set of handlers generated from
// api/openapi.yaml.
type Server struct {
	log      *slog.Logger
	store    *storage.Store
	auth     *auth.Manager
	notifier audit.Notifier
	alerts   *audit.Tracker
}

// NewServer constructs the API handler set.
func NewServer(log *slog.Logger, store *storage.Store, authMgr *auth.Manager) *Server {
	notifier := &audit.SlogNotifier{Log: log}
	return &Server{
		log:      log,
		store:    store,
		auth:     authMgr,
		notifier: notifier,
		alerts:   audit.NewTracker(notifier),
	}
}

// Ensure *Server satisfies the generated contract at compile time.
var _ gen.ServerInterface = (*Server)(nil)

// PostRegister implements POST /api/register.
// Returns 201 regardless of email uniqueness to prevent account enumeration.
func (s *Server) PostRegister(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.auth.CheckRegisterLimit(ip) {
		writeJSON(w, http.StatusTooManyRequests, gen.Error{Error: "too many registration attempts; try again later"})
		return
	}

	var body gen.RegisterRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}

	email := crypto.NormalizeEmail(string(body.Email))
	if email == "" {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "email must not be empty"})
		return
	}

	authHashBytes, err := base64.StdEncoding.DecodeString(body.AuthHash)
	if err != nil || len(authHashBytes) == 0 {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "auth_hash must be valid base64"})
		return
	}

	if err := validateCiphertext(body.ProtectedSymmetricKey); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "protected_symmetric_key: " + err.Error()})
		return
	}

	kdfJSON, err := json.Marshal(body.KdfParams)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "invalid kdf_params"})
		return
	}

	salt, err := crypto.NewServerSalt()
	if err != nil {
		s.logInternalError(r, "register: new salt", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	serverHash, err := crypto.DeriveServerAuthHash(authHashBytes, salt, crypto.DefaultServerAuthParams())
	if err != nil {
		s.logInternalError(r, "register: derive server hash", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	_, err = s.store.Users.Create(r.Context(), email, kdfJSON, serverHash, salt, body.ProtectedSymmetricKey)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Unique constraint violation: email already registered.
			// Return 201 silently to prevent account enumeration — the caller
			// cannot distinguish "created" from "already exists".
			s.log.Info("register: duplicate email suppressed",
				"request_id", r.Context().Value(requestIDKey))
			w.WriteHeader(http.StatusCreated)
			return
		}
		// Any other error (DB down, constraint mismatch, …) is a real failure.
		s.logInternalError(r, "register: create user", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	// Registration audit without user id (enumeration-safe).
	s.recordEvent(r, nil, EventRegister, nil, map[string]any{"outcome": "created"})
}

// GetLoginKdfParams implements GET /api/login/kdf-params.
// Returns stored KDF parameters for the account, or defaults when unknown
// (with equalized timing) so clients can derive the auth hash before login.
func (s *Server) GetLoginKdfParams(w http.ResponseWriter, r *http.Request, params gen.GetLoginKdfParamsParams) {
	email := crypto.NormalizeEmail(string(params.Email))
	if email == "" {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "email must not be empty"})
		return
	}

	user, err := s.store.Users.GetByEmail(r.Context(), email)
	if errors.Is(err, storage.ErrNotFound) {
		// Equalize timing for unknown emails — same dummy work as failed login.
		dummySalt, _ := crypto.NewServerSalt()
		_, _ = crypto.DeriveServerAuthHash(make([]byte, 32), dummySalt, crypto.DefaultServerAuthParams())
		writeJSON(w, http.StatusOK, gen.LoginKdfParamsResponse{KdfParams: defaultGenKDFParams()})
		return
	}
	if err != nil {
		s.logInternalError(r, "login kdf-params: get user", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	var kdfParams gen.KDFParams
	if err := json.Unmarshal(user.KDFParams, &kdfParams); err != nil {
		s.logInternalError(r, "login kdf-params: unmarshal kdf_params", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	writeJSON(w, http.StatusOK, gen.LoginKdfParamsResponse{KdfParams: kdfParams})
}

func defaultGenKDFParams() gen.KDFParams {
	p := crypto.DefaultKDFParams()
	return gen.KDFParams{
		Type:        p.Type,
		Version:     int(p.Version),
		MemoryKib:   int(p.MemoryKiB),
		Iterations:  int(p.Iterations),
		Parallelism: int(p.Parallelism),
	}
}

// getLoginKdfParams adapts the generated handler signature to http.HandlerFunc.
func (s *Server) getLoginKdfParams(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "email query parameter is required"})
		return
	}
	s.GetLoginKdfParams(w, r, gen.GetLoginKdfParamsParams{
		Email: openapi_types.Email(email),
	})
}

// PostLogin implements POST /api/login.
func (s *Server) PostLogin(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)

	var body gen.LoginRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}

	email := crypto.NormalizeEmail(string(body.Email))

	if s.auth.IsLoginLocked(email) || !s.auth.CheckLoginLimit(ip, email) {
		writeJSON(w, http.StatusTooManyRequests, gen.Error{Error: "too many login attempts; try again later"})
		return
	}

	clientAuthHash, err := base64.StdEncoding.DecodeString(body.AuthHash)
	if err != nil || len(clientAuthHash) == 0 {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "auth_hash must be valid base64"})
		return
	}

	user, err := s.store.Users.GetByEmail(r.Context(), email)
	if errors.Is(err, storage.ErrNotFound) {
		// Perform a dummy hash to equalize timing for unknown vs wrong-password.
		dummySalt, _ := crypto.NewServerSalt()
		_, _ = crypto.DeriveServerAuthHash(clientAuthHash, dummySalt, crypto.DefaultServerAuthParams())
		if d := s.auth.RecordLoginFailure(email); d > 0 {
			time.Sleep(d)
		}
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "invalid credentials"})
		return
	}
	if err != nil {
		s.logInternalError(r, "login: get user", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	candidate, err := crypto.DeriveServerAuthHash(clientAuthHash, user.AuthHashSalt, crypto.DefaultServerAuthParams())
	if err != nil {
		s.logInternalError(r, "login: derive candidate hash", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	if subtle.ConstantTimeCompare(candidate, user.AuthHash) != 1 {
		uid := user.ID
		s.recordEvent(r, &uid, EventLoginFailure, nil, map[string]any{"reason": "invalid_credentials"})
		if d := s.auth.RecordLoginFailure(email); d > 0 {
			time.Sleep(d)
		}
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "invalid credentials"})
		return
	}

	// Auth succeeded — clear rate-limit counters.
	s.auth.ResetLoginLimit(ip, email)

	if user.TOTPEnabled {
		token, err := s.createMFAToken(r.Context(), user.ID)
		if err != nil {
			s.logInternalError(r, "login: mfa challenge", err)
			writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
			return
		}
		uid := user.ID
		s.recordEvent(r, &uid, EventMFARequired, nil, nil)
		mfaRequired := true
		ptotp := ""
		if user.ProtectedTOTPSecret != nil {
			ptotp = *user.ProtectedTOTPSecret
		}
		var kdfParams gen.KDFParams
		if err := json.Unmarshal(user.KDFParams, &kdfParams); err != nil {
			s.logInternalError(r, "login: unmarshal kdf_params", err)
			writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
			return
		}
		psk := user.ProtectedSymmetricKey
		writeJSON(w, http.StatusOK, gen.LoginResponse{
			MfaRequired:           &mfaRequired,
			MfaToken:              &token,
			ProtectedTotpSecret:   &ptotp,
			ProtectedSymmetricKey: &psk,
			KdfParams:             &kdfParams,
		})
		return
	}

	s.completeLogin(w, r, user)
}

// PostAuthRefresh implements POST /api/auth/refresh.
func (s *Server) PostAuthRefresh(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(auth.RefreshCookieName)
	if err != nil || cookie.Value == "" {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	newAccess, newRefresh, err := s.auth.RefreshSession(r.Context(), cookie.Value)
	if errors.Is(err, auth.ErrSessionInvalid) {
		clearAuthCookies(w)
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}
	if err != nil {
		s.logInternalError(r, "auth refresh", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	setAuthCookies(w, newAccess, newRefresh, s.auth.AccessTTL(), s.auth.RefreshTTL())
	w.WriteHeader(http.StatusNoContent)
}

// PostLogout implements POST /api/logout.
func (s *Server) PostLogout(w http.ResponseWriter, r *http.Request) {
	userID, _ := userIDFromCtx(r.Context())
	cookie, err := r.Cookie(auth.AccessCookieName)
	if err == nil {
		if rErr := s.auth.RevokeSession(r.Context(), cookie.Value); rErr != nil {
			s.logInternalError(r, "logout: revoke session", rErr)
		}
	}

	clearAuthCookies(w)
	if userID != uuid.Nil {
		s.recordEvent(r, &userID, EventLogout, nil, nil)
	}
	w.WriteHeader(http.StatusNoContent)
}

// DeleteUser implements DELETE /api/user.
func (s *Server) DeleteUser(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	if err := s.auth.RevokeAllSessions(r.Context(), userID); err != nil {
		s.logInternalError(r, "delete user: revoke sessions", err)
	}

	if err := s.store.Users.DeleteUser(r.Context(), userID); err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.logInternalError(r, "delete user", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to delete account"})
		return
	}

	clearAuthCookies(w)
	s.recordEvent(r, &userID, EventUserDelete, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// PutUserKey implements PUT /api/user/key — master-password rotation.
func (s *Server) PutUserKey(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	var body gen.UpdateKeyRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}

	newAuthHashBytes, err := base64.StdEncoding.DecodeString(body.AuthHash)
	if err != nil || len(newAuthHashBytes) == 0 {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "auth_hash must be valid base64"})
		return
	}

	if err := validateCiphertext(body.ProtectedSymmetricKey); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "protected_symmetric_key: " + err.Error()})
		return
	}

	newSalt, err := crypto.NewServerSalt()
	if err != nil {
		s.logInternalError(r, "key rotation: new salt", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	newServerHash, err := crypto.DeriveServerAuthHash(newAuthHashBytes, newSalt, crypto.DefaultServerAuthParams())
	if err != nil {
		s.logInternalError(r, "key rotation: derive hash", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	kdfJSON, err := json.Marshal(body.KdfParams)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "invalid kdf_params"})
		return
	}

	if _, err := s.store.Users.UpdateAuthCredentials(r.Context(), userID, newServerHash, newSalt, kdfJSON, body.ProtectedSymmetricKey); err != nil {
		s.logInternalError(r, "key rotation: update credentials", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to update credentials"})
		return
	}

	s.recordEvent(r, &userID, EventKeyRotation, nil, nil)
	w.WriteHeader(http.StatusOK)
}

// clientIP extracts the real client IP from RemoteAddr, stripping the port.
// For production deployments behind a reverse proxy, extend this to read
// X-Forwarded-For or X-Real-IP (after validating the proxy is trusted).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

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
	rid := item.ID
	s.recordEvent(r, &userID, EventItemCreate, &rid, map[string]any{"item_type": body.ItemType})
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
	rid := item.ID
	s.recordEvent(r, &userID, EventItemUpdate, &rid, map[string]any{"revision": item.Revision})
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
	s.recordEvent(r, &userID, EventItemDelete, &id, nil)
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
		TotpEnabled:           user.TOTPEnabled,
		ProtectedTotpSecret:   user.ProtectedTOTPSecret,
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
