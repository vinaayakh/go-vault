//go:build integration

// Integration tests for Phase 3 auth: register → login → authenticated requests
// → logout flow. They require a live PostgreSQL database with migrations applied.
//
// Run with:
//
//	TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/api/...
package api_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/api"
	"github.com/vinaayakh/secure-vault/internal/api/gen"
	"github.com/vinaayakh/secure-vault/internal/auth"
	"github.com/vinaayakh/secure-vault/internal/config"
	"github.com/vinaayakh/secure-vault/internal/crypto"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

// testServer creates an httptest.Server backed by real storage and auth.
// The test skips if TEST_DATABASE_URL is unset.
func testServer(t *testing.T) (*httptest.Server, *storage.Store) {
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

	cfg := &config.Config{
		AllowedOrigin:   "http://localhost:5173",
		SessionDuration: 24 * time.Hour,
	}
	authMgr := auth.NewManager(store.Sessions, cfg.SessionDuration)

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	handler := api.NewRouter(log, store, authMgr, cfg)

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv, store
}

// clientCreds holds the client-side derived material for a test user.
type clientCreds struct {
	Email                 string
	Password              string
	AuthHash              string // base64
	KDFParams             gen.KDFParams
	ProtectedSymmetricKey string // base64
}

// deriveClientCreds runs the client-side key derivation for a test user.
func deriveClientCreds(t *testing.T, email, password string) clientCreds {
	t.Helper()
	params := crypto.DefaultKDFParams()
	normEmail := crypto.NormalizeEmail(email)

	masterKey, err := crypto.DeriveMasterKey([]byte(password), []byte(normEmail), params)
	if err != nil {
		t.Fatalf("derive master key: %v", err)
	}

	encKey, _, err := crypto.StretchMasterKey(masterKey)
	if err != nil {
		t.Fatalf("stretch master key: %v", err)
	}

	authHash, err := crypto.DeriveAuthHash(masterKey, []byte(password), params)
	if err != nil {
		t.Fatalf("derive auth hash: %v", err)
	}

	vaultKey, err := crypto.NewVaultKey()
	if err != nil {
		t.Fatalf("new vault key: %v", err)
	}

	protectedKey, err := crypto.WrapKey(encKey, vaultKey, nil)
	if err != nil {
		t.Fatalf("wrap vault key: %v", err)
	}

	return clientCreds{
		Email:    email,
		Password: password,
		AuthHash: base64.StdEncoding.EncodeToString(authHash),
		KDFParams: gen.KDFParams{
			Type:        params.Type,
			Version:     int(params.Version),
			MemoryKib:   int(params.MemoryKiB),
			Iterations:  int(params.Iterations),
			Parallelism: int(params.Parallelism),
		},
		ProtectedSymmetricKey: base64.StdEncoding.EncodeToString(protectedKey),
	}
}

func uniqueEmail() string {
	return fmt.Sprintf("test+%s@example.com", uuid.New().String())
}

func doJSON(t *testing.T, client *http.Client, baseURL, method, path string, body any, cookie *http.Cookie) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}

	req, err := http.NewRequest(method, baseURL+path, &buf)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-CSRF", "1")
	if cookie != nil {
		req.AddCookie(cookie)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			return c
		}
	}
	return nil
}

// TestRegisterLogin covers the full register → login → sync → logout flow.
func TestRegisterLogin(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}
	creds := deriveClientCreds(t, uniqueEmail(), "correct-horse-battery-staple")

	// Register.
	regResp := doJSON(t, client, srv.URL, http.MethodPost, "/api/register",
		map[string]any{
			"email":                   creds.Email,
			"kdf_params":              creds.KDFParams,
			"auth_hash":               creds.AuthHash,
			"protected_symmetric_key": creds.ProtectedSymmetricKey,
		}, nil)
	regResp.Body.Close()
	if regResp.StatusCode != http.StatusCreated {
		t.Fatalf("register: got %d, want 201", regResp.StatusCode)
	}

	// Login.
	loginResp := doJSON(t, client, srv.URL, http.MethodPost, "/api/login",
		map[string]any{"email": creds.Email, "auth_hash": creds.AuthHash}, nil)
	defer loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login: got %d, want 200", loginResp.StatusCode)
	}

	cookie := sessionCookie(loginResp)
	if cookie == nil {
		t.Fatal("login: no vault_session cookie in response")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Error("session cookie must be SameSite=Strict")
	}

	var loginBody gen.LoginResponse
	if err := json.NewDecoder(loginResp.Body).Decode(&loginBody); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginBody.ProtectedSymmetricKey != creds.ProtectedSymmetricKey {
		t.Error("login response: protected_symmetric_key mismatch")
	}

	// Sync with session.
	syncResp := doJSON(t, client, srv.URL, http.MethodGet, "/api/sync", nil, cookie)
	defer syncResp.Body.Close()
	if syncResp.StatusCode != http.StatusOK {
		t.Fatalf("sync: got %d, want 200", syncResp.StatusCode)
	}
}

// TestLogout verifies that after logout the session is revoked.
func TestLogout(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}
	creds := deriveClientCreds(t, uniqueEmail(), "correct-horse-battery-staple")

	doJSON(t, client, srv.URL, http.MethodPost, "/api/register",
		map[string]any{
			"email": creds.Email, "kdf_params": creds.KDFParams,
			"auth_hash": creds.AuthHash, "protected_symmetric_key": creds.ProtectedSymmetricKey,
		}, nil).Body.Close()

	loginResp := doJSON(t, client, srv.URL, http.MethodPost, "/api/login",
		map[string]any{"email": creds.Email, "auth_hash": creds.AuthHash}, nil)
	cookie := sessionCookie(loginResp)
	loginResp.Body.Close()

	// Logout.
	logoutResp := doJSON(t, client, srv.URL, http.MethodPost, "/api/logout", nil, cookie)
	logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout: got %d, want 204", logoutResp.StatusCode)
	}

	// Reuse the old token — must get 401.
	syncResp := doJSON(t, client, srv.URL, http.MethodGet, "/api/sync", nil, cookie)
	syncResp.Body.Close()
	if syncResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("sync after logout: got %d, want 401", syncResp.StatusCode)
	}
}

// TestLoginWrongPassword verifies that a bad auth hash returns 401.
func TestLoginWrongPassword(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}
	creds := deriveClientCreds(t, uniqueEmail(), "correct-horse-battery-staple")
	wrongCreds := deriveClientCreds(t, creds.Email, "wrong-password")

	doJSON(t, client, srv.URL, http.MethodPost, "/api/register",
		map[string]any{
			"email": creds.Email, "kdf_params": creds.KDFParams,
			"auth_hash": creds.AuthHash, "protected_symmetric_key": creds.ProtectedSymmetricKey,
		}, nil).Body.Close()

	resp := doJSON(t, client, srv.URL, http.MethodPost, "/api/login",
		map[string]any{"email": creds.Email, "auth_hash": wrongCreds.AuthHash}, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", resp.StatusCode)
	}
}

// TestRegisterEnumeration verifies that registering twice returns the same status.
func TestRegisterEnumeration(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}
	creds := deriveClientCreds(t, uniqueEmail(), "correct-horse-battery-staple")

	body := map[string]any{
		"email": creds.Email, "kdf_params": creds.KDFParams,
		"auth_hash": creds.AuthHash, "protected_symmetric_key": creds.ProtectedSymmetricKey,
	}

	r1 := doJSON(t, client, srv.URL, http.MethodPost, "/api/register", body, nil)
	r1.Body.Close()
	r2 := doJSON(t, client, srv.URL, http.MethodPost, "/api/register", body, nil)
	r2.Body.Close()

	if r1.StatusCode != r2.StatusCode {
		t.Errorf("register enumeration: first=%d second=%d, want same status", r1.StatusCode, r2.StatusCode)
	}
	if r1.StatusCode != http.StatusCreated {
		t.Errorf("register: got %d, want 201", r1.StatusCode)
	}
}

// TestCSRFRejection confirms that POST without X-Vault-CSRF header returns 403.
func TestCSRFRejection(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/register", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	// Deliberately omit X-Vault-CSRF header.

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("missing CSRF header: got %d, want 403", resp.StatusCode)
	}
}

// TestUnauthenticatedSync verifies that GET /api/sync without a session returns 401.
func TestUnauthenticatedSync(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/sync", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated sync: got %d, want 401", resp.StatusCode)
	}
}

// TestSecurityHeaders verifies that key security headers are present.
func TestSecurityHeaders(t *testing.T) {
	srv, _ := testServer(t)
	client := &http.Client{}

	resp, err := client.Get(srv.URL + "/api/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	resp.Body.Close()

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, value := range want {
		if got := resp.Header.Get(header); got != value {
			t.Errorf("header %s: got %q, want %q", header, got, value)
		}
	}
	if csp := resp.Header.Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header missing")
	}
}
