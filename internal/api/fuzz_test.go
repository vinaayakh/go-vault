package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
)

func TestDecodeJSONRejectsUnknownFields(t *testing.T) {
	body := `{"email":"a@b.com","auth_hash":"abc","extra":1}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte(body)))
	var dst gen.LoginRequest
	if err := decodeJSON(req, &dst); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func FuzzDecodeJSONLogin(f *testing.F) {
	f.Add([]byte(`{"email":"test@example.com","auth_hash":"dGVzdA=="}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		req := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(data))
		var dst gen.LoginRequest
		_ = decodeJSON(req, &dst)
	})
}
