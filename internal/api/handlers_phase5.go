package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/vinaayakh/secure-vault/internal/api/gen"
	"github.com/vinaayakh/secure-vault/internal/mfa"
	"github.com/vinaayakh/secure-vault/internal/storage"
)

func (s *Server) createMFAToken(ctx context.Context, userID uuid.UUID) (string, error) {
	raw, err := generateHexToken()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(raw))
	if err := s.store.MFA.CreateChallenge(ctx, userID, hash[:], time.Now().Add(mfaChallengeTTL)); err != nil {
		return "", err
	}
	return raw, nil
}

func (s *Server) validateMFAToken(ctx context.Context, token string) (uuid.UUID, error) {
	hash := sha256.Sum256([]byte(token))
	return s.store.MFA.ConsumeChallenge(ctx, hash[:])
}

func generateHexToken() (string, error) {
	return authGenerateToken()
}

// authGenerateToken wraps token generation without importing unexported auth symbols.
func authGenerateToken() (string, error) {
	// Reuse session token format: 32 random bytes as hex.
	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randRead(b []byte) (int, error) {
	return randReadCrypto(b)
}

// PostLoginMfa implements POST /api/login/mfa.
func (s *Server) PostLoginMfa(w http.ResponseWriter, r *http.Request) {
	var body gen.LoginMfaRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}
	if body.MfaToken == "" {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "mfa_token is required"})
		return
	}

	userID, err := s.validateMFAToken(r.Context(), body.MfaToken)
	if errors.Is(err, storage.ErrNotFound) {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "invalid or expired MFA challenge"})
		return
	}
	if err != nil {
		s.logInternalError(r, "login mfa: validate token", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	verified := false
	switch {
	case body.RecoveryCode != nil && *body.RecoveryCode != "":
		ok, err := s.store.MFA.ConsumeRecoveryCode(r.Context(), userID, func(h []byte) bool {
			return mfa.VerifyRecoveryCode(*body.RecoveryCode, h)
		})
		if err != nil {
			s.logInternalError(r, "login mfa: recovery code", err)
			writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
			return
		}
		verified = ok
	case body.TotpCode != nil && body.TotpSecret != nil:
		verified = mfa.ValidateTOTP(*body.TotpSecret, *body.TotpCode)
	default:
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "totp_code and totp_secret or recovery_code required"})
		return
	}

	if !verified {
		s.recordEvent(r, &userID, EventMFAFailure, nil, nil)
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "invalid MFA code"})
		return
	}

	user, err := s.store.Users.GetByID(r.Context(), userID)
	if err != nil {
		s.logInternalError(r, "login mfa: get user", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	s.completeLogin(w, r, user)
	s.recordEvent(r, &userID, EventMFASuccess, nil, nil)
}

func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, user *storage.User) {
	accessRaw, refreshRaw, err := s.auth.CreateSessionPair(r.Context(), user.ID)
	if err != nil {
		s.logInternalError(r, "login: create session", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	setAuthCookies(w, accessRaw, refreshRaw, s.auth.AccessTTL(), s.auth.RefreshTTL())

	var kdfParams gen.KDFParams
	if err := json.Unmarshal(user.KDFParams, &kdfParams); err != nil {
		s.logInternalError(r, "login: unmarshal kdf_params", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	psk := user.ProtectedSymmetricKey
	writeJSON(w, http.StatusOK, gen.LoginResponse{
		ProtectedSymmetricKey: &psk,
		KdfParams:             &kdfParams,
	})
	s.recordEvent(r, &user.ID, EventLoginSuccess, nil, nil)
}

// PostUser2faEnroll implements POST /api/user/2fa/enroll.
func (s *Server) PostUser2faEnroll(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	var body gen.Enroll2faRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}
	if err := validateCiphertext(body.ProtectedTotpSecret); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "protected_totp_secret: " + err.Error()})
		return
	}
	if !mfa.ValidateTOTP(body.TotpSecret, body.TotpCode) {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "invalid TOTP code"})
		return
	}

	enabled, _, err := s.store.MFA.GetTOTPStatus(r.Context(), userID)
	if err != nil {
		s.logInternalError(r, "2fa enroll: status", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}
	if enabled {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: "2FA is already enabled"})
		return
	}

	if err := s.store.MFA.EnableTOTP(r.Context(), userID, body.ProtectedTotpSecret); err != nil {
		s.logInternalError(r, "2fa enroll", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to enable 2FA"})
		return
	}

	codes, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		s.logInternalError(r, "2fa enroll: recovery codes", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}
	if err := s.store.MFA.ReplaceRecoveryCodes(r.Context(), userID, hashes); err != nil {
		s.logInternalError(r, "2fa enroll: store recovery", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	s.recordEvent(r, &userID, Event2FAEnroll, nil, nil)
	writeJSON(w, http.StatusOK, gen.Enroll2faResponse{RecoveryCodes: codes})
}

// DeleteUser2fa implements DELETE /api/user/2fa.
func (s *Server) DeleteUser2fa(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	var body gen.Disable2faRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}

	if !s.verify2FACredential(r.Context(), userID, body) {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "invalid verification code"})
		return
	}

	if err := s.store.MFA.DisableTOTP(r.Context(), userID); err != nil {
		s.logInternalError(r, "2fa disable", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to disable 2FA"})
		return
	}

	s.recordEvent(r, &userID, Event2FADisable, nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// PostUser2faRecoveryCodes implements POST /api/user/2fa/recovery-codes.
func (s *Server) PostUser2faRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	var body gen.RegenerateRecoveryCodesRequest
	if err := decodeJSON(r, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, gen.Error{Error: err.Error()})
		return
	}
	if !mfa.ValidateTOTP(body.TotpSecret, body.TotpCode) {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "invalid TOTP code"})
		return
	}

	codes, hashes, err := mfa.GenerateRecoveryCodes()
	if err != nil {
		s.logInternalError(r, "recovery regen", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}
	if err := s.store.MFA.ReplaceRecoveryCodes(r.Context(), userID, hashes); err != nil {
		s.logInternalError(r, "recovery regen: store", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "internal server error"})
		return
	}

	s.recordEvent(r, &userID, EventRecoveryRegen, nil, nil)
	writeJSON(w, http.StatusOK, gen.RecoveryCodesResponse{RecoveryCodes: codes})
}

func (s *Server) verify2FACredential(ctx context.Context, userID uuid.UUID, body gen.Disable2faRequest) bool {
	switch {
	case body.RecoveryCode != nil && *body.RecoveryCode != "":
		ok, _ := s.store.MFA.ConsumeRecoveryCode(ctx, userID, func(h []byte) bool {
			return mfa.VerifyRecoveryCode(*body.RecoveryCode, h)
		})
		return ok
	case body.TotpCode != nil && body.TotpSecret != nil:
		return mfa.ValidateTOTP(*body.TotpSecret, *body.TotpCode)
	default:
		return false
	}
}

// GetActivity implements GET /api/activity.
func (s *Server) GetActivity(w http.ResponseWriter, r *http.Request, params gen.GetActivityParams) {
	userID, ok := userIDFromCtx(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, gen.Error{Error: "authentication required"})
		return
	}

	limit := 50
	if params.Limit != nil {
		limit = *params.Limit
	}

	var cursor *uuid.UUID
	if params.Cursor != nil {
		c := uuid.UUID(*params.Cursor)
		cursor = &c
	}

	events, err := s.store.Audit.ListByUser(r.Context(), userID, cursor, limit)
	if err != nil {
		s.logInternalError(r, "activity list", err)
		writeJSON(w, http.StatusInternalServerError, gen.Error{Error: "failed to load activity"})
		return
	}

	hasMore := len(events) > limit
	if hasMore {
		events = events[:limit]
	}

	resp := gen.ActivityResponse{Events: make([]gen.ActivityEvent, 0, len(events))}
	for _, ev := range events {
		ae := gen.ActivityEvent{
			Id:        ev.ID,
			EventType: ev.EventType,
			CreatedAt: ev.CreatedAt,
		}
		if ev.IP != nil {
			ip := ev.IP.String()
			ae.Ip = &ip
		}
		if ev.UserAgent != "" {
			ae.UserAgent = &ev.UserAgent
		}
		if ev.ResourceID != nil {
			rid := openapi_types.UUID(*ev.ResourceID)
			ae.ResourceId = &rid
		}
		var meta map[string]any
		if len(ev.Metadata) > 0 {
			_ = json.Unmarshal(ev.Metadata, &meta)
		}
		ae.Metadata = &meta
		resp.Events = append(resp.Events, ae)
	}
	if hasMore && len(events) > 0 {
		last := events[len(events)-1].ID
		cursorID := openapi_types.UUID(last)
		resp.NextCursor = &cursorID
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) getActivity(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := parseIntParam(l); err == nil && n > 0 {
			limit = n
		}
	}
	var cursor *openapi_types.UUID
	if c := r.URL.Query().Get("cursor"); c != "" {
		if id, err := uuid.Parse(c); err == nil {
			cid := openapi_types.UUID(id)
			cursor = &cid
		}
	}
	s.GetActivity(w, r, gen.GetActivityParams{Limit: &limit, Cursor: cursor})
}
