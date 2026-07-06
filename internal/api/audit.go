package api

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/audit"
)

// Event type constants for the append-only audit log.
const (
	EventLoginSuccess  = "login_success"
	EventLoginFailure  = "login_failure"
	EventMFARequired   = "mfa_required"
	EventMFASuccess    = "mfa_success"
	EventMFAFailure    = "mfa_failure"
	EventLogout        = "logout"
	EventRegister      = "register"
	EventUserDelete    = "user_delete"
	EventKeyRotation   = "key_rotation"
	EventItemCreate    = "item_create"
	EventItemUpdate    = "item_update"
	EventItemDelete    = "item_delete"
	Event2FAEnroll     = "2fa_enroll"
	Event2FADisable    = "2fa_disable"
	EventRecoveryRegen = "recovery_codes_regen"
)

func (s *Server) recordEvent(r *http.Request, userID *uuid.UUID, eventType string, resourceID *uuid.UUID, meta map[string]any) {
	ip := net.ParseIP(clientIP(r))
	ua := userAgentFromCtx(r.Context())
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		metaJSON = []byte("{}")
	}
	if _, err := s.store.Audit.Append(r.Context(), userID, eventType, ip, ua, resourceID, metaJSON); err != nil {
		s.log.Error("audit append failed", "event_type", eventType, "error", err)
	}
	if userID != nil && eventType == EventLoginFailure {
		s.alerts.RecordLoginFailure(*userID, clientIP(r))
	}
	if userID != nil && eventType == EventLoginSuccess {
		s.alerts.ResetFailures(*userID)
		hash := audit.HashUserAgent(ua)
		if len(hash) > 0 {
			if isNew, err := s.store.Audit.RecordDeviceHash(r.Context(), *userID, hash); err == nil && isNew {
				s.notifier.NewDevice(*userID, ua)
			}
		}
	}
}
