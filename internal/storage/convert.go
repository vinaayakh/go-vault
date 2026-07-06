package storage

import (
	"encoding/json"
	"fmt"
	"math"
	"net"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

func userFromRow(u *sqlcgen.User) *User {
	return &User{
		ID:                    u.ID,
		Email:                 u.Email,
		KDFParams:             u.KdfParams,
		AuthHash:              u.AuthHash,
		AuthHashSalt:          u.AuthHashSalt,
		ProtectedSymmetricKey: u.ProtectedSymmetricKey,
		TOTPEnabled:           u.TotpEnabled,
		ProtectedTOTPSecret:   u.ProtectedTotpSecret,
		CreatedAt:             u.CreatedAt,
	}
}

func itemFromRow(i sqlcgen.VaultItem) *VaultItem {
	return &VaultItem{
		ID:         i.ID,
		UserID:     i.UserID,
		Ciphertext: i.Ciphertext,
		ItemType:   i.ItemType,
		Revision:   int(i.Revision),
		UpdatedAt:  i.UpdatedAt,
	}
}

func sessionFromRow(s *sqlcgen.Session) *Session {
	return &Session{
		ID:               s.ID,
		UserID:           s.UserID,
		AccessTokenHash:  s.AccessTokenHash,
		AccessExpiresAt:  s.AccessExpiresAt,
		RefreshTokenHash: s.RefreshTokenHash,
		RefreshExpiresAt: s.RefreshExpiresAt,
		CreatedAt:        s.CreatedAt,
	}
}

func auditFromRow(ev sqlcgen.ListAuditEventsByUserRow) *AuditEvent {
	out := &AuditEvent{
		ID:         ev.ID,
		UserID:     ev.UserID,
		EventType:  ev.EventType,
		UserAgent:  derefString(ev.UserAgent),
		ResourceID: ev.ResourceID,
		Metadata:   ev.Metadata,
		CreatedAt:  ev.CreatedAt,
	}
	if ev.Ip != nil && *ev.Ip != "" {
		out.IP = net.ParseIP(*ev.Ip)
	}
	return out
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func emptyMetadata(m json.RawMessage) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage(`{}`)
	}
	return m
}

func auditLimit(limit int) int32 {
	if limit <= 0 || limit > 100 {
		return 50
	}
	return int32(limit)
}

func revisionAsInt32(rev int) (int32, error) {
	if rev < 0 || rev > math.MaxInt32 {
		return 0, fmt.Errorf("revision out of range: %d", rev)
	}
	return int32(rev), nil
}
