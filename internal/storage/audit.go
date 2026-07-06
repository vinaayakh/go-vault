package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/vinaayakh/secure-vault/internal/storage/sqlcgen"
)

// AuditEvent is a metadata-only security event row.
type AuditEvent struct {
	ID         uuid.UUID
	UserID     *uuid.UUID
	EventType  string
	IP         net.IP
	UserAgent  string
	ResourceID *uuid.UUID
	Metadata   json.RawMessage
	CreatedAt  time.Time
}

// AuditRepo provides append-only audit log access via sqlc.
type AuditRepo struct {
	q *sqlcgen.Queries
}

// Append inserts a new audit event.
func (r *AuditRepo) Append(
	ctx context.Context,
	userID *uuid.UUID,
	eventType string,
	ip net.IP,
	userAgent string,
	resourceID *uuid.UUID,
	metadata json.RawMessage,
) (*AuditEvent, error) {
	var ipArg *net.IP
	if ip != nil {
		ipArg = &ip
	}
	var ua *string
	if userAgent != "" {
		ua = &userAgent
	}
	row, err := r.q.AppendAuditEvent(ctx, sqlcgen.AppendAuditEventParams{
		UserID:     userID,
		EventType:  eventType,
		Ip:         ipArg,
		UserAgent:  ua,
		ResourceID: resourceID,
		Metadata:   emptyMetadata(metadata),
	})
	if err != nil {
		return nil, fmt.Errorf("append audit event: %w", err)
	}
	return &AuditEvent{
		UserID:     userID,
		EventType:  eventType,
		IP:         ip,
		UserAgent:  userAgent,
		ResourceID: resourceID,
		Metadata:   emptyMetadata(metadata),
		ID:         row.ID,
		CreatedAt:  row.CreatedAt,
	}, nil
}

// ListByUser returns paginated audit events for a user.
func (r *AuditRepo) ListByUser(ctx context.Context, userID uuid.UUID, cursor *uuid.UUID, limit int) ([]*AuditEvent, error) {
	lim := auditLimit(limit)
	rows, err := r.q.ListAuditEventsByUser(ctx, sqlcgen.ListAuditEventsByUserParams{
		UserID: userID,
		Cursor: cursor,
		Limit:  lim + 1,
	})
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	events := make([]*AuditEvent, 0, len(rows))
	for _, row := range rows {
		events = append(events, auditFromRow(row))
	}
	return events, nil
}

// CountRecentLoginFailures returns login_failure events in the last 15 minutes.
func (r *AuditRepo) CountRecentLoginFailures(ctx context.Context, userID uuid.UUID) (int, error) {
	n, err := r.q.CountRecentLoginFailures(ctx, userID)
	return int(n), err
}

// RecordDeviceHash inserts a user-agent hash if new. Returns true when first seen.
func (r *AuditRepo) RecordDeviceHash(ctx context.Context, userID uuid.UUID, uaHash []byte) (bool, error) {
	_, err := r.q.RecordDeviceHash(ctx, userID, uaHash)
	if mapNotFound(err) == ErrNotFound {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("record device hash: %w", err)
	}
	return true, nil
}
