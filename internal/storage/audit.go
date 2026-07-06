package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
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

// AuditRepo provides append-only audit log access.
type AuditRepo struct {
	pool *pgxpool.Pool
}

const appendAuditSQL = `
INSERT INTO audit_events (user_id, event_type, ip, user_agent, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, created_at`

// Append inserts a new audit event (never updated or deleted).
func (r *AuditRepo) Append(
	ctx context.Context,
	userID *uuid.UUID,
	eventType string,
	ip net.IP,
	userAgent string,
	resourceID *uuid.UUID,
	metadata json.RawMessage,
) (*AuditEvent, error) {
	if len(metadata) == 0 {
		metadata = json.RawMessage(`{}`)
	}
	ev := &AuditEvent{
		UserID:     userID,
		EventType:  eventType,
		IP:         ip,
		UserAgent:  userAgent,
		ResourceID: resourceID,
		Metadata:   metadata,
	}
	err := r.pool.QueryRow(ctx, appendAuditSQL,
		userID, eventType, ip, userAgent, resourceID, metadata,
	).Scan(&ev.ID, &ev.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("append audit event: %w", err)
	}
	return ev, nil
}

const listAuditSQL = `
SELECT id, user_id, event_type, ip::text, user_agent, resource_id, metadata, created_at
FROM audit_events
WHERE user_id = $1
  AND ($2::uuid IS NULL OR created_at < (SELECT created_at FROM audit_events WHERE id = $2))
ORDER BY created_at DESC
LIMIT $3`

// ListByUser returns paginated audit events for a user (newest first).
func (r *AuditRepo) ListByUser(ctx context.Context, userID uuid.UUID, cursor *uuid.UUID, limit int) ([]*AuditEvent, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := r.pool.Query(ctx, listAuditSQL, userID, cursor, limit+1)
	if err != nil {
		return nil, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []*AuditEvent
	for rows.Next() {
		ev := &AuditEvent{}
		var ipStr *string
		var uid *uuid.UUID
		if err := rows.Scan(
			&ev.ID, &uid, &ev.EventType, &ipStr, &ev.UserAgent,
			&ev.ResourceID, &ev.Metadata, &ev.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit event: %w", err)
		}
		ev.UserID = uid
		if ipStr != nil && *ipStr != "" {
			ev.IP = net.ParseIP(*ipStr)
		}
		events = append(events, ev)
	}
	return events, rows.Err()
}

const countRecentFailuresSQL = `
SELECT COUNT(*) FROM audit_events
WHERE user_id = $1 AND event_type = 'login_failure'
  AND created_at > NOW() - INTERVAL '15 minutes'`

// CountRecentLoginFailures returns login_failure events in the last 15 minutes.
func (r *AuditRepo) CountRecentLoginFailures(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, countRecentFailuresSQL, userID).Scan(&n)
	return n, err
}

const recordDeviceSQL = `
INSERT INTO user_device_hashes (user_id, ua_hash)
VALUES ($1, $2)
ON CONFLICT DO NOTHING
RETURNING user_id`

// RecordDeviceHash inserts a user-agent hash if new. Returns true when first seen.
func (r *AuditRepo) RecordDeviceHash(ctx context.Context, userID uuid.UUID, uaHash []byte) (bool, error) {
	var dummy uuid.UUID
	err := r.pool.QueryRow(ctx, recordDeviceSQL, userID, uaHash).Scan(&dummy)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("record device hash: %w", err)
	}
	return true, nil
}
