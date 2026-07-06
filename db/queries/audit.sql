-- name: AppendAuditEvent :one
INSERT INTO audit_events (user_id, event_type, ip, user_agent, resource_id, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, created_at;

-- name: ListAuditEventsByUser :many
SELECT id, user_id, event_type, host(ip) AS ip, user_agent, resource_id, metadata, created_at
FROM audit_events
WHERE user_id = $1
  AND (sqlc.narg('cursor')::uuid IS NULL OR created_at < (SELECT created_at FROM audit_events WHERE id = sqlc.narg('cursor')))
ORDER BY created_at DESC
LIMIT $2;

-- name: CountRecentLoginFailures :one
SELECT COUNT(*)::int FROM audit_events
WHERE user_id = $1 AND event_type = 'login_failure'
  AND created_at > NOW() - INTERVAL '15 minutes';

-- name: RecordDeviceHash :one
INSERT INTO user_device_hashes (user_id, ua_hash)
VALUES ($1, $2)
ON CONFLICT DO NOTHING
RETURNING user_id;
