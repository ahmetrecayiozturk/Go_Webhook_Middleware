-- name: GetActiveRouteBySlug :one
SELECT
    r.id,
    r.tenant_id,
    r.route_slug,
    r.provider_type,
    r.signing_secret_enc,
    r.outgoing_secret_enc,
    r.target_url,
    r.target_headers_enc,
    r.rate_limit_per_sec,
    r.max_retries,
    r.is_active,
    t.monthly_event_quota
FROM routes r
INNER JOIN tenants t ON t.id = r.tenant_id
WHERE r.route_slug = $1
  AND r.is_active = TRUE
  AND t.is_active = TRUE
LIMIT 1;

-- name: InsertOutboxEvent :execrows
INSERT INTO outbox_events (
    tenant_id,
    route_id,
    event_id,
    event_type,
    content_type,
    headers,
    payload,
    status
)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'PENDING')
ON CONFLICT (route_id, event_id) DO NOTHING;

-- name: FetchPendingOutboxEvents :many
WITH picked AS (
    SELECT oe.id
    FROM outbox_events oe
    WHERE oe.status = 'PENDING'
      AND (oe.next_retry_at IS NULL OR oe.next_retry_at <= NOW())
    ORDER BY oe.created_at ASC
    LIMIT sqlc.arg(batch_limit)
    FOR UPDATE SKIP LOCKED
),
updated AS (
    UPDATE outbox_events oe
    SET status = 'PROCESSING', updated_at = NOW()
    FROM picked
    WHERE oe.id = picked.id
    RETURNING
        oe.id,
        oe.tenant_id,
        oe.route_id,
        oe.event_id,
        oe.event_type,
        oe.content_type,
        oe.headers,
        oe.payload,
        oe.retry_count
)
SELECT
    u.id,
    u.tenant_id,
    u.route_id,
    u.event_id,
    u.event_type,
    u.content_type,
    u.headers,
    u.payload,
    u.retry_count,
    r.route_slug,
    r.target_url,
    r.target_headers_enc,
    r.outgoing_secret_enc,
    r.max_retries
FROM updated u
INNER JOIN routes r ON r.id = u.route_id;

-- name: MarkOutboxEventAsCompleted :exec
UPDATE outbox_events
SET status = 'COMPLETED', updated_at = NOW()
WHERE id = $1;

-- name: MarkOutboxEventForRetry :exec
UPDATE outbox_events
SET status = 'PENDING',
    retry_count = retry_count + 1,
    next_retry_at = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: MoveToDLQ :exec
WITH deleted_events AS (
    DELETE FROM outbox_events oe
    WHERE oe.id = $1
    RETURNING
        oe.id,
        oe.tenant_id,
        oe.route_id,
        oe.event_id,
        oe.event_type,
        oe.content_type,
        oe.headers,
        oe.payload
)
INSERT INTO dead_letter_queue (
    original_outbox_id,
    tenant_id,
    route_id,
    event_id,
    event_type,
    content_type,
    headers,
    payload,
    error_reason
)
SELECT
    de.id,
    de.tenant_id,
    de.route_id,
    de.event_id,
    de.event_type,
    de.content_type,
    de.headers,
    de.payload,
    $2
FROM deleted_events de;

-- name: ReplayDLQEvents :many
WITH deleted_dlq AS (
    DELETE FROM dead_letter_queue dlq
    WHERE dlq.id = ANY(sqlc.arg(dlq_ids)::bigint[])
      AND (sqlc.arg(tenant_id)::bigint = 0 OR dlq.tenant_id = sqlc.arg(tenant_id)::bigint)
    RETURNING
        dlq.tenant_id,
        dlq.route_id,
        dlq.event_id,
        dlq.event_type,
        dlq.content_type,
        dlq.headers,
        dlq.payload
)
INSERT INTO outbox_events (
    tenant_id, route_id, event_id, event_type, content_type, headers, payload, status, retry_count, next_retry_at
)
SELECT tenant_id, route_id, event_id, event_type, content_type, headers, payload, 'PENDING', 0, NOW()
FROM deleted_dlq
ON CONFLICT (route_id, event_id) DO UPDATE
SET status = 'PENDING', retry_count = 0, next_retry_at = NOW(), updated_at = NOW()
RETURNING event_id;

-- name: SweepOrphanedEvents :exec
UPDATE outbox_events
SET status = 'PENDING', updated_at = NOW()
WHERE status = 'PROCESSING'
  AND updated_at < NOW() - INTERVAL '5 minutes';


-- name: DeferOutboxEvent :exec
UPDATE outbox_events
SET status = 'PENDING',
    next_retry_at = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: InsertDeliveryAttempt :exec
INSERT INTO delivery_attempts (
    tenant_id,
    route_id,
    outbox_event_id,
    event_id,
    attempt_number,
    http_status,
    duration_ms,
    error_summary,
    response_body_snippet
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9);

-- name: DeleteOldCompletedOutboxEvents :execrows
DELETE FROM outbox_events
WHERE id IN (
    SELECT id
    FROM outbox_events
    WHERE status = 'COMPLETED'
      AND updated_at < NOW() - INTERVAL '30 days'
    LIMIT 1000
);

-- name: DeleteOldDeliveryAttempts :execrows
DELETE FROM delivery_attempts
WHERE id IN (
    SELECT id
    FROM delivery_attempts
    WHERE created_at < NOW() - INTERVAL '30 days'
    LIMIT 1000
);

-- name: CreateTenant :one
INSERT INTO tenants (name, api_key_hash, monthly_event_quota)
VALUES ($1, $2, $3)
RETURNING id, name, monthly_event_quota, is_active, created_at;

-- name: CreateRoute :one
INSERT INTO routes (
    tenant_id,
    route_slug,
    provider_type,
    signing_secret_enc,
    outgoing_secret_enc,
    target_url,
    target_headers_enc,
    rate_limit_per_sec,
    max_retries,
    is_active
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE)
RETURNING id, tenant_id, route_slug, provider_type, target_url, rate_limit_per_sec, max_retries, is_active, created_at, updated_at;

-- name: ListRoutesByTenant :many
SELECT id, tenant_id, route_slug, provider_type, target_url, rate_limit_per_sec, max_retries, is_active, created_at, updated_at
FROM routes
WHERE tenant_id = $1
ORDER BY id DESC;

-- name: GetRouteByID :one
SELECT id, tenant_id, route_slug, provider_type, signing_secret_enc, outgoing_secret_enc, target_url, target_headers_enc, rate_limit_per_sec, max_retries, is_active, created_at, updated_at
FROM routes
WHERE id = $1
LIMIT 1;

-- name: UpdateRoute :one
UPDATE routes
SET provider_type = $2,
    signing_secret_enc = $3,
    outgoing_secret_enc = $4,
    target_url = $5,
    target_headers_enc = $6,
    rate_limit_per_sec = $7,
    max_retries = $8,
    is_active = $9,
    updated_at = NOW()
WHERE id = $1
RETURNING id, tenant_id, route_slug, provider_type, target_url, rate_limit_per_sec, max_retries, is_active, created_at, updated_at;

-- name: DeleteRoute :one
DELETE FROM routes
WHERE id = $1
RETURNING route_slug;

-- name: ListDLQEvents :many
SELECT id, original_outbox_id, tenant_id, route_id, event_id, event_type, error_reason, failed_at
FROM dead_letter_queue
WHERE ($1::bigint = 0 OR tenant_id = $1)
  AND ($2::bigint = 0 OR route_id = $2)
ORDER BY id DESC
LIMIT $3;

-- name: ListTenants :many
SELECT id, name, monthly_event_quota, is_active, created_at
FROM tenants
ORDER BY id DESC
LIMIT 100;

-- name: ListDeliveryAttempts :many
SELECT
    id,
    tenant_id,
    route_id,
    outbox_event_id,
    event_id,
    attempt_number,
    http_status,
    duration_ms,
    error_summary,
    response_body_snippet,
    created_at
FROM delivery_attempts
WHERE ($1::bigint = 0 OR tenant_id = $1)
  AND ($2::bigint = 0 OR route_id = $2)
  AND ($3::text = '' OR event_id = $3)
ORDER BY id DESC
LIMIT $4;

-- name: GetActiveTenantByAPIKeyHash :one
SELECT id, name, monthly_event_quota, is_active
FROM tenants
WHERE api_key_hash = $1
  AND is_active = TRUE
LIMIT 1;

-- name: GetTenantByID :one
SELECT id, name, monthly_event_quota, is_active, created_at
FROM tenants
WHERE id = $1
LIMIT 1;

-- name: UpdateTenant :one
UPDATE tenants
SET monthly_event_quota = $2,
    is_active = $3,
    updated_at = NOW()
WHERE id = $1
RETURNING id, name, monthly_event_quota, is_active, created_at;

-- name: UpdateTenantAPIKeyHash :one
UPDATE tenants
SET api_key_hash = $2,
    updated_at = NOW()
WHERE id = $1
RETURNING id, name, monthly_event_quota, is_active, created_at;