CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    api_key_hash VARCHAR(64) NOT NULL UNIQUE,
    monthly_event_quota BIGINT NOT NULL DEFAULT 100000,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS routes (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_slug VARCHAR(128) NOT NULL UNIQUE,
    provider_type VARCHAR(64) NOT NULL DEFAULT 'none',
    signing_secret_enc TEXT NOT NULL DEFAULT '',
    outgoing_secret_enc TEXT NOT NULL DEFAULT '',
    target_url TEXT NOT NULL,
    target_headers_enc TEXT NOT NULL DEFAULT '',
    rate_limit_per_sec INT NOT NULL DEFAULT 100,
    max_retries INT NOT NULL DEFAULT 3,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS outbox_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    event_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL DEFAULT 'unknown',
    content_type VARCHAR(128) NOT NULL DEFAULT 'application/json',
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload BYTEA NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING',
    retry_count INT NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_outbox_route_event UNIQUE (route_id, event_id)
);
CREATE TABLE IF NOT EXISTS dead_letter_queue (
    id BIGSERIAL PRIMARY KEY,
    original_outbox_id BIGINT,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    event_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL DEFAULT 'unknown',
    content_type VARCHAR(128) NOT NULL DEFAULT 'application/json',
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload BYTEA NOT NULL,
    error_reason TEXT,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS delivery_attempts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    outbox_event_id BIGINT NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    attempt_number INT NOT NULL DEFAULT 1,
    http_status INT NOT NULL DEFAULT 0,
    duration_ms INT NOT NULL DEFAULT 0,
    error_summary TEXT NOT NULL DEFAULT '',
    response_body_snippet TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
