-- Multi-tenant yapı için müşteri (tenant) tablosu
CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    api_key_hash VARCHAR(64) NOT NULL UNIQUE, -- SHA-256 hex hash (düz metin saklanmaz)
    monthly_event_quota BIGINT NOT NULL DEFAULT 100000,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Dinamik webhook rotaları
CREATE TABLE IF NOT EXISTS routes (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_slug VARCHAR(128) NOT NULL UNIQUE, -- Örn: tr_shop_iyzico_01
    provider_type VARCHAR(64) NOT NULL DEFAULT 'none', -- none, generic_hmac, stripe, shopify, iyzico, paytr
    signing_secret_enc TEXT NOT NULL DEFAULT '',       -- AES-256-GCM şifreli (gelen imza doğrulama)
    outgoing_secret_enc TEXT NOT NULL DEFAULT '',      -- AES-256-GCM şifreli (ERP'ye çıkış imzası)
    target_url TEXT NOT NULL,
    target_headers_enc TEXT NOT NULL DEFAULT '',       -- AES-256-GCM şifreli JSON map (örn: {"Authorization": "Bearer ..."})
    rate_limit_per_sec INT NOT NULL DEFAULT 100,
    max_retries INT NOT NULL DEFAULT 3,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_routes_tenant_id ON routes(tenant_id);

-- Outbox tablosu: Raw payload (BYTEA) + header'lar + tenant/route izolasyonu
CREATE TABLE IF NOT EXISTS outbox_events (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    event_id VARCHAR(255) NOT NULL,
    event_type VARCHAR(255) NOT NULL DEFAULT 'unknown',
    content_type VARCHAR(128) NOT NULL DEFAULT 'application/json',
    headers JSONB NOT NULL DEFAULT '{}'::jsonb,
    payload BYTEA NOT NULL, -- Ham gövde (JSON, form-urlencoded vb. bozulmadan saklanır)
    status VARCHAR(32) NOT NULL DEFAULT 'PENDING', -- PENDING, PROCESSING, COMPLETED
    retry_count INT NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_outbox_route_event UNIQUE (route_id, event_id)
);

-- Dead Letter Queue tablosu
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

CREATE INDEX IF NOT EXISTS idx_dlq_tenant_route ON dead_letter_queue(tenant_id, route_id, failed_at DESC);

-- Faz 4: Sadece PENDING kayıtları tarayan Partial Index (Worker polling hızını sabit tutar)
CREATE INDEX IF NOT EXISTS idx_outbox_pending_ready
    ON outbox_events (created_at ASC)
    WHERE status = 'PENDING';

-- Faz 4: RetentionSweeper'ın 30 günden eski COMPLETED kayıtları full-scan yapmadan bulması için
CREATE INDEX IF NOT EXISTS idx_outbox_completed_retention
    ON outbox_events (updated_at ASC)
    WHERE status = 'COMPLETED';

-- Faz 4: Her teslimat denemesinin HTTP kodu, süresi ve ilk 2KB yanıt özeti
CREATE TABLE IF NOT EXISTS delivery_attempts (
    id BIGSERIAL PRIMARY KEY,
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_id BIGINT NOT NULL REFERENCES routes(id) ON DELETE CASCADE,
    outbox_event_id BIGINT NOT NULL,
    event_id VARCHAR(255) NOT NULL,
    attempt_number INT NOT NULL DEFAULT 1,
    http_status INT NOT NULL DEFAULT 0, -- 0: network/DNS/timeout hatası
    duration_ms INT NOT NULL DEFAULT 0,
    error_summary TEXT NOT NULL DEFAULT '',
    response_body_snippet TEXT NOT NULL DEFAULT '', -- Max 2KB
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_delivery_attempts_route_event
    ON delivery_attempts (route_id, event_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_delivery_attempts_retention
    ON delivery_attempts (created_at ASC);