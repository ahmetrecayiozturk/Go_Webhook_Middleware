CREATE TABLE IF NOT EXISTS monthly_event_usage (
    tenant_id BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    month VARCHAR(7) NOT NULL,
    used BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, month),
    CONSTRAINT monthly_event_usage_used_nonnegative CHECK (used >= 0)
);
CREATE INDEX IF NOT EXISTS idx_routes_tenant_id ON routes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dlq_tenant_route ON dead_letter_queue(tenant_id, route_id, failed_at DESC);
CREATE INDEX IF NOT EXISTS idx_outbox_pending_ready ON outbox_events(created_at ASC) WHERE status = 'PENDING';
CREATE INDEX IF NOT EXISTS idx_outbox_completed_retention ON outbox_events(updated_at ASC) WHERE status = 'COMPLETED';
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_route_event ON delivery_attempts(route_id, event_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_retention ON delivery_attempts(created_at ASC);
