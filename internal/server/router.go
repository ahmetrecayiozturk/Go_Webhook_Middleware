package server

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func NewRouter(handler *WebhookHandler, adminAPIKey string) http.Handler {
	mux := http.NewServeMux()

	// Public Ingest, Health, Metrics & Admin UI Shell
	mux.HandleFunc("POST /api/v1/ingest/{route_slug}", handler.HandleIngestWebhook)
	mux.HandleFunc("GET /api/v1/health", handler.HandleHealthCheck)
	mux.Handle("GET /metrics", promhttp.Handler())
	mux.HandleFunc("GET /admin", HandleAdminUI)

	// Control Plane API (X-API-KEY korumalı)

	// Sadece Süper Admin
	mux.HandleFunc("POST /api/v1/admin/tenants", RequiredAPIKey(adminAPIKey, handler.HandleCreateTenant))
	mux.HandleFunc("GET /api/v1/admin/tenants", RequiredAPIKey(adminAPIKey, handler.HandleListTenants))
	mux.HandleFunc("PATCH /api/v1/admin/tenants/{id}", RequiredAPIKey(adminAPIKey, handler.HandleUpdateTenant))
	mux.HandleFunc("POST /api/v1/admin/tenants/{id}/rotate-key", RequiredAPIKey(adminAPIKey, handler.HandleRotateTenantKey))

	// Süper Admin veya ilgili Tenant API Key (whk_...)
	mux.HandleFunc("POST /api/v1/admin/routes", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleCreateRoute))
	mux.HandleFunc("GET /api/v1/admin/routes", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleListRoutes))
	mux.HandleFunc("PUT /api/v1/admin/routes/{id}", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleUpdateRoute))
	mux.HandleFunc("DELETE /api/v1/admin/routes/{id}", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleDeleteRoute))
	mux.HandleFunc("GET /api/v1/admin/attempts", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleListDeliveryAttempts))
	mux.HandleFunc("GET /api/v1/admin/dlq", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleListDLQ))
	mux.HandleFunc("POST /api/v1/admin/replay-dlq", RequireAdminOrTenantKey(adminAPIKey, handler.sqlc, handler.HandleReplayDLQ))

	return mux
}
