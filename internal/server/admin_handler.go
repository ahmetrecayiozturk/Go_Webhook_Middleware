package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gowebhookmiddleware/internal/repository/postgres/sqlc_gen"
	"gowebhookmiddleware/internal/verifier"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// -----------------------------------------------------------------------------
// 1. TENANT OLUŞTURMA & LİSTELEME (Sadece Süper Admin)
// -----------------------------------------------------------------------------
type CreateTenantRequest struct {
	Name              string `json:"name" validate:"required,min=2,max=255"`
	MonthlyEventQuota int64  `json:"monthly_event_quota"`
}

type UpdateTenantRequest struct {
	MonthlyEventQuota *int64 `json:"monthly_event_quota"`
	IsActive          *bool  `json:"is_active"`
}

const maxAllowedRetries = 10

func isValidHTTPURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(u.Scheme)
	return (scheme == "http" || scheme == "https") && u.Host != ""
}

func (h *WebhookHandler) HandleCreateTenant(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req CreateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz JSON formatı")
		return
	}
	if err := h.validator.Struct(req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz tenant parametreleri")
		return
	}
	if req.MonthlyEventQuota <= 0 {
		req.MonthlyEventQuota = 100000
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		log.Printf("Kriptografik API key üretilemedi: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "API key üretilemedi")
		return
	}
	plainAPIKey := "whk_" + hex.EncodeToString(rawKey)
	hash := sha256.Sum256([]byte(plainAPIKey))

	tenant, err := h.sqlc.CreateTenant(r.Context(), sqlc_gen.CreateTenantParams{
		Name:              req.Name,
		ApiKeyHash:        hex.EncodeToString(hash[:]),
		MonthlyEventQuota: req.MonthlyEventQuota,
	})
	if err != nil {
		log.Printf("Tenant oluşturma hatası: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "Tenant oluşturulamadı")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"tenant":  tenant,
		"api_key": plainAPIKey,
	})
}

func (h *WebhookHandler) HandleListTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.sqlc.ListTenants(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Tenant listesi alınamadı")
		return
	}
	if tenants == nil {
		tenants = []sqlc_gen.ListTenantsRow{}
	}
	writeJSON(w, http.StatusOK, tenants)
}

func (h *WebhookHandler) HandleUpdateTenant(w http.ResponseWriter, r *http.Request) {
	tenantID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || tenantID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz tenant id")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req UpdateTenantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz JSON formatı")
		return
	}

	existing, err := h.sqlc.GetTenantByID(r.Context(), tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "Tenant bulunamadı")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Tenant sorgulanamadı")
		return
	}

	quota := existing.MonthlyEventQuota
	if req.MonthlyEventQuota != nil && *req.MonthlyEventQuota > 0 {
		quota = *req.MonthlyEventQuota
	}

	isActive := existing.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	updated, err := h.sqlc.UpdateTenant(r.Context(), sqlc_gen.UpdateTenantParams{
		ID:                tenantID,
		MonthlyEventQuota: quota,
		IsActive:          isActive,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Tenant güncellenemedi")
		return
	}

	// Tenant pasife alındıysa bağlı rotaların Redis cache'ini hemen temizle
	if !isActive {
		if routes, err := h.sqlc.ListRoutesByTenant(r.Context(), tenantID); err == nil {
			for _, rt := range routes {
				_ = h.routeCache.Invalidate(r.Context(), rt.RouteSlug)
			}
		}
	}

	writeJSON(w, http.StatusOK, updated)
}

func (h *WebhookHandler) HandleRotateTenantKey(w http.ResponseWriter, r *http.Request) {
	tenantID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || tenantID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz tenant id")
		return
	}

	rawKey := make([]byte, 32)
	if _, err := rand.Read(rawKey); err != nil {
		log.Printf("Kriptografik API key üretilemedi: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "API key üretilemedi")
		return
	}
	plainAPIKey := "whk_" + hex.EncodeToString(rawKey)
	hash := sha256.Sum256([]byte(plainAPIKey))

	updated, err := h.sqlc.UpdateTenantAPIKeyHash(r.Context(), sqlc_gen.UpdateTenantAPIKeyHashParams{
		ID:         tenantID,
		ApiKeyHash: hex.EncodeToString(hash[:]),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "Tenant bulunamadı")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "API key yenilenemedi")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"tenant":  updated,
		"api_key": plainAPIKey,
	})
}

// -----------------------------------------------------------------------------
// 2. ROUTE CRUD (Süper Admin veya İlgili Tenant API Key)
// -----------------------------------------------------------------------------
type CreateRouteRequest struct {
	TenantID        int64             `json:"tenant_id" validate:"required,gt=0"`
	RouteSlug       string            `json:"route_slug" validate:"required,min=3,max=128"`
	ProviderType    string            `json:"provider_type" validate:"required"`
	SigningSecret   string            `json:"signing_secret"`
	OutgoingSecret  string            `json:"outgoing_secret"`
	TargetURL       string            `json:"target_url" validate:"required,url"`
	TargetHeaders   map[string]string `json:"target_headers"`
	RateLimitPerSec int32             `json:"rate_limit_per_sec"`
	MaxRetries      int32             `json:"max_retries"`
}

func (h *WebhookHandler) HandleCreateRoute(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var req CreateRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz JSON formatı")
		return
	}

	// Tenant kendi anahtarıyla istek atıyorsa tenant_id'yi zorla kendi ID'sine sabitle
	auth := getAuthInfo(r.Context())
	if !auth.IsAdmin {
		req.TenantID = auth.TenantID
	}

	if err := h.validator.Struct(req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Eksik veya geçersiz route alanları")
		return
	}
	if _, err := verifier.Get(req.ProviderType); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !isValidHTTPURL(req.TargetURL) {
		writeJSONError(w, http.StatusBadRequest, "target_url yalnızca http veya https şeması içerebilir")
		return
	}
	if req.MaxRetries > maxAllowedRetries {
		writeJSONError(w, http.StatusBadRequest, "max_retries en fazla 10 olabilir")
		return
	}

	if req.RateLimitPerSec <= 0 {
		req.RateLimitPerSec = 100
	}
	if req.MaxRetries <= 0 {
		req.MaxRetries = 3
	}

	signingEnc, err := h.cipher.Encrypt(req.SigningSecret)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Secret şifrelenemedi")
		return
	}
	outgoingEnc, err := h.cipher.Encrypt(req.OutgoingSecret)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Outgoing secret şifrelenemedi")
		return
	}

	var headersEnc string
	if len(req.TargetHeaders) > 0 {
		b, _ := json.Marshal(req.TargetHeaders)
		headersEnc, err = h.cipher.Encrypt(string(b))
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Target headers şifrelenemedi")
			return
		}
	}

	route, err := h.sqlc.CreateRoute(r.Context(), sqlc_gen.CreateRouteParams{
		TenantID:          req.TenantID,
		RouteSlug:         req.RouteSlug,
		ProviderType:      req.ProviderType,
		SigningSecretEnc:  signingEnc,
		OutgoingSecretEnc: outgoingEnc,
		TargetUrl:         req.TargetURL,
		TargetHeadersEnc:  headersEnc,
		RateLimitPerSec:   req.RateLimitPerSec,
		MaxRetries:        req.MaxRetries,
	})
	if err != nil {
		log.Printf("Route oluşturma hatası: %v", err)
		writeJSONError(w, http.StatusConflict, "Route oluşturulamadı (slug zaten kullanımda olabilir)")
		return
	}

	writeJSON(w, http.StatusCreated, route)
}

func (h *WebhookHandler) HandleListRoutes(w http.ResponseWriter, r *http.Request) {
	auth := getAuthInfo(r.Context())
	tenantID, err := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
	if !auth.IsAdmin {
		tenantID = auth.TenantID
		err = nil
	}
	if err != nil || tenantID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Geçerli tenant_id query parametresi zorunludur")
		return
	}

	routes, err := h.sqlc.ListRoutesByTenant(r.Context(), tenantID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Route listesi alınamadı")
		return
	}
	if routes == nil {
		routes = []sqlc_gen.ListRoutesByTenantRow{}
	}
	writeJSON(w, http.StatusOK, routes)
}

type UpdateRouteRequest struct {
	ProviderType    string            `json:"provider_type" validate:"required"`
	SigningSecret   *string           `json:"signing_secret"`
	OutgoingSecret  *string           `json:"outgoing_secret"`
	TargetURL       string            `json:"target_url" validate:"required,url"`
	TargetHeaders   map[string]string `json:"target_headers"`
	RateLimitPerSec int32             `json:"rate_limit_per_sec"`
	MaxRetries      int32             `json:"max_retries"`
	IsActive        *bool             `json:"is_active"`
}

func (h *WebhookHandler) HandleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	routeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || routeID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz route id")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req UpdateRouteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz JSON formatı")
		return
	}
	if err := h.validator.Struct(req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Eksik veya geçersiz alanlar")
		return
	}
	if _, err := verifier.Get(req.ProviderType); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !isValidHTTPURL(req.TargetURL) {
		writeJSONError(w, http.StatusBadRequest, "target_url yalnızca http veya https şeması içerebilir")
		return
	}
	if req.MaxRetries > maxAllowedRetries {
		writeJSONError(w, http.StatusBadRequest, "max_retries en fazla 10 olabilir")
		return
	}

	existing, err := h.sqlc.GetRouteByID(r.Context(), routeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "Route bulunamadı")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Route sorgulanamadı")
		return
	}

	// IDOR koruması: Tenant sadece kendi route'unu güncelleyebilir
	auth := getAuthInfo(r.Context())
	if !auth.IsAdmin && existing.TenantID != auth.TenantID {
		writeJSONError(w, http.StatusForbidden, "Bu route üzerinde yetkiniz yok")
		return
	}

	signingEnc := existing.SigningSecretEnc
	if req.SigningSecret != nil {
		signingEnc, err = h.cipher.Encrypt(*req.SigningSecret)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Secret şifrelenemedi")
			return
		}
	}

	outgoingEnc := existing.OutgoingSecretEnc
	if req.OutgoingSecret != nil {
		outgoingEnc, err = h.cipher.Encrypt(*req.OutgoingSecret)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Outgoing secret şifrelenemedi")
			return
		}
	}

	headersEnc := existing.TargetHeadersEnc
	if req.TargetHeaders != nil {
		b, _ := json.Marshal(req.TargetHeaders)
		headersEnc, err = h.cipher.Encrypt(string(b))
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "Target headers şifrelenemedi")
			return
		}
	}

	rateLimit := req.RateLimitPerSec
	if rateLimit <= 0 {
		rateLimit = existing.RateLimitPerSec
	}

	maxRetries := req.MaxRetries
	if maxRetries <= 0 {
		maxRetries = existing.MaxRetries
	}

	isActive := existing.IsActive
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	updated, err := h.sqlc.UpdateRoute(r.Context(), sqlc_gen.UpdateRouteParams{
		ID:                routeID,
		ProviderType:      req.ProviderType,
		SigningSecretEnc:  signingEnc,
		OutgoingSecretEnc: outgoingEnc,
		TargetUrl:         req.TargetURL,
		TargetHeadersEnc:  headersEnc,
		RateLimitPerSec:   rateLimit,
		MaxRetries:        maxRetries,
		IsActive:          isActive,
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Route güncellenemedi")
		return
	}

	_ = h.routeCache.Invalidate(r.Context(), existing.RouteSlug)
	writeJSON(w, http.StatusOK, updated)
}

func (h *WebhookHandler) HandleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	routeID, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || routeID <= 0 {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz route id")
		return
	}

	// IDOR koruması: Silmeden önce sahiplik kontrolü
	existing, err := h.sqlc.GetRouteByID(r.Context(), routeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSONError(w, http.StatusNotFound, "Route bulunamadı")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Route sorgulanamadı")
		return
	}

	auth := getAuthInfo(r.Context())
	if !auth.IsAdmin && existing.TenantID != auth.TenantID {
		writeJSONError(w, http.StatusForbidden, "Bu route üzerinde yetkiniz yok")
		return
	}

	slug, err := h.sqlc.DeleteRoute(r.Context(), routeID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Route silinemedi")
		return
	}

	_ = h.routeCache.Invalidate(r.Context(), slug)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted", "route_slug": slug})
}

// -----------------------------------------------------------------------------
// 3. FİLTRELİ DLQ, DELIVERY ATTEMPTS VE REPLAY
// -----------------------------------------------------------------------------
func (h *WebhookHandler) HandleListDLQ(w http.ResponseWriter, r *http.Request) {
	auth := getAuthInfo(r.Context())
	tenantID, _ := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
	if !auth.IsAdmin {
		tenantID = auth.TenantID
	}

	routeID, _ := strconv.ParseInt(r.URL.Query().Get("route_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	items, err := h.sqlc.ListDLQEvents(r.Context(), sqlc_gen.ListDLQEventsParams{
		Column1: tenantID,
		Column2: routeID,
		Limit:   int32(limit),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "DLQ listesi alınamadı")
		return
	}
	if items == nil {
		items = []sqlc_gen.ListDLQEventsRow{}
	}
	writeJSON(w, http.StatusOK, items)
}

type ReplayDLQRequest struct {
	DLQIDs []int64 `json:"dlq_ids" validate:"required,min=1"`
}

func (h *WebhookHandler) HandleReplayDLQ(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)

	var payload ReplayDLQRequest
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "Payload çok büyük (max 1MB)")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "Geçersiz JSON formatı")
		return
	}
	if err := h.validator.Struct(payload); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Geçersiz ya da boş payload")
		return
	}

	auth := getAuthInfo(r.Context())
	tenantFilter := int64(0)
	if !auth.IsAdmin {
		tenantFilter = auth.TenantID
	}

	replayed, err := h.sqlc.ReplayDLQEvents(r.Context(), sqlc_gen.ReplayDLQEventsParams{
		DlqIds:   payload.DLQIDs,
		TenantID: tenantFilter,
	})
	if err != nil {
		log.Printf("Error replaying DLQ events: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "DLQ eventleri tekrar oynatılamadı")
		return
	}
	if replayed == nil {
		replayed = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "success",
		"replayed_count":  len(replayed),
		"replayed_events": replayed,
	})
}

func (h *WebhookHandler) HandleListDeliveryAttempts(w http.ResponseWriter, r *http.Request) {
	auth := getAuthInfo(r.Context())
	tenantID, _ := strconv.ParseInt(r.URL.Query().Get("tenant_id"), 10, 64)
	if !auth.IsAdmin {
		tenantID = auth.TenantID
	}

	routeID, _ := strconv.ParseInt(r.URL.Query().Get("route_id"), 10, 64)
	eventID := r.URL.Query().Get("event_id")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	items, err := h.sqlc.ListDeliveryAttempts(r.Context(), sqlc_gen.ListDeliveryAttemptsParams{
		Column1: tenantID,
		Column2: routeID,
		Column3: eventID,
		Limit:   int32(limit),
	})
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "Teslimat denemeleri alınamadı")
		return
	}
	if items == nil {
		items = []sqlc_gen.DeliveryAttempt{}
	}
	writeJSON(w, http.StatusOK, items)
}

func writeJSON(w http.ResponseWriter, statusCode int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(v)
}
