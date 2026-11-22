package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"gowebhookmiddleware/internal/cache"
	"gowebhookmiddleware/internal/crypto"
	"gowebhookmiddleware/internal/metrics"
	"gowebhookmiddleware/internal/repository/postgres/sqlc_gen"
	"gowebhookmiddleware/internal/verifier"
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"
)

const maxWebhookBodySize = 1 << 20 // 1 MB

var quotaIncrScript = redis.NewScript(`
	local used = redis.call('INCR', KEYS[1])
	if redis.call('TTL', KEYS[1]) == -1 then
		redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
	end
	return used
`)

type WebhookHandler struct {
	db          *sql.DB
	sqlc        *sqlc_gen.Queries
	redisClient *redis.Client
	routeCache  *cache.RouteCache
	cipher      *crypto.Cipher
	limiter     *redis_rate.Limiter
	validator   *validator.Validate
}

func NewWebhookHandler(
	db *sql.DB,
	redisClient *redis.Client,
	sqlc *sqlc_gen.Queries,
	routeCache *cache.RouteCache,
	cipher *crypto.Cipher,
) *WebhookHandler {
	return &WebhookHandler{
		db:          db,
		redisClient: redisClient,
		sqlc:        sqlc,
		routeCache:  routeCache,
		cipher:      cipher,
		limiter:     redis_rate.NewLimiter(redisClient),
		validator:   validator.New(),
	}
}
func (h *WebhookHandler) HandleIngestWebhook(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	routeSlug := r.PathValue("route_slug")
	if routeSlug == "" {
		writeJSONError(w, http.StatusBadRequest, "route_slug eksik")
		return
	}

	// 1. Route ayarlarını al
	routeCfg, err := h.routeCache.GetBySlug(ctx, routeSlug)
	if err != nil {
		if errors.Is(err, cache.ErrRouteNotFound) {
			metrics.WebhooksReceivedTotal.WithLabelValues("unknown", "not_found").Inc()
			writeJSONError(w, http.StatusNotFound, "Route bulunamadı veya pasif")
			return
		}
		log.Printf("Route yüklenirken hata (%s): %v", routeSlug, err)
		metrics.WebhooksReceivedTotal.WithLabelValues("unknown", "error").Inc()
		writeJSONError(w, http.StatusInternalServerError, "Sunucu hatası")
		return
	}

	// 2. Route bazlı Rate Limit
	if routeCfg.RateLimitPerSec > 0 {
		rateKey := fmt.Sprintf("rate_limit:t:%d:r:%d", routeCfg.TenantID, routeCfg.ID)
		res, err := h.limiter.Allow(ctx, rateKey, redis_rate.PerSecond(routeCfg.RateLimitPerSec))
		if err == nil {
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))
			if res.Allowed == 0 {
				metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "rate_limited").Inc()
				retryAfter := int(math.Ceil(res.RetryAfter.Seconds()))
				if retryAfter < 1 {
					retryAfter = 1
				}
				w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
				writeJSONError(w, http.StatusTooManyRequests, "Too Many Requests: Route rate limit aşıldı")
				return
			}
		}
	}

	// 3. Ham body'yi oku (max 1MB)
	r.Body = http.MaxBytesReader(w, r.Body, maxWebhookBodySize)
	rawBody, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "invalid").Inc()
		if errors.As(err, &maxBytesErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "Payload çok büyük (max 1MB)")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "Body okunamadı")
		return
	}
	if len(rawBody) == 0 {
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "invalid").Inc()
		writeJSONError(w, http.StatusBadRequest, "Boş payload gönderilemez")
		return
	}

	// 4. Sağlayıcıyı bul ve imzayı doğrula
	provider, err := verifier.Get(routeCfg.ProviderType)
	if err != nil {
		log.Printf("Geçersiz provider_type (%s): %v", routeCfg.ProviderType, err)
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "error").Inc()
		writeJSONError(w, http.StatusInternalServerError, "Route yapılandırma hatası")
		return
	}

	signingSecret, err := h.cipher.Decrypt(routeCfg.SigningSecretEnc)
	if err != nil {
		log.Printf("Signing secret çözülemedi (route=%s): %v", routeSlug, err)
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "error").Inc()
		writeJSONError(w, http.StatusInternalServerError, "Route yapılandırma hatası")
		return
	}

	if err := provider.Verify(r, rawBody, signingSecret); err != nil {
		log.Printf("İmza doğrulama başarısız (route=%s, provider=%s): %v", routeSlug, routeCfg.ProviderType, err)
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "invalid_signature").Inc()
		writeJSONError(w, http.StatusUnauthorized, "Geçersiz webhook imzası")
		return
	}

	// 5. Sağlayıcıya özel EventID ve EventType çıkarımı
	eventID, eventType := provider.ExtractMetadata(r, rawBody)

	// 6. Tenant + Route izole Idempotency (Redis kesintisinde PostgreSQL ON CONFLICT fallback)
	idempotencyKey := fmt.Sprintf("webhook:idempotency:t:%d:r:%d:%s", routeCfg.TenantID, routeCfg.ID, eventID)
	redisIdemOK := false
	isSet, err := h.redisClient.SetNX(ctx, idempotencyKey, "accepted", 24*time.Hour).Result()
	if err != nil {
		log.Printf("Redis idempotency hatası (PostgreSQL fallback): %v", err)
	} else {
		redisIdemOK = true
		if !isSet {
			metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "duplicate").Inc()
			provider.WriteAck(w, true)
			return
		}
	}
	// 6.5. Aylık Tenant Kota Kontrolü (Duplicate olmayan gerçek event'ler sayılır)
	var quotaKey string
	if routeCfg.MonthlyEventQuota > 0 {
		quotaKey = fmt.Sprintf("quota:t:%d:%s", routeCfg.TenantID, time.Now().UTC().Format("2006-01"))
		const quotaTTLSeconds = int64(35 * 24 * 60 * 60) // 35 gün
		used, qErr := quotaIncrScript.Run(ctx, h.redisClient, []string{quotaKey}, quotaTTLSeconds).Int64()
		if qErr == nil {
			w.Header().Set("X-Quota-Limit", strconv.FormatInt(routeCfg.MonthlyEventQuota, 10))
			w.Header().Set("X-Quota-Used", strconv.FormatInt(used, 10))

			if used > routeCfg.MonthlyEventQuota {
				_ = h.redisClient.Decr(ctx, quotaKey).Err()
				if redisIdemOK {
					_ = h.redisClient.Del(ctx, idempotencyKey).Err()
				}
				metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "quota_exceeded").Inc()
				writeJSONError(w, http.StatusTooManyRequests, "Aylık event kotası aşıldı")
				return
			}
		}
	}

	// 7. Outbox'a kaydet
	headersJSON := extractSafeHeaders(r)
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/json"
	}

	rowsAffected, err := h.sqlc.InsertOutboxEvent(ctx, sqlc_gen.InsertOutboxEventParams{
		TenantID:    routeCfg.TenantID,
		RouteID:     routeCfg.ID,
		EventID:     eventID,
		EventType:   eventType,
		ContentType: contentType,
		Headers:     headersJSON,
		Payload:     rawBody,
	})
	if err != nil {
		delCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if redisIdemOK {
			_ = h.redisClient.Del(delCtx, idempotencyKey).Err()
		}
		if quotaKey != "" {
			_ = h.redisClient.Decr(delCtx, quotaKey).Err()
		}

		log.Printf("PostgreSQL outbox insert hatası (route=%s): %v", routeSlug, err)
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "error").Inc()
		writeJSONError(w, http.StatusInternalServerError, "Sunucu hatası")
		return
	}
	if rowsAffected == 0 {
		if quotaKey != "" {
			_ = h.redisClient.Decr(ctx, quotaKey).Err()
		}
		metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "duplicate").Inc()
		provider.WriteAck(w, true)
		return
	}

	metrics.WebhooksReceivedTotal.WithLabelValues(routeCfg.RouteSlug, "accepted").Inc()
	provider.WriteAck(w, false)
}
func extractSafeHeaders(r *http.Request) json.RawMessage {
	keep := map[string]string{}
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "cookie" || lk == "host" || lk == "content-length" {
			continue
		}
		if len(vals) > 0 {
			keep[k] = vals[0]
		}
	}
	b, err := json.Marshal(keep)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func (h *WebhookHandler) HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := h.db.PingContext(ctx); err != nil {
		http.Error(w, "PostgreSQL erişilemiyor", http.StatusServiceUnavailable)
		return
	}
	if err := h.redisClient.Ping(ctx).Err(); err != nil {
		http.Error(w, "Redis erişilemiyor", http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func writeJSONError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "error",
		"error":  message,
	})
}
