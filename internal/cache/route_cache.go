package cache

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"gowebhookmiddleware/internal/repository/postgres/sqlc_gen"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

var ErrRouteNotFound = errors.New("route bulunamadı veya pasif")

const (
	routeCacheTTL       = 60 * time.Second
	routeCacheKeyPrefix = "route:cfg:"
)

type RouteConfig struct {
	ID                int64  `json:"id"`
	TenantID          int64  `json:"tenant_id"`
	RouteSlug         string `json:"route_slug"`
	ProviderType      string `json:"provider_type"`
	SigningSecretEnc  string `json:"signing_secret_enc"`
	OutgoingSecretEnc string `json:"outgoing_secret_enc"`
	TargetURL         string `json:"target_url"`
	TargetHeadersEnc  string `json:"target_headers_enc"`
	RateLimitPerSec   int    `json:"rate_limit_per_sec"`
	MaxRetries        int    `json:"max_retries"`
	MonthlyEventQuota int64  `json:"monthly_event_quota"`
}

type RouteCache struct {
	redis *redis.Client
	sqlc  *sqlc_gen.Queries
}

func NewRouteCache(redisClient *redis.Client, sqlc *sqlc_gen.Queries) *RouteCache {
	return &RouteCache{
		redis: redisClient,
		sqlc:  sqlc,
	}
}

func (rc *RouteCache) GetBySlug(ctx context.Context, slug string) (*RouteConfig, error) {
	key := routeCacheKeyPrefix + slug

	// 1. Önce Redis'e bak (Redis hatasında DB'ye fallback yap)
	cached, err := rc.redis.Get(ctx, key).Bytes()
	if err == nil {
		var cfg RouteConfig
		if unmarshalErr := json.Unmarshal(cached, &cfg); unmarshalErr == nil {
			return &cfg, nil
		}
	} else if !errors.Is(err, redis.Nil) {
		log.Printf("RouteCache: Redis okuma hatası (DB fallback): %v", err)
	}

	// 2. Cache miss -> PostgreSQL'den çek
	row, err := rc.sqlc.GetActiveRouteBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrRouteNotFound
		}
		return nil, fmt.Errorf("route DB sorgu hatası: %w", err)
	}

	cfg := &RouteConfig{
		ID:                row.ID,
		TenantID:          row.TenantID,
		RouteSlug:         row.RouteSlug,
		ProviderType:      row.ProviderType,
		SigningSecretEnc:  row.SigningSecretEnc,
		OutgoingSecretEnc: row.OutgoingSecretEnc,
		TargetURL:         row.TargetUrl,
		TargetHeadersEnc:  row.TargetHeadersEnc,
		RateLimitPerSec:   int(row.RateLimitPerSec),
		MaxRetries:        int(row.MaxRetries),
		MonthlyEventQuota: row.MonthlyEventQuota,
	}

	// 3. Redis'e 60s TTL ile yaz (hata olursa akışı bozma)
	if encoded, err := json.Marshal(cfg); err == nil {
		_ = rc.redis.Set(ctx, key, encoded, routeCacheTTL).Err()
	}

	return cfg, nil
}

// Invalidate, Control Plane'de route güncellendiğinde cache'i anında temizler.
func (rc *RouteCache) Invalidate(ctx context.Context, slug string) error {
	return rc.redis.Del(ctx, routeCacheKeyPrefix+slug).Err()
}
