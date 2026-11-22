package server

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"gowebhookmiddleware/internal/repository/postgres/sqlc_gen"
	"net/http"
)

type authContextKey struct{}

type AuthInfo struct {
	IsAdmin  bool
	TenantID int64
}

func getAuthInfo(ctx context.Context) AuthInfo {
	if v, ok := ctx.Value(authContextKey{}).(AuthInfo); ok {
		return v
	}
	return AuthInfo{}
}

func RequiredAPIKey(expectedKey string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providedKey := r.Header.Get("X-API-KEY")
		if providedKey == "" {
			writeJSONError(w, http.StatusUnauthorized, "API key is required")
			return
		}
		if len(expectedKey) != len(providedKey) || subtle.ConstantTimeCompare([]byte(expectedKey), []byte(providedKey)) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "Invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), authContextKey{}, AuthInfo{IsAdmin: true})
		next(w, r.WithContext(ctx))
	}
}

func RequireAdminOrTenantKey(adminKey string, sqlc *sqlc_gen.Queries, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		providedKey := r.Header.Get("X-API-KEY")
		if providedKey == "" {
			writeJSONError(w, http.StatusUnauthorized, "API key is required")
			return
		}

		// 1. Önce Süper Admin anahtarını kontrol et
		if len(adminKey) == len(providedKey) && subtle.ConstantTimeCompare([]byte(adminKey), []byte(providedKey)) == 1 {
			ctx := context.WithValue(r.Context(), authContextKey{}, AuthInfo{IsAdmin: true})
			next(w, r.WithContext(ctx))
			return
		}

		// 2. Değilse SHA-256 hash ile Tenant API Key doğrula
		sum := sha256.Sum256([]byte(providedKey))
		tenant, err := sqlc.GetActiveTenantByAPIKeyHash(r.Context(), hex.EncodeToString(sum[:]))
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				writeJSONError(w, http.StatusUnauthorized, "Invalid API key")
				return
			}
			writeJSONError(w, http.StatusInternalServerError, "Kimlik doğrulama hatası")
			return
		}

		ctx := context.WithValue(r.Context(), authContextKey{}, AuthInfo{
			IsAdmin:  false,
			TenantID: tenant.ID,
		})
		next(w, r.WithContext(ctx))
	}
}
