package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

var (
	ErrUnsupportedProvider = errors.New("desteklenmeyen provider_type")
	ErrMissingSignature    = errors.New("imza header'ı veya alanı eksik")
	ErrInvalidSignature    = errors.New("imza doğrulaması başarısız")
	ErrExpiredTimestamp    = errors.New("webhook zaman damgası tolerans süresini aştı")
)

// Provider, her webhook sağlayıcısı için imza doğrulama, metadata çıkarımı ve ACK yanıtını yönetir.
type Provider interface {
	Verify(r *http.Request, body []byte, secret string) error
	ExtractMetadata(r *http.Request, body []byte) (eventID string, eventType string)
	WriteAck(w http.ResponseWriter, duplicate bool)
}

var registry = map[string]Provider{
	"none":         &NoneProvider{},
	"generic_hmac": &GenericHMACProvider{},
	"stripe":       &StripeProvider{},
	"shopify":      &ShopifyProvider{},
	"iyzico":       &IyzicoProvider{},
	"paytr":        &PayTRProvider{},
}

func Get(providerType string) (Provider, error) {
	p, ok := registry[strings.ToLower(strings.TrimSpace(providerType))]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedProvider, providerType)
	}
	return p, nil
}

// SignOutgoing, Worker'ın hedef ERP'ye gönderdiği payload'ı HMAC-SHA256 ile imzalar.
// Format: HMAC-SHA256(secret, "<unix_timestamp>.<raw_body>") -> "v1=<hex>"
func SignOutgoing(payload []byte, secret string, timestamp int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(payload)
	return "v1=" + hex.EncodeToString(mac.Sum(nil))
}

func writeJSONAck(w http.ResponseWriter, duplicate bool) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if duplicate {
		_, _ = w.Write([]byte(`{"status":"duplicate","message":"Bu event daha önce işlenmiş"}`))
		return
	}
	_, _ = w.Write([]byte(`{"status":"accepted"}`))
}
