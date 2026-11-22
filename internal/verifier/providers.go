package verifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// -----------------------------------------------------------------------------
// 1. NONE (Test ve iç ağlar için doğrulamasız)
// -----------------------------------------------------------------------------
type NoneProvider struct{}

func (p *NoneProvider) Verify(_ *http.Request, _ []byte, _ string) error { return nil }
func (p *NoneProvider) ExtractMetadata(r *http.Request, body []byte) (string, string) {
	return extractGenericMetadata(r, body)
}
func (p *NoneProvider) WriteAck(w http.ResponseWriter, duplicate bool) {
	writeJSONAck(w, duplicate)
}

// -----------------------------------------------------------------------------
// 2. GENERIC HMAC-SHA256 (GitHub, Trendyol veya özel entegrasyonlar)
// Header: X-Webhook-Signature veya X-Hub-Signature-256 ("sha256=<hex>" veya "<hex>")
// -----------------------------------------------------------------------------
type GenericHMACProvider struct{}

func (p *GenericHMACProvider) Verify(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrInvalidSignature
	}
	sigHeader := firstNonEmpty(
		r.Header.Get("X-Webhook-Signature"),
		r.Header.Get("X-Hub-Signature-256"),
	)
	if sigHeader == "" {
		return ErrMissingSignature
	}

	sigHex := strings.TrimPrefix(strings.TrimSpace(sigHeader), "sha256=")
	provided, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, provided) {
		return ErrInvalidSignature
	}
	return nil
}

func (p *GenericHMACProvider) ExtractMetadata(r *http.Request, body []byte) (string, string) {
	return extractGenericMetadata(r, body)
}

func (p *GenericHMACProvider) WriteAck(w http.ResponseWriter, duplicate bool) {
	writeJSONAck(w, duplicate)
}

// -----------------------------------------------------------------------------
// 3. STRIPE (Stripe-Signature: t=<ts>,v1=<hex>) + 5 dk Replay Koruması
// -----------------------------------------------------------------------------
type StripeProvider struct{}

func (p *StripeProvider) Verify(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrInvalidSignature
	}
	header := r.Header.Get("Stripe-Signature")
	if header == "" {
		return ErrMissingSignature
	}

	var timestamp string
	var signatures []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return ErrInvalidSignature
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return ErrInvalidSignature
	}
	// 5 dakikalık replay attack toleransı
	if math.Abs(float64(time.Now().Unix()-ts)) > 300 {
		return ErrExpiredTimestamp
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := mac.Sum(nil)

	for _, sig := range signatures {
		provided, err := hex.DecodeString(sig)
		if err == nil && hmac.Equal(expected, provided) {
			return nil
		}
	}
	return ErrInvalidSignature
}

func (p *StripeProvider) ExtractMetadata(r *http.Request, body []byte) (string, string) {
	return extractGenericMetadata(r, body)
}

func (p *StripeProvider) WriteAck(w http.ResponseWriter, duplicate bool) {
	writeJSONAck(w, duplicate)
}

// -----------------------------------------------------------------------------
// 4. SHOPIFY (X-Shopify-Hmac-Sha256: Base64 HMAC-SHA256)
// -----------------------------------------------------------------------------
type ShopifyProvider struct{}

func (p *ShopifyProvider) Verify(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrInvalidSignature
	}
	sigHeader := strings.TrimSpace(r.Header.Get("X-Shopify-Hmac-Sha256"))
	if sigHeader == "" {
		return ErrMissingSignature
	}

	provided, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return ErrInvalidSignature
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, provided) {
		return ErrInvalidSignature
	}
	return nil
}

func (p *ShopifyProvider) ExtractMetadata(r *http.Request, body []byte) (string, string) {
	return extractGenericMetadata(r, body)
}

func (p *ShopifyProvider) WriteAck(w http.ResponseWriter, duplicate bool) {
	writeJSONAck(w, duplicate)
}

// -----------------------------------------------------------------------------
// 5. IYZICO (X-IYZ-SIGNATURE-V3: Hex HMAC-SHA256)
// İmzalanan metin: secretKey + iyziEventType + iyziPaymentId + paymentConversationId + status
// -----------------------------------------------------------------------------
type IyzicoProvider struct{}

func (p *IyzicoProvider) Verify(r *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrInvalidSignature
	}
	sigHeader := strings.TrimSpace(r.Header.Get("X-IYZ-SIGNATURE-V3"))
	if sigHeader == "" {
		return ErrMissingSignature
	}

	provided, err := hex.DecodeString(sigHeader)
	if err != nil {
		return ErrInvalidSignature
	}

	var payload struct {
		IyziEventType         string      `json:"iyziEventType"`
		IyziPaymentID         json.Number `json:"iyziPaymentId"`
		PaymentID             json.Number `json:"paymentId"`
		PaymentConversationID string      `json:"paymentConversationId"`
		Status                string      `json:"status"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&payload); err != nil {
		return ErrInvalidSignature
	}

	pid := payload.IyziPaymentID.String()
	if pid == "" {
		pid = payload.PaymentID.String()
	}
	dataToSign := secret + payload.IyziEventType + pid + payload.PaymentConversationID + payload.Status
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(dataToSign))
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, provided) {
		return ErrInvalidSignature
	}
	return nil
}

func (p *IyzicoProvider) ExtractMetadata(r *http.Request, body []byte) (string, string) {
	return extractGenericMetadata(r, body)
}

func (p *IyzicoProvider) WriteAck(w http.ResponseWriter, duplicate bool) {
	writeJSONAck(w, duplicate)
}

// -----------------------------------------------------------------------------
// 6. PAYTR (application/x-www-form-urlencoded + düz metin "OK" ACK zorunluluğu)
// signing_secret formatı: "<merchant_key>:<merchant_salt>"
// Formül: base64(HMAC-SHA256(merchant_oid + merchant_salt + status + total_amount, merchant_key))
// -----------------------------------------------------------------------------
type PayTRProvider struct{}

func (p *PayTRProvider) Verify(_ *http.Request, body []byte, secret string) error {
	if secret == "" {
		return ErrInvalidSignature
	}
	parts := strings.SplitN(secret, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("%w: paytr secret 'merchant_key:merchant_salt' formatında olmalıdır", ErrInvalidSignature)
	}
	merchantKey, merchantSalt := parts[0], parts[1]

	values, err := url.ParseQuery(string(body))
	if err != nil {
		return ErrInvalidSignature
	}

	providedHash := values.Get("hash")
	if providedHash == "" {
		return ErrMissingSignature
	}

	provided, err := base64.StdEncoding.DecodeString(providedHash)
	if err != nil {
		return ErrInvalidSignature
	}

	dataToSign := values.Get("merchant_oid") + merchantSalt + values.Get("status") + values.Get("total_amount")
	mac := hmac.New(sha256.New, []byte(merchantKey))
	mac.Write([]byte(dataToSign))
	expected := mac.Sum(nil)

	if !hmac.Equal(expected, provided) {
		return ErrInvalidSignature
	}
	return nil
}

func (p *PayTRProvider) ExtractMetadata(_ *http.Request, body []byte) (string, string) {
	values, err := url.ParseQuery(string(body))
	if err == nil {
		oid := strings.TrimSpace(values.Get("merchant_oid"))
		status := strings.TrimSpace(values.Get("status"))
		if oid != "" {
			eventType := "paytr.payment"
			if status != "" {
				eventType = "paytr." + status
			}
			return oid, eventType
		}
	}
	sum := sha256.Sum256(body)
	return "sha256_" + hex.EncodeToString(sum[:]), "paytr.unknown"
}

// PayTR, ACK olarak mutlaka düz metin "OK" bekler; JSON dönersen bildirimi başarısız sayar.
func (p *PayTRProvider) WriteAck(w http.ResponseWriter, _ bool) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// -----------------------------------------------------------------------------
// Yardımcı Metadata Çıkarıcı
// -----------------------------------------------------------------------------
func extractGenericMetadata(r *http.Request, rawBody []byte) (string, string) {
	eventID := firstNonEmpty(
		r.Header.Get("X-Event-Id"),
		r.Header.Get("X-Shopify-Webhook-Id"),
		r.Header.Get("X-GitHub-Delivery"),
		r.Header.Get("X-Request-Id"),
	)
	eventType := firstNonEmpty(
		r.Header.Get("X-Event-Type"),
		r.Header.Get("X-Shopify-Topic"),
		r.Header.Get("X-GitHub-Event"),
	)

	if eventID == "" || eventType == "" {
		var generic map[string]any
		if json.Unmarshal(rawBody, &generic) == nil {
			if eventID == "" {
				eventID = firstStringField(generic, "event_id", "id", "iyziEventId", "iyziPaymentId", "merchant_oid")
			}
			if eventType == "" {
				eventType = firstStringField(generic, "event_type", "type", "iyziEventType", "event")
			}
		}
	}

	if eventID == "" {
		sum := sha256.Sum256(rawBody)
		eventID = "sha256_" + hex.EncodeToString(sum[:])
	}
	if eventType == "" {
		eventType = "unknown"
	}
	return eventID, eventType
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func firstStringField(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}
