package verifier

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"
)

func TestRegistryGet(t *testing.T) {
	valid := []string{"none", "generic_hmac", "stripe", "shopify", "iyzico", "paytr", " STRIPE "}
	for _, name := range valid {
		if _, err := Get(name); err != nil {
			t.Fatalf("Get(%q) beklenmeyen hata: %v", name, err)
		}
	}

	if _, err := Get("bilinmeyen"); !errors.Is(err, ErrUnsupportedProvider) {
		t.Fatalf("desteklenmeyen provider için ErrUnsupportedProvider bekleniyordu, gelen: %v", err)
	}
}

func TestGenericHMACProvider(t *testing.T) {
	p, _ := Get("generic_hmac")
	body := []byte(`{"event_id":"evt_1","event_type":"order.paid"}`)
	secret := "super_secret_key"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sigHex := hex.EncodeToString(mac.Sum(nil))

	t.Run("ValidWithPrefix", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Webhook-Signature", "sha256="+sigHex)
		if err := p.Verify(req, body, secret); err != nil {
			t.Fatalf("geçerli imza reddedildi: %v", err)
		}
	})

	t.Run("ValidGitHubHeader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Hub-Signature-256", "sha256="+sigHex)
		if err := p.Verify(req, body, secret); err != nil {
			t.Fatalf("X-Hub-Signature-256 reddedildi: %v", err)
		}
	})

	t.Run("MissingSignature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		if err := p.Verify(req, body, secret); !errors.Is(err, ErrMissingSignature) {
			t.Fatalf("ErrMissingSignature bekleniyordu, gelen: %v", err)
		}
	})

	t.Run("WrongSecretAndEmptySecret", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("X-Webhook-Signature", "sha256="+sigHex)
		if err := p.Verify(req, body, "yanlis"); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("yanlış secret için ErrInvalidSignature bekleniyordu, gelen: %v", err)
		}
		if err := p.Verify(req, body, ""); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("boş secret için ErrInvalidSignature bekleniyordu, gelen: %v", err)
		}
	})
}

func TestStripeProvider(t *testing.T) {
	p, _ := Get("stripe")
	body := []byte(`{"id":"evt_stripe_1","type":"payment_intent.succeeded"}`)
	secret := "whsec_test_123"

	makeSig := func(ts int64) string {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(strconv.FormatInt(ts, 10)))
		mac.Write([]byte("."))
		mac.Write(body)
		return fmt.Sprintf("t=%d,v1=%s", ts, hex.EncodeToString(mac.Sum(nil)))
	}

	t.Run("ValidSignature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Stripe-Signature", makeSig(time.Now().Unix()))
		if err := p.Verify(req, body, secret); err != nil {
			t.Fatalf("geçerli Stripe imzası reddedildi: %v", err)
		}
	})

	t.Run("ExpiredTimestampReplayAttack", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Stripe-Signature", makeSig(time.Now().Add(-10*time.Minute).Unix()))
		if err := p.Verify(req, body, secret); !errors.Is(err, ErrExpiredTimestamp) {
			t.Fatalf("eski timestamp için ErrExpiredTimestamp bekleniyordu, gelen: %v", err)
		}
	})

	t.Run("InvalidSignature", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", nil)
		req.Header.Set("Stripe-Signature", fmt.Sprintf("t=%d,v1=deadbeef", time.Now().Unix()))
		if err := p.Verify(req, body, secret); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("ErrInvalidSignature bekleniyordu, gelen: %v", err)
		}
	})
}

func TestShopifyProvider(t *testing.T) {
	p, _ := Get("shopify")
	body := []byte(`{"id":"order_99"}`)
	secret := "shopify_secret"

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	sigB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-Shopify-Hmac-Sha256", sigB64)
	req.Header.Set("X-Shopify-Webhook-Id", "sh_wh_123")
	req.Header.Set("X-Shopify-Topic", "orders/create")

	if err := p.Verify(req, body, secret); err != nil {
		t.Fatalf("geçerli Shopify imzası reddedildi: %v", err)
	}

	id, typ := p.ExtractMetadata(req, body)
	if id != "sh_wh_123" || typ != "orders/create" {
		t.Fatalf("Shopify metadata hatalı: id=%s type=%s", id, typ)
	}
}

func TestIyzicoProvider(t *testing.T) {
	p, _ := Get("iyzico")
	secret := "iyzi_secret_key"
	body := []byte(`{"iyziEventType":"API_AUTH","iyziPaymentId":"123456","paymentConversationId":"conv_99","status":"SUCCESS"}`)

	dataToSign := secret + "API_AUTH" + "123456" + "conv_99" + "SUCCESS"
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(dataToSign))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set("X-IYZ-SIGNATURE-V3", sigHex)

	if err := p.Verify(req, body, secret); err != nil {
		t.Fatalf("geçerli iyzico imzası reddedildi: %v", err)
	}

	if err := p.Verify(req, body, "yanlis_secret"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("yanlış iyzico secret reddedilmeliydi, gelen: %v", err)
	}
}

func TestPayTRProvider(t *testing.T) {
	p, _ := Get("paytr")
	merchantKey := "paytr_key"
	merchantSalt := "paytr_salt"
	secret := merchantKey + ":" + merchantSalt

	oid := "ORD12345"
	status := "success"
	totalAmount := "14990"

	mac := hmac.New(sha256.New, []byte(merchantKey))
	mac.Write([]byte(oid + merchantSalt + status + totalAmount))
	hashB64 := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	form := url.Values{}
	form.Set("merchant_oid", oid)
	form.Set("status", status)
	form.Set("total_amount", totalAmount)
	form.Set("hash", hashB64)
	body := []byte(form.Encode())

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	if err := p.Verify(req, body, secret); err != nil {
		t.Fatalf("geçerli PayTR imzası reddedildi: %v", err)
	}

	// Metadata kontrolü
	id, typ := p.ExtractMetadata(req, body)
	if id != oid || typ != "paytr.success" {
		t.Fatalf("PayTR metadata hatalı: id=%s type=%s", id, typ)
	}

	// PayTR düz metin "OK" ACK kontrolü
	rec := httptest.NewRecorder()
	p.WriteAck(rec, false)
	if rec.Code != http.StatusOK || rec.Body.String() != "OK" {
		t.Fatalf("PayTR ACK 'OK' olmalıydı, gelen: code=%d body=%q", rec.Code, rec.Body.String())
	}

	// Hatalı secret formatı kontrolü
	if err := p.Verify(req, body, "sadece_key_salt_yok"); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("hatalı PayTR secret formatı reddedilmeliydi, gelen: %v", err)
	}
}

func TestSignOutgoing(t *testing.T) {
	payload := []byte(`{"order_id":42}`)
	secret := "out_secret"
	ts := int64(1700000000)

	sig := SignOutgoing(payload, secret, ts)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("1700000000."))
	mac.Write(payload)
	expected := "v1=" + hex.EncodeToString(mac.Sum(nil))

	if sig != expected {
		t.Fatalf("SignOutgoing uyuşmadı. beklenen=%s gelen=%s", expected, sig)
	}
}
