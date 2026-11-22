package e2e

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	baseURL    = "http://127.0.0.1"
	mockAddr   = "0.0.0.0:9099" // demo-studio (9000) ile çakışmasın
	defaultDSN = "postgres://postgres:postgres@127.0.0.1:5432/webhook_db?sslmode=disable"
)

var (
	mockERPStatus     atomic.Int32
	mockFailNextCount atomic.Int32

	lastSigMu        sync.Mutex
	lastOutgoingSig  string
	lastOutgoingTS   string
	lastOutgoingBody []byte
)

func startProgrammableMockERP(t *testing.T) *http.Server {
	t.Helper()
	mockERPStatus.Store(http.StatusOK)
	mockFailNextCount.Store(0)

	mux := http.NewServeMux()
	mux.HandleFunc("/erp/webhook", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		lastSigMu.Lock()
		lastOutgoingSig = r.Header.Get("X-Webhook-Signature")
		lastOutgoingTS = r.Header.Get("X-Webhook-Timestamp")
		lastOutgoingBody = body
		lastSigMu.Unlock()

		if mockFailNextCount.Load() > 0 && mockFailNextCount.Add(-1) >= 0 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"simulated temporary 500 error"}`))
			return
		}

		status := int(mockERPStatus.Load())
		w.WriteHeader(status)
		if status >= 400 {
			_, _ = w.Write([]byte(`{"error":"simulated erp error"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{Addr: mockAddr, Handler: mux}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			t.Logf("Mock ERP kapandı: %v", err)
		}
	}()

	time.Sleep(200 * time.Millisecond)
	return srv
}
func loadEnvVar(t *testing.T, key, fallback string) string {
	t.Helper()
	if v := os.Getenv(key); v != "" {
		return v
	}
	data, err := os.ReadFile("../../.env")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, key+"=") {
				val := strings.TrimPrefix(line, key+"=")
				val = strings.Trim(strings.TrimSpace(val), `"'`)
				if val != "" {
					return val
				}
			}
		}
	}
	return fallback
}

func loadAdminKey(t *testing.T) string {
	t.Helper()
	key := loadEnvVar(t, "ADMIN_API_KEY", "")
	if key == "" {
		t.Fatal(".env içinde ADMIN_API_KEY bulunamadı")
	}
	return key
}

func connectDB(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("E2E_DATABASE_DSN")
	if dsn == "" {
		user := loadEnvVar(t, "POSTGRES_USER", "postgres")
		pass := loadEnvVar(t, "POSTGRES_PASSWORD", "postgres")
		dbName := loadEnvVar(t, "POSTGRES_DB", "webhook_db")
		port := loadEnvVar(t, "POSTGRES_PORT", "5432")
		dsn = fmt.Sprintf("postgres://%s:%s@127.0.0.1:%s/%s?sslmode=disable", user, pass, port, dbName)
	}
	conn, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("PostgreSQL bağlantısı başarısız (%s): %v", dsn, err)
	}
	return conn
}

func signGenericHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func verifyOutgoingSignature(body []byte, secret, ts, providedSig string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := "v1=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(providedSig))
}

func createTenantAndRoute(t *testing.T, adminKey, slug, inSecret, outSecret, targetURL string) (int64, int64) {
	t.Helper()

	// 1. Tenant oluştur
	tReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/tenants",
		strings.NewReader(`{"name":"E2E Test Tenant","monthly_event_quota":50000}`))
	tReq.Header.Set("Content-Type", "application/json")
	tReq.Header.Set("X-API-KEY", adminKey)

	tResp, err := http.DefaultClient.Do(tReq)
	if err != nil {
		t.Fatalf("Tenant oluşturma isteği hatası: %v", err)
	}
	defer tResp.Body.Close()
	if tResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(tResp.Body)
		t.Fatalf("Tenant oluşturulamadı (%d): %s", tResp.StatusCode, string(body))
	}

	var tRes struct {
		Tenant struct {
			ID int64 `json:"ID"`
		} `json:"tenant"`
	}
	_ = json.NewDecoder(tResp.Body).Decode(&tRes)
	tenantID := tRes.Tenant.ID

	// 2. Route oluştur
	routeBody, _ := json.Marshal(map[string]any{
		"tenant_id":          tenantID,
		"route_slug":         slug,
		"provider_type":      "generic_hmac",
		"signing_secret":     inSecret,
		"outgoing_secret":    outSecret,
		"target_url":         targetURL,
		"rate_limit_per_sec": 500,
		"max_retries":        3,
	})
	rReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/routes", bytes.NewReader(routeBody))
	rReq.Header.Set("Content-Type", "application/json")
	rReq.Header.Set("X-API-KEY", adminKey)

	rResp, err := http.DefaultClient.Do(rReq)
	if err != nil {
		t.Fatalf("Route oluşturma isteği hatası: %v", err)
	}
	defer rResp.Body.Close()
	if rResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(rResp.Body)
		t.Fatalf("Route oluşturulamadı (%d): %s", rResp.StatusCode, string(body))
	}

	var rRes struct {
		ID int64 `json:"ID"`
	}
	_ = json.NewDecoder(rResp.Body).Decode(&rRes)
	return tenantID, rRes.ID
}

func createTenantWithQuota(t *testing.T, adminKey, name string, quota int64) (int64, string) {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"monthly_event_quota":%d}`, name, quota)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", adminKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Tenant oluşturma isteği hatası: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Tenant oluşturulamadı (%d): %s", resp.StatusCode, string(b))
	}

	var res struct {
		Tenant struct {
			ID int64 `json:"ID"`
		} `json:"tenant"`
		APIKey string `json:"api_key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	if res.Tenant.ID == 0 || !strings.HasPrefix(res.APIKey, "whk_") {
		t.Fatalf("Geçersiz tenant yanıtı: id=%d key=%s", res.Tenant.ID, res.APIKey)
	}
	return res.Tenant.ID, res.APIKey
}

func createRouteWithKey(t *testing.T, apiKey string, tenantID int64, slug, inSecret, targetURL string) int64 {
	t.Helper()
	routeBody, _ := json.Marshal(map[string]any{
		"tenant_id":          tenantID,
		"route_slug":         slug,
		"provider_type":      "generic_hmac",
		"signing_secret":     inSecret,
		"target_url":         targetURL,
		"rate_limit_per_sec": 500,
		"max_retries":        3,
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/routes", bytes.NewReader(routeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Route oluşturma isteği hatası: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("Route oluşturulamadı (%d): %s", resp.StatusCode, string(b))
	}

	var res struct {
		ID int64 `json:"ID"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&res)
	return res.ID
}

func sendSignedWebhook(t *testing.T, slug, eventID, secret string) (int, map[string]any) {
	t.Helper()
	payload := map[string]any{
		"event_id":   eventID,
		"event_type": "order.created",
		"payload":    map[string]any{"order_id": 123, "amount": 99.5},
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/ingest/"+slug, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("X-Webhook-Signature", signGenericHMAC(body, secret))
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Webhook isteği başarısız: %v", err)
	}
	defer resp.Body.Close()

	var res map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res)
	return resp.StatusCode, res
}

func waitForCondition(timeout time.Duration, check func() bool) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return false
}

func TestWebhookMiddlewareE2E(t *testing.T) {
	mockSrv := startProgrammableMockERP(t)
	defer mockSrv.Shutdown(context.Background())

	db := connectDB(t)
	defer db.Close(context.Background())

	adminKey := loadAdminKey(t)
	targetURL := os.Getenv("MOCK_ERP_TARGET_URL")
	if targetURL == "" {
		targetURL = "http://host.docker.internal:9099/erp/webhook"
	}

	routeSlug := fmt.Sprintf("e2e_route_%d", time.Now().UnixNano())
	inSecret := "e2e_incoming_secret_123"
	outSecret := "e2e_outgoing_secret_456"

	tenantID, routeID := createTenantAndRoute(t, adminKey, routeSlug, inSecret, outSecret, targetURL)

	// SENARYO 1: Nginx /metrics Güvenlik Engeli
	t.Run("Security_MetricsBlockedByNginx", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/metrics")
		if err != nil {
			t.Fatalf("/metrics isteği hatası: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Beklenen 403 Forbidden, gelen: %d", resp.StatusCode)
		}
	})

	// SENARYO 2: Admin Endpoint Yetkisiz Erişim Engeli
	t.Run("Security_AdminAuthRejected", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/replay-dlq", strings.NewReader(`{"dlq_ids":[1]}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-KEY", "yanlis-anahtar")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("Admin isteği hatası: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Beklenen 401 Unauthorized, gelen: %d", resp.StatusCode)
		}
	})

	// SENARYO 3: Geçersiz HMAC İmzası Reddi (401)
	t.Run("Security_InvalidSignatureRejected", func(t *testing.T) {
		code, _ := sendSignedWebhook(t, routeSlug, fmt.Sprintf("e2e_badsig_%d", time.Now().UnixNano()), "yanlis_secret")
		if code != http.StatusUnauthorized {
			t.Fatalf("Geçersiz imzada beklenen 401 Unauthorized, gelen: %d", code)
		}
	})

	// SENARYO 4: Happy Path + Idempotency + Outgoing Signature + DeliveryAttempts
	t.Run("HappyPath_Idempotency_OutgoingSig", func(t *testing.T) {
		mockERPStatus.Store(http.StatusOK)
		eventID := fmt.Sprintf("e2e_happy_%d", time.Now().UnixNano())

		code1, res1 := sendSignedWebhook(t, routeSlug, eventID, inSecret)
		if code1 != http.StatusOK || res1["status"] != "accepted" {
			t.Fatalf("İlk istek accepted olmalıydı. Code: %d, Body: %v", code1, res1)
		}

		code2, res2 := sendSignedWebhook(t, routeSlug, eventID, inSecret)
		if code2 != http.StatusOK || res2["status"] != "duplicate" {
			t.Fatalf("İkinci istek duplicate olmalıydı. Code: %d, Body: %v", code2, res2)
		}

		ok := waitForCondition(5*time.Second, func() bool {
			var status string
			err := db.QueryRow(context.Background(),
				"SELECT status FROM outbox_events WHERE route_id = $1 AND event_id = $2", routeID, eventID).Scan(&status)
			return err == nil && status == "COMPLETED"
		})
		if !ok {
			t.Fatalf("Event (%s) 5 saniye içinde COMPLETED olmadı", eventID)
		}

		// Çıkış imzasını doğrula
		lastSigMu.Lock()
		sig, ts, body := lastOutgoingSig, lastOutgoingTS, lastOutgoingBody
		lastSigMu.Unlock()
		if !verifyOutgoingSignature(body, outSecret, ts, sig) {
			t.Fatalf("ERP'ye giden X-Webhook-Signature doğrulanamadı! ts=%s sig=%s", ts, sig)
		}

		// delivery_attempts kaydını doğrula
		var httpStatus int
		err := db.QueryRow(context.Background(),
			"SELECT http_status FROM delivery_attempts WHERE route_id = $1 AND event_id = $2 ORDER BY id DESC LIMIT 1",
			routeID, eventID).Scan(&httpStatus)
		if err != nil || httpStatus != http.StatusOK {
			t.Fatalf("delivery_attempts kaydı doğrulanamadı: status=%d err=%v", httpStatus, err)
		}
	})

	// SENARYO 5: 400 -> DLQ -> Control Plane Listeleme -> Replay -> COMPLETED
	t.Run("DLQ_List_And_AdminReplay", func(t *testing.T) {
		mockERPStatus.Store(http.StatusBadRequest)
		eventID := fmt.Sprintf("e2e_dlq_%d", time.Now().UnixNano())

		code, _ := sendSignedWebhook(t, routeSlug, eventID, inSecret)
		if code != http.StatusOK {
			t.Fatalf("Webhook kabul edilmedi, code: %d", code)
		}

		var dlqID int64
		ok := waitForCondition(5*time.Second, func() bool {
			err := db.QueryRow(context.Background(),
				"SELECT id FROM dead_letter_queue WHERE route_id = $1 AND event_id = $2", routeID, eventID).Scan(&dlqID)
			return err == nil && dlqID > 0
		})
		if !ok {
			t.Fatalf("Event (%s) DLQ tablosuna düşmedi", eventID)
		}

		// Control Plane filtreli DLQ listeleme kontrolü
		listReq, _ := http.NewRequest(http.MethodGet,
			fmt.Sprintf("%s/api/v1/admin/dlq?tenant_id=%d&route_id=%d", baseURL, tenantID, routeID), nil)
		listReq.Header.Set("X-API-KEY", adminKey)
		listResp, err := http.DefaultClient.Do(listReq)
		if err != nil || listResp.StatusCode != http.StatusOK {
			t.Fatalf("DLQ listeleme başarısız: err=%v", err)
		}
		_ = listResp.Body.Close()

		// ERP'yi düzelt ve Replay et
		mockERPStatus.Store(http.StatusOK)
		replayReq, _ := http.NewRequest(http.MethodPost, baseURL+"/api/v1/admin/replay-dlq",
			strings.NewReader(fmt.Sprintf(`{"dlq_ids":[%d]}`, dlqID)))
		replayReq.Header.Set("Content-Type", "application/json")
		replayReq.Header.Set("X-API-KEY", adminKey)

		replayResp, err := http.DefaultClient.Do(replayReq)
		if err != nil || replayResp.StatusCode != http.StatusOK {
			t.Fatalf("Replay başarısız: err=%v", err)
		}
		_ = replayResp.Body.Close()

		ok = waitForCondition(5*time.Second, func() bool {
			var status string
			err := db.QueryRow(context.Background(),
				"SELECT status FROM outbox_events WHERE route_id = $1 AND event_id = $2", routeID, eventID).Scan(&status)
			return err == nil && status == "COMPLETED"
		})
		if !ok {
			t.Fatalf("Replay edilen event (%s) COMPLETED olmadı", eventID)
		}
	})

	// SENARYO 6: 500 -> Exponential Backoff Planlaması (retry_count = 1, next_retry_at > NOW())
	t.Run("Transient500_ScheduledForBackoffRetry", func(t *testing.T) {
		mockERPStatus.Store(http.StatusOK)
		mockFailNextCount.Store(1)

		eventID := fmt.Sprintf("e2e_retry_%d", time.Now().UnixNano())
		code, _ := sendSignedWebhook(t, routeSlug, eventID, inSecret)
		if code != http.StatusOK {
			t.Fatalf("Webhook kabul edilmedi: %d", code)
		}

		ok := waitForCondition(5*time.Second, func() bool {
			var status string
			var retryCount int
			var nextRetry *time.Time
			err := db.QueryRow(context.Background(),
				"SELECT status, retry_count, next_retry_at FROM outbox_events WHERE route_id = $1 AND event_id = $2",
				routeID, eventID).Scan(&status, &retryCount, &nextRetry)
			return err == nil && status == "PENDING" && retryCount == 1 && nextRetry != nil && nextRetry.After(time.Now())
		})
		if !ok {
			t.Fatalf("Event (%s) 500 hatası sonrası retry için planlanmadı", eventID)
		}
	})

	// SENARYO 7: Tenant API Key (whk_...) İzolasyonu & IDOR Koruması (200 / 401 / 403)
	t.Run("TenantAPIKey_Isolation_And_IDOR", func(t *testing.T) {
		tenant2ID, tenant2Key := createTenantWithQuota(t, adminKey, "E2E Isolated Tenant", 1000)
		slug2 := fmt.Sprintf("e2e_t2_route_%d", time.Now().UnixNano())

		// 1. Tenant kendi whk_... anahtarıyla kendi route'unu oluşturabilmeli (201)
		_ = createRouteWithKey(t, tenant2Key, tenant2ID, slug2, inSecret, targetURL)

		// 2. Tenant kendi anahtarıyla kendi route'larını listeleyebilmeli (200)
		listReq, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/admin/routes", nil)
		listReq.Header.Set("X-API-KEY", tenant2Key)
		listResp, err := http.DefaultClient.Do(listReq)
		if err != nil || listResp.StatusCode != http.StatusOK {
			t.Fatalf("Tenant kendi route'larını listeleyemedi: err=%v", err)
		}
		var routes []struct {
			TenantID  int64  `json:"tenant_id"`
			RouteSlug string `json:"route_slug"`
		}
		_ = json.NewDecoder(listResp.Body).Decode(&routes)
		_ = listResp.Body.Close()
		if len(routes) != 1 || routes[0].TenantID != tenant2ID {
			t.Fatalf("Tenant sadece kendi route'unu görmeliydi, gelen: %+v", routes)
		}

		// 3. Tenant anahtarı Süper Admin ucuna erişememeli (401 Unauthorized)
		adminReq, _ := http.NewRequest(http.MethodGet, baseURL+"/api/v1/admin/tenants", nil)
		adminReq.Header.Set("X-API-KEY", tenant2Key)
		adminResp, err := http.DefaultClient.Do(adminReq)
		if err != nil {
			t.Fatalf("Admin ucu isteği hatası: %v", err)
		}
		_ = adminResp.Body.Close()
		if adminResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("Tenant anahtarı /admin/tenants için 401 almalıydı, gelen: %d", adminResp.StatusCode)
		}

		// 4. IDOR: Tenant 2, Tenant 1'in route'unu (routeID) silmeye çalıştığında 403 Forbidden almalı
		delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/admin/routes/%d", baseURL, routeID), nil)
		delReq.Header.Set("X-API-KEY", tenant2Key)
		delResp, err := http.DefaultClient.Do(delReq)
		if err != nil {
			t.Fatalf("IDOR DELETE isteği hatası: %v", err)
		}
		_ = delResp.Body.Close()
		if delResp.StatusCode != http.StatusForbidden {
			t.Fatalf("Başka tenant'ın route'unu silmede beklenen 403 Forbidden, gelen: %d", delResp.StatusCode)
		}
	})

	// SENARYO 8: Aylık Kota Zorlaması (Duplicate kota yemez, limit aşımında 429)
	t.Run("MonthlyQuota_Enforced_DuplicatesFree", func(t *testing.T) {
		mockERPStatus.Store(http.StatusOK)

		// Kotası sadece 2 olan bir tenant + route oluştur
		qTenantID, qTenantKey := createTenantWithQuota(t, adminKey, "E2E Quota Tenant", 2)
		qSlug := fmt.Sprintf("e2e_quota_route_%d", time.Now().UnixNano())
		_ = createRouteWithKey(t, qTenantKey, qTenantID, qSlug, inSecret, targetURL)

		ev1 := fmt.Sprintf("e2e_q1_%d", time.Now().UnixNano())
		ev2 := fmt.Sprintf("e2e_q2_%d", time.Now().UnixNano())
		ev3 := fmt.Sprintf("e2e_q3_%d", time.Now().UnixNano())

		// 1. Event -> 200 accepted (Kota: 1/2)
		if code, res := sendSignedWebhook(t, qSlug, ev1, inSecret); code != http.StatusOK || res["status"] != "accepted" {
			t.Fatalf("1. event accepted olmalıydı: code=%d res=%v", code, res)
		}

		// 1. Event tekrar (duplicate) -> 200 duplicate (Kota harcamamalı, hala 1/2)
		if code, res := sendSignedWebhook(t, qSlug, ev1, inSecret); code != http.StatusOK || res["status"] != "duplicate" {
			t.Fatalf("Duplicate event 200 duplicate olmalıydı: code=%d res=%v", code, res)
		}

		// 2. Event -> 200 accepted (Kota: 2/2)
		if code, res := sendSignedWebhook(t, qSlug, ev2, inSecret); code != http.StatusOK || res["status"] != "accepted" {
			t.Fatalf("2. event accepted olmalıydı: code=%d res=%v", code, res)
		}

		// 3. Event -> 429 Too Many Requests (Kota aşıldı)
		if code, _ := sendSignedWebhook(t, qSlug, ev3, inSecret); code != http.StatusTooManyRequests {
			t.Fatalf("Kota aşımında beklenen 429 Too Many Requests, gelen: %d", code)
		}
	})
}
