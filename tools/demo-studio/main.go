package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed index.html
var uiFS embed.FS

type ChaosConfig struct {
	Err500Rate int  `json:"err500_rate"`
	Err400Rate int  `json:"err400_rate"`
	LatencyMs  int  `json:"latency_ms"`
	Outage     bool `json:"outage"`
}

type LoadRequest struct {
	TotalRequests int `json:"total_requests"`
	Concurrency   int `json:"concurrency"`
	DuplicateRate int `json:"duplicate_rate"`
}

type LoadResult struct {
	Running     bool    `json:"running"`
	Total       int64   `json:"total"`
	Accepted    int64   `json:"accepted"`
	Duplicate   int64   `json:"duplicate"`
	RateLimited int64   `json:"rate_limited"`
	Errors      int64   `json:"errors"`
	DurationMs  int64   `json:"duration_ms"`
	RPS         float64 `json:"rps"`
}

type ERPStats struct {
	Total  int64 `json:"total"`
	OK200  int64 `json:"ok_200"`
	Err500 int64 `json:"err_500"`
	Err400 int64 `json:"err_400"`
	Outage int64 `json:"outage_503"`
}

type DLQItem struct {
	ID          int64     `json:"id"`
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"`
	ErrorReason string    `json:"error_reason"`
	CreatedAt   time.Time `json:"created_at"`
}

var (
	chaosMu  sync.RWMutex
	chaosCfg = ChaosConfig{Err500Rate: 10, Err400Rate: 0, LatencyMs: 100, Outage: false}

	erpTotal  atomic.Int64
	erp200    atomic.Int64
	erp500    atomic.Int64
	erp400    atomic.Int64
	erpOutage atomic.Int64

	loadMu     sync.Mutex
	loadResult LoadResult

	dbPool         *pgxpool.Pool
	apiBaseURL     string
	routeSlug      string
	webhookURL     string
	adminReplayURL string
	adminAPIKey    string
)

func main() {
	apiBaseURL = strings.TrimRight(getEnv("API_BASE_URL", "http://nginx"), "/")
	routeSlug = getEnv("DEMO_ROUTE_SLUG", "demo-studio-route")
	webhookURL = getEnv("WEBHOOK_URL", fmt.Sprintf("%s/api/v1/ingest/%s", apiBaseURL, routeSlug))
	adminReplayURL = getEnv("ADMIN_REPLAY_URL", apiBaseURL+"/api/v1/admin/replay-dlq")
	adminAPIKey = getEnv("ADMIN_API_KEY", "")
	dbURL := getEnv("DATABASE_DSN", "postgres://postgres:postgres@postgres:5432/webhook_db?sslmode=disable")

	var err error
	dbPool, err = pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("PostgreSQL bağlantısı kurulamadı: %v", err)
	}
	defer dbPool.Close()

	// 1. Port 9000: Programlanabilir Chaos Mock ERP
	go startMockERP()

	// 2. Arka planda demo tenant & route'u otomatik oluştur (idempotent)
	if adminAPIKey != "" {
		go bootstrapDemoRoute()
	}

	// 3. Port 8090: Web UI & Kontrol API'si
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data, _ := uiFS.ReadFile("index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/chaos", handleChaos)
	mux.HandleFunc("/api/load", handleLoad)
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/api/stats/reset", handleResetStats)
	mux.HandleFunc("/api/dlq", handleListDLQ)
	mux.HandleFunc("/api/dlq/replay", handleReplayDLQ)

	log.Printf("Demo Studio UI http://0.0.0.0:8090 adresinde hazır (target=%s)", webhookURL)
	log.Fatal(http.ListenAndServe(":8090", mux))
}

func bootstrapDemoRoute() {
	mockTarget := getEnv("DEMO_MOCK_ERP_URL", "http://demo-studio:9000/erp/webhook")
	client := &http.Client{Timeout: 5 * time.Second}

	for attempt := 1; attempt <= 10; attempt++ {
		// Tenant oluştur
		tReq, _ := http.NewRequest(http.MethodPost, apiBaseURL+"/api/v1/admin/tenants",
			strings.NewReader(`{"name":"Demo Studio Tenant","monthly_event_quota":1000000}`))
		tReq.Header.Set("Content-Type", "application/json")
		tReq.Header.Set("X-API-KEY", adminAPIKey)

		tResp, err := client.Do(tReq)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		var tRes struct {
			Tenant struct {
				ID int64 `json:"ID"`
			} `json:"tenant"`
		}
		_ = json.NewDecoder(tResp.Body).Decode(&tRes)
		_ = tResp.Body.Close()

		if tRes.Tenant.ID == 0 {
			time.Sleep(2 * time.Second)
			continue
		}

		// Route oluştur (zaten varsa 409 döner -> sorun yok)
		routeBody, _ := json.Marshal(map[string]any{
			"tenant_id":          tRes.Tenant.ID,
			"route_slug":         routeSlug,
			"provider_type":      "none",
			"target_url":         mockTarget,
			"rate_limit_per_sec": 1000,
			"max_retries":        3,
		})
		rReq, _ := http.NewRequest(http.MethodPost, apiBaseURL+"/api/v1/admin/routes", bytes.NewReader(routeBody))
		rReq.Header.Set("Content-Type", "application/json")
		rReq.Header.Set("X-API-KEY", adminAPIKey)

		rResp, err := client.Do(rReq)
		if err == nil {
			_ = rResp.Body.Close()
			if rResp.StatusCode == http.StatusCreated || rResp.StatusCode == http.StatusConflict {
				log.Printf("Demo Studio route hazır: %s -> %s", routeSlug, mockTarget)
				return
			}
		}
		time.Sleep(2 * time.Second)
	}
}

func startMockERP() {
	mux := http.NewServeMux()
	mux.HandleFunc("/erp/webhook", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_ = r.Body.Close()

		erpTotal.Add(1)

		chaosMu.RLock()
		cfg := chaosCfg
		chaosMu.RUnlock()

		if cfg.LatencyMs > 0 {
			jitter := rand.Intn(cfg.LatencyMs/2 + 1)
			time.Sleep(time.Duration(cfg.LatencyMs/2+jitter) * time.Millisecond)
		}

		if cfg.Outage {
			erpOutage.Add(1)
			http.Error(w, `{"error":"ERP down (outage simulated)"}`, http.StatusServiceUnavailable)
			return
		}

		roll := rand.Intn(100)
		if roll < cfg.Err400Rate {
			erp400.Add(1)
			http.Error(w, `{"error":"invalid payload (simulated 400)"}`, http.StatusBadRequest)
			return
		}
		if roll < cfg.Err400Rate+cfg.Err500Rate {
			erp500.Add(1)
			http.Error(w, `{"error":"internal erp error (simulated 500)"}`, http.StatusInternalServerError)
			return
		}

		erp200.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	log.Println("Chaos Mock ERP http://0.0.0.0:9000/erp/webhook adresinde dinliyor")
	log.Fatal(http.ListenAndServe(":9000", mux))
}

func handleChaos(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		chaosMu.RLock()
		defer chaosMu.RUnlock()
		writeJSON(w, http.StatusOK, chaosCfg)
		return
	}
	if r.Method == http.MethodPost {
		var cfg ChaosConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		chaosMu.Lock()
		chaosCfg = cfg
		chaosMu.Unlock()
		writeJSON(w, http.StatusOK, cfg)
		return
	}
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

func handleLoad(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.TotalRequests <= 0 || req.TotalRequests > 20000 {
		req.TotalRequests = 500
	}
	if req.Concurrency <= 0 || req.Concurrency > 200 {
		req.Concurrency = 25
	}

	loadMu.Lock()
	if loadResult.Running {
		loadMu.Unlock()
		http.Error(w, "Yük testi zaten çalışıyor", http.StatusConflict)
		return
	}
	loadResult = LoadResult{Running: true, Total: int64(req.TotalRequests)}
	loadMu.Unlock()

	go runLoadTest(req)
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "started"})
}

func runLoadTest(req LoadRequest) {
	start := time.Now()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        req.Concurrency,
			MaxIdleConnsPerHost: req.Concurrency,
		},
	}

	var accepted, duplicate, rateLimited, errorsCount atomic.Int64
	jobs := make(chan int, req.TotalRequests)
	var wg sync.WaitGroup
	batchPrefix := fmt.Sprintf("demo_%d", time.Now().UnixNano())

	for i := 0; i < req.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				eventID := fmt.Sprintf("%s_%d", batchPrefix, idx)
				if req.DuplicateRate > 0 && idx > 0 && rand.Intn(100) < req.DuplicateRate {
					eventID = fmt.Sprintf("%s_%d", batchPrefix, idx-1)
				}

				body := fmt.Sprintf(`{"event_id":"%s","event_type":"order.created","payload":{"order_id":%d,"amount":149.90}}`, eventID, idx)
				resp, err := client.Post(webhookURL, "application/json", bytes.NewBufferString(body))
				if err != nil {
					errorsCount.Add(1)
					continue
				}

				var res map[string]any
				_ = json.NewDecoder(resp.Body).Decode(&res)
				_ = resp.Body.Close()

				switch resp.StatusCode {
				case http.StatusOK:
					if res["status"] == "duplicate" {
						duplicate.Add(1)
					} else {
						accepted.Add(1)
					}
				case http.StatusTooManyRequests:
					rateLimited.Add(1)
				default:
					errorsCount.Add(1)
				}
			}
		}()
	}

	for i := 0; i < req.TotalRequests; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	elapsed := time.Since(start)
	rps := float64(req.TotalRequests) / elapsed.Seconds()

	loadMu.Lock()
	loadResult = LoadResult{
		Running:     false,
		Total:       int64(req.TotalRequests),
		Accepted:    accepted.Load(),
		Duplicate:   duplicate.Load(),
		RateLimited: rateLimited.Load(),
		Errors:      errorsCount.Load(),
		DurationMs:  elapsed.Milliseconds(),
		RPS:         rps,
	}
	loadMu.Unlock()
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	loadMu.Lock()
	lr := loadResult
	loadMu.Unlock()

	chaosMu.RLock()
	cc := chaosCfg
	chaosMu.RUnlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"chaos": cc,
		"load":  lr,
		"erp": ERPStats{
			Total:  erpTotal.Load(),
			OK200:  erp200.Load(),
			Err500: erp500.Load(),
			Err400: erp400.Load(),
			Outage: erpOutage.Load(),
		},
	})
}

func handleResetStats(w http.ResponseWriter, r *http.Request) {
	erpTotal.Store(0)
	erp200.Store(0)
	erp500.Store(0)
	erp400.Store(0)
	erpOutage.Store(0)
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func handleListDLQ(w http.ResponseWriter, r *http.Request) {
	rows, err := dbPool.Query(r.Context(), `
		SELECT id, event_id, event_type, COALESCE(error_reason, ''), failed_at
		FROM dead_letter_queue
		ORDER BY id DESC
		LIMIT 25
	`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	items := make([]DLQItem, 0)
	for rows.Next() {
		var it DLQItem
		if err := rows.Scan(&it.ID, &it.EventID, &it.EventType, &it.ErrorReason, &it.CreatedAt); err == nil {
			items = append(items, it)
		}
	}
	writeJSON(w, http.StatusOK, items)
}

func handleReplayDLQ(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	req, _ := http.NewRequest(http.MethodPost, adminReplayURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", adminAPIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
