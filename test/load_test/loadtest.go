package main

import (
	"bytes"
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
	"time"
)

const (
	totalRequests   = 1000
	concurrency     = 50
	duplicateModulo = 3
)

type WebhookPayload struct {
	EventID   string         `json:"event_id"`
	EventType string         `json:"event_type"`
	Payload   map[string]any `json:"payload"`
}

func main() {
	baseURL := getEnv("BASE_URL", "http://localhost")
	routeSlug := getEnv("ROUTE_SLUG", "demo-studio-route")
	signingSecret := os.Getenv("SIGNING_SECRET")
	targetURL := fmt.Sprintf("%s/api/v1/ingest/%s", strings.TrimRight(baseURL, "/"), routeSlug)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			MaxIdleConnsPerHost: concurrency,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	var (
		acceptedCount    atomic.Int64
		duplicateCount   atomic.Int64
		rateLimitedCount atomic.Int64
		errorCount       atomic.Int64
	)

	runID := time.Now().UnixNano()
	jobs := make(chan int, totalRequests)
	for i := 0; i < totalRequests; i++ {
		jobs <- i
	}
	close(jobs)

	fmt.Printf("Yük testi başlıyor -> %s | %d istek, %d worker...\n", targetURL, totalRequests, concurrency)
	start := time.Now()

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				idNum := i
				if i > 0 && i%duplicateModulo == 0 {
					idNum = i - 1
				}

				bodyBytes, _ := json.Marshal(WebhookPayload{
					EventID:   fmt.Sprintf("load_%d_%d", runID, idNum),
					EventType: "order.created",
					Payload: map[string]any{
						"order_id": idNum,
						"amount":   149.90,
					},
				})

				req, _ := http.NewRequest(http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
				if signingSecret != "" {
					mac := hmac.New(sha256.New, []byte(signingSecret))
					mac.Write(bodyBytes)
					req.Header.Set("X-Webhook-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
				}

				resp, err := client.Do(req)
				if err != nil {
					errorCount.Add(1)
					continue
				}

				respBody, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()

				switch resp.StatusCode {
				case http.StatusOK:
					if strings.Contains(string(respBody), `"duplicate"`) {
						duplicateCount.Add(1)
					} else {
						acceptedCount.Add(1)
					}
				case http.StatusTooManyRequests:
					rateLimitedCount.Add(1)
				default:
					errorCount.Add(1)
				}
			}
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)
	rps := float64(totalRequests) / elapsed.Seconds()

	fmt.Println("========================================")
	fmt.Printf("Toplam Süre      : %v\n", elapsed.Round(time.Millisecond))
	fmt.Printf("Ortalama Hız     : %.2f istek/saniye (RPS)\n", rps)
	fmt.Println("----------------------------------------")
	fmt.Printf("Accepted  (200)  : %d\n", acceptedCount.Load())
	fmt.Printf("Duplicate (200)  : %d\n", duplicateCount.Load())
	fmt.Printf("RateLimit (429)  : %d\n", rateLimitedCount.Load())
	fmt.Printf("Hata / Diğer     : %d\n", errorCount.Load())
	fmt.Println("========================================")
}

func getEnv(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
