package main

import (
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"
)

func main() {
	var (
		totalCount   atomic.Int64
		successCount atomic.Int64
		errorCount   atomic.Int64
	)

	// Her 2 saniyede bir canlı özet bas (konsolu boğmamak için)
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		var lastTotal int64
		for range ticker.C {
			curr := totalCount.Load()
			if curr != lastTotal {
				fmt.Printf("[MOCK ERP] Toplam: %d | 200 OK: %d | 500 Hata: %d\n",
					curr, successCount.Load(), errorCount.Load())
				lastTotal = curr
			}
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("POST /erp/webhook", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
		// burasını dlq'ya düşüp düşmediğini test etmek için aktif etmeliyiz
		//http.Error(w, `{"error":"invalid order payload"}`, http.StatusBadRequest)
		//return
		totalCount.Add(1)

		// 50ms - 250ms arası gerçekçi ağ/işlem gecikmesi
		delay := time.Duration(50+rand.IntN(200)) * time.Millisecond
		time.Sleep(delay)

		// Burasını ne zaman aktif et biliyor musun, istek göndeildikten hemen sonra dockeri kapattığımızda veya mock erp'yi kapattığımızda acaba graceful shutdown çalışıyor mu diye test etmek için aktif edebiliriz. Yani mock erp'yi kapattığımızda graceful shutdown çalışıyor mu diye test edebiliriz.
		// 4 saniye gecikme
		//time.Sleep(4 * time.Second)

		// %10 ihtimalle 500 Internal Server Error dön
		if rand.IntN(100) < 10 {
			errorCount.Add(1)
			http.Error(w, `{"error":"ERP geçici olarak meşgul"}`, http.StatusInternalServerError)
			return
		}

		successCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"received"}`))
	})

	// 0.0.0.0:9000 üzerinden dinle ki Docker konteyneri erişebilsin
	addr := "0.0.0.0:9000"
	log.Printf("Mock ERP sunucusu http://%s/erp/webhook adresinde dinliyor (%%10 hata, 50-250ms gecikme)...", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("Mock ERP başlatılamadı: %v", err)
	}
}
