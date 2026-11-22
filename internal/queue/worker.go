package queue

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"gowebhookmiddleware/internal/config"
	"gowebhookmiddleware/internal/crypto"
	"gowebhookmiddleware/internal/metrics"
	"gowebhookmiddleware/internal/repository/postgres/sqlc_gen"
	"gowebhookmiddleware/internal/security"
	"gowebhookmiddleware/internal/verifier"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type OutboxEvent struct {
	ID                int64
	TenantID          int64
	RouteID           int64
	RouteSlug         string
	EventID           string
	EventType         string
	ContentType       string
	Headers           json.RawMessage
	Payload           []byte
	RetryCount        int
	TargetURL         string
	TargetHeadersEnc  string
	OutgoingSecretEnc string
	MaxRetries        int
}

const maxResponseSnippetBytes = 2048 // 2 KB

const maxRetryBackoff = 24 * time.Hour

type alertJob struct {
	job    OutboxEvent
	reason string
}

type WorkerPool struct {
	httpClient  *http.Client
	workerCount int
	sqlc        *sqlc_gen.Queries
	cipher      *crypto.Cipher
	cb          *CircuitBreakerManager
	done        chan struct{}
	wg          sync.WaitGroup
	alertChan   chan alertJob
	alertWg     sync.WaitGroup
	cfg         *config.Config
	batchSize   int
}

func NewWorkerPool(sqlc *sqlc_gen.Queries, cfg *config.Config, cipher *crypto.Cipher, redisClient *redis.Client) *WorkerPool {
	transport := &http.Transport{
		DialContext:         security.NewSafeDialContext(cfg.AllowPrivateTargets),
		MaxIdleConns:        cfg.WorkerCount,
		MaxIdleConnsPerHost: cfg.WorkerCount,
		IdleConnTimeout:     90 * time.Second,
	}
	batchSize := cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 50 // Varsayılan batch boyutu
	}
	return &WorkerPool{
		httpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			// 3xx yönlendirmelerini takip etme (SSRF bypass ve target_headers sızıntısını önler)
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		workerCount: cfg.WorkerCount,
		sqlc:        sqlc,
		cipher:      cipher,
		cb:          NewDistributedCircuitBreakerManager(redisClient, 5, 60*time.Second),
		done:        make(chan struct{}),
		alertChan:   make(chan alertJob, 100),
		cfg:         cfg,
		batchSize:   batchSize,
	}
}

func (wp *WorkerPool) Start(ctx context.Context) {
	jobsChan := make(chan OutboxEvent, wp.workerCount*2)

	for i := 0; i < wp.workerCount; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, jobsChan)
	}

	wp.wg.Add(1)
	go wp.dispatcher(ctx, jobsChan)

	wp.wg.Add(1)
	go wp.sweeper(ctx)

	wp.wg.Add(1)
	go wp.retentionSweeper(ctx)

	const alertWorkerCount = 2
	for i := 0; i < alertWorkerCount; i++ {
		wp.alertWg.Add(1)
		go wp.alertWorker()
	}

	go func() {
		<-ctx.Done()
		log.Println("WorkerPool: Context iptal edildi, dispatcher ve worker'lar durduruluyor...")
		wp.wg.Wait()
		close(wp.alertChan)
		wp.alertWg.Wait()
		log.Println("WorkerPool: Tüm worker'lar durduruldu.")
		close(wp.done)
	}()
}

func (wp *WorkerPool) alertWorker() {
	defer wp.alertWg.Done()
	for alert := range wp.alertChan {
		wp.sendAlert(alert.job, alert.reason, wp.cfg)
	}
}

func (wp *WorkerPool) Wait(ctx context.Context) error {
	select {
	case <-wp.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (wp *WorkerPool) sweeper(ctx context.Context) {
	defer wp.wg.Done()
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := wp.sqlc.SweepOrphanedEvents(sweepCtx)
			cancel()
			if err != nil {
				log.Printf("Sweeper hatası: %v", err)
			}
		}
	}
}

func (wp *WorkerPool) dispatcher(ctx context.Context, jobs chan<- OutboxEvent) {
	defer wp.wg.Done()
	defer close(jobs)

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wp.fetchAndDispatch(ctx, jobs)
		}
	}
}

func (wp *WorkerPool) fetchAndDispatch(ctx context.Context, jobs chan<- OutboxEvent) {
	for {
		if ctx.Err() != nil {
			return
		}
		events, err := wp.sqlc.FetchPendingOutboxEvents(ctx, int32(wp.batchSize))
		if err != nil {
			if ctx.Err() == nil {
				log.Printf("Dispatcher DB hatası: %v", err)
			}
			return
		}
		for _, event := range events {
			job := OutboxEvent{
				ID:                event.ID,
				TenantID:          event.TenantID,
				RouteID:           event.RouteID,
				RouteSlug:         event.RouteSlug,
				EventID:           event.EventID,
				EventType:         event.EventType,
				ContentType:       event.ContentType,
				Headers:           event.Headers,
				Payload:           event.Payload,
				RetryCount:        int(event.RetryCount),
				TargetURL:         event.TargetUrl,
				TargetHeadersEnc:  event.TargetHeadersEnc,
				OutgoingSecretEnc: event.OutgoingSecretEnc,
				MaxRetries:        int(event.MaxRetries),
			}
			jobs <- job
			metrics.QueueDepth.Inc()
		}
		if len(events) < wp.batchSize {
			// Eğer batch boyutu dolmadıysa, daha fazla event yok demektir.
			// Bu durumda döngüyü kır ve bir sonraki tick'i bekle.
			return
		}
	}
}

func (wp *WorkerPool) worker(ctx context.Context, jobs <-chan OutboxEvent) {
	defer wp.wg.Done()
	for job := range jobs {
		metrics.QueueDepth.Dec()
		wp.processJob(ctx, job)
	}
}

func (wp *WorkerPool) processJob(ctx context.Context, job OutboxEvent) {
	// 1. Circuit Breaker kontrolü
	if allowed, retryAfter := wp.cb.Allow(job.RouteID); !allowed {
		jitter := time.Duration(rand.Int64N(5000)) * time.Millisecond
		wp.deferForCircuitBreaker(job.ID, job.RouteSlug, retryAfter.Add(jitter))
		return
	}

	// Probe kilidinin erken return veya 4xx durumunda asılı kalmasını önle
	cbReported := false
	defer func() {
		if !cbReported {
			wp.cb.CancelProbe(job.RouteID)
		}
	}()

	reqCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, job.TargetURL, bytes.NewReader(job.Payload))
	if err != nil {
		wp.moveToDLQ(job, "HTTP isteği oluşturulamadı: "+err.Error())
		return
	}

	req.Header.Set("Content-Type", job.ContentType)
	req.Header.Set("X-Webhook-Event-Id", job.EventID)
	req.Header.Set("X-Webhook-Event-Type", job.EventType)

	// Şifreli hedef auth header'larını çöz ve ekle
	if job.TargetHeadersEnc != "" {
		decrypted, err := wp.cipher.Decrypt(job.TargetHeadersEnc)
		if err != nil {
			wp.moveToDLQ(job, "Target headers şifre çözme hatası: "+err.Error())
			return
		}
		var customHeaders map[string]string
		if err := json.Unmarshal([]byte(decrypted), &customHeaders); err == nil {
			for k, v := range customHeaders {
				req.Header.Set(k, v)
			}
		}
	}

	// Çıkış imzası
	if job.OutgoingSecretEnc != "" {
		outSecret, err := wp.cipher.Decrypt(job.OutgoingSecretEnc)
		if err != nil {
			wp.moveToDLQ(job, "Outgoing secret şifre çözme hatası: "+err.Error())
			return
		}
		if outSecret != "" {
			ts := time.Now().Unix()
			sig := verifier.SignOutgoing(job.Payload, outSecret, ts)
			req.Header.Set("X-Webhook-Timestamp", strconv.FormatInt(ts, 10))
			req.Header.Set("X-Webhook-Signature", sig)
		}
	}

	start := time.Now()
	resp, err := wp.httpClient.Do(req)
	elapsed := time.Since(start)
	metrics.ERPDeliveryDuration.WithLabelValues(job.RouteSlug).Observe(elapsed.Seconds())

	if err != nil {
		wp.recordDeliveryAttempt(job, 0, int(elapsed.Milliseconds()), err.Error(), "")
		if errors.Is(err, security.ErrBlockedTargetIP) {
			wp.moveToDLQ(job, err.Error())
			return
		}
		wp.cb.RecordFailure(job.RouteID)
		cbReported = true
		wp.handleFailure(job, fmt.Sprintf("Hedef bağlantı hatası: %v", err))
		return
	}

	// İlk 2KB'yi log/panel için oku, kalanı keep-alive için tüket
	snippetBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSnippetBytes))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	snippet := string(snippetBytes)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		wp.recordDeliveryAttempt(job, resp.StatusCode, int(elapsed.Milliseconds()), "", snippet)
		wp.cb.RecordSuccess(job.RouteID)
		cbReported = true
		wp.markAsCompleted(job.ID, job.RouteSlug)
		return
	}

	errMsg := fmt.Sprintf("Hedeften başarısız yanıt. StatusCode: %d", resp.StatusCode)
	wp.recordDeliveryAttempt(job, resp.StatusCode, int(elapsed.Milliseconds()), errMsg, snippet)

	if resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusRequestTimeout {
		wp.cb.RecordFailure(job.RouteID)
		cbReported = true
		wp.handleFailure(job, errMsg)
	} else {
		// 3xx/4xx: hedef sunucu ayakta ama istek kalıcı olarak reddedildi -> DLQ
		wp.moveToDLQ(job, errMsg)
	}
}

func calculateNextRetryTime(retryCount int) time.Time {
	if retryCount < 0 {
		retryCount = 0
	}
	var base time.Duration
	if retryCount >= 5 { // 5^5 dk = 52 saat > 24 saat; overflow riskini baştan kes
		base = maxRetryBackoff
	} else {
		base = time.Duration(math.Pow(5, float64(retryCount))) * time.Minute
		if base > maxRetryBackoff {
			base = maxRetryBackoff
		}
	}
	jitter := time.Duration(rand.Int64N(int64(base)/5 + 1))
	return time.Now().Add(base + jitter)
}

func (wp *WorkerPool) handleFailure(job OutboxEvent, errorMessage string) {
	if job.RetryCount < job.MaxRetries {
		nextRetry := calculateNextRetryTime(job.RetryCount)
		wp.markForRetry(job.ID, job.RouteSlug, nextRetry)
	} else {
		wp.moveToDLQ(job, errorMessage)
	}
}

func (wp *WorkerPool) moveToDLQ(job OutboxEvent, reason string) {
	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := wp.sqlc.MoveToDLQ(updateCtx, sqlc_gen.MoveToDLQParams{
		ID:          job.ID,
		ErrorReason: sql.NullString{String: reason, Valid: true},
	})
	if err != nil {
		log.Printf("DLQ taşıma hatası (id=%d): %v", job.ID, err)
		return
	}
	metrics.WebhooksProcessedTotal.WithLabelValues(job.RouteSlug, "dlq").Inc()
	select {
	case wp.alertChan <- alertJob{job: job, reason: reason}:
	default:
		log.Printf("Alert kanalı dolu, bildirim atlandı (event=%s)", job.EventID)
	}
}

func (wp *WorkerPool) sendAlert(job OutboxEvent, reason string, cfg *config.Config) {
	if cfg.SlackAlertWebhookUrl == "" {
		return
	}
	alertMessage := fmt.Sprintf("[Route: %s] Event DLQ'ya taşındı. EventID: %s, Type: %s, Reason: %s",
		job.RouteSlug, job.EventID, job.EventType, reason)
	payload, _ := json.Marshal(map[string]string{"text": alertMessage})

	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(updateCtx, http.MethodPost, cfg.SlackAlertWebhookUrl, bytes.NewReader(payload))
	if err != nil {
		log.Printf("Slack alert isteği oluşturulamadı (event=%s): %v", job.EventID, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := wp.httpClient.Do(req)
	if err != nil {
		log.Printf("Slack alert gönderilemedi (event=%s): %v", job.EventID, err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("Slack alert başarısız yanıt (event=%s, status=%d)", job.EventID, resp.StatusCode)
	}
}

func (wp *WorkerPool) markForRetry(id int64, routeSlug string, nextRetry time.Time) {
	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := wp.sqlc.MarkOutboxEventForRetry(updateCtx, sqlc_gen.MarkOutboxEventForRetryParams{
		ID:          id,
		NextRetryAt: sql.NullTime{Time: nextRetry, Valid: true},
	})
	if err != nil {
		log.Printf("Retry güncelleme hatası (id=%d): %v", id, err)
		return
	}
	metrics.WebhooksProcessedTotal.WithLabelValues(routeSlug, "retry").Inc()
}

func (wp *WorkerPool) markAsCompleted(id int64, routeSlug string) {
	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wp.sqlc.MarkOutboxEventAsCompleted(updateCtx, id); err != nil {
		log.Printf("Completed güncelleme hatası (id=%d): %v", id, err)
		return
	}
	metrics.WebhooksProcessedTotal.WithLabelValues(routeSlug, "completed").Inc()
}
func (wp *WorkerPool) deferForCircuitBreaker(id int64, routeSlug string, nextRetry time.Time) {
	updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := wp.sqlc.DeferOutboxEvent(updateCtx, sqlc_gen.DeferOutboxEventParams{
		ID:          id,
		NextRetryAt: sql.NullTime{Time: nextRetry, Valid: true},
	})
	if err != nil {
		log.Printf("CircuitBreaker erteleme hatası (id=%d): %v", id, err)
		return
	}
	metrics.WebhooksProcessedTotal.WithLabelValues(routeSlug, "circuit_open").Inc()
}

func (wp *WorkerPool) recordDeliveryAttempt(job OutboxEvent, statusCode, durationMs int, errSummary, snippet string) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := wp.sqlc.InsertDeliveryAttempt(ctx, sqlc_gen.InsertDeliveryAttemptParams{
		TenantID:            job.TenantID,
		RouteID:             job.RouteID,
		OutboxEventID:       job.ID,
		EventID:             job.EventID,
		AttemptNumber:       int32(job.RetryCount + 1),
		HttpStatus:          int32(statusCode),
		DurationMs:          int32(durationMs),
		ErrorSummary:        errSummary,
		ResponseBodySnippet: snippet,
	})
	if err != nil {
		log.Printf("DeliveryAttempt kayıt hatası (event=%s): %v", job.EventID, err)
	}
}

// retentionSweeper: Günde bir çalışarak 30 günden eski COMPLETED outbox ve delivery_attempts kayıtlarını 1000'erli batch'ler halinde siler.
func (wp *WorkerPool) retentionSweeper(ctx context.Context) {
	defer wp.wg.Done()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			wp.runRetentionCleanup(ctx)
		}
	}
}

func (wp *WorkerPool) runRetentionCleanup(ctx context.Context) {
	var totalOutbox, totalAttempts int64

	for ctx.Err() == nil {
		delCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		n, err := wp.sqlc.DeleteOldCompletedOutboxEvents(delCtx)
		cancel()
		if err != nil {
			log.Printf("RetentionSweeper (outbox) hatası: %v", err)
			break
		}
		totalOutbox += n
		if n < 1000 {
			break
		}
		time.Sleep(100 * time.Millisecond) // DB I/O yükünü yaymak için kısa bekleme
	}

	for ctx.Err() == nil {
		delCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		n, err := wp.sqlc.DeleteOldDeliveryAttempts(delCtx)
		cancel()
		if err != nil {
			log.Printf("RetentionSweeper (delivery_attempts) hatası: %v", err)
			break
		}
		totalAttempts += n
		if n < 1000 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if totalOutbox > 0 || totalAttempts > 0 {
		log.Printf("RetentionSweeper tamamlandı: %d outbox, %d delivery_attempts temizlendi.", totalOutbox, totalAttempts)
	}
}
