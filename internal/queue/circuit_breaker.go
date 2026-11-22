package queue

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

type CBState int

const (
	StateClosed CBState = iota
	StateOpen
	StateHalfOpen
)

func (s CBState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF-OPEN"
	default:
		return "UNKNOWN"
	}
}

const (
	cbKeyPrefix    = "cb:route:"
	cbProbeLockMs  = 15000 // Probe atan instance çökerse 15 sn sonra kilit otomatik açılır
	cbRedisTimeout = 2 * time.Second
)

var (
	cbAllowScript = redis.NewScript(`
		local state = redis.call('HGET', KEYS[1], 'state')
		if not state or state == 'closed' then
			return {1, 0}
		end

		local now = tonumber(ARGV[1])
		local probeLockMs = tonumber(ARGV[2])

		if state == 'open' then
			local openUntil = tonumber(redis.call('HGET', KEYS[1], 'open_until_ms') or '0')
			if now >= openUntil then
				redis.call('HSET', KEYS[1], 'state', 'half_open', 'probe_until_ms', now + probeLockMs)
				redis.call('PEXPIRE', KEYS[1], 3600000)
				return {1, 1}
			end
			return {0, openUntil}
		end

		if state == 'half_open' then
			local probeUntil = tonumber(redis.call('HGET', KEYS[1], 'probe_until_ms') or '0')
			if now >= probeUntil then
				redis.call('HSET', KEYS[1], 'probe_until_ms', now + probeLockMs)
				return {1, 0}
			end
			return {0, now + 5000}
		end

		return {1, 0}
	`)

	cbRecordFailureScript = redis.NewScript(`
		local state = redis.call('HGET', KEYS[1], 'state') or 'closed'
		local now = tonumber(ARGV[1])
		local threshold = tonumber(ARGV[2])
		local openDurationMs = tonumber(ARGV[3])
		local ttlMs = math.max(openDurationMs * 2, 600000)

		if state == 'half_open' then
			redis.call('HSET', KEYS[1], 'state', 'open', 'open_until_ms', now + openDurationMs, 'failures', 0, 'probe_until_ms', 0)
			redis.call('PEXPIRE', KEYS[1], ttlMs)
			return 2
		end

		local failures = redis.call('HINCRBY', KEYS[1], 'failures', 1)
		if failures >= threshold then
			redis.call('HSET', KEYS[1], 'state', 'open', 'open_until_ms', now + openDurationMs, 'failures', 0, 'probe_until_ms', 0)
			redis.call('PEXPIRE', KEYS[1], ttlMs)
			return 1
		end

		redis.call('HSET', KEYS[1], 'state', 'closed')
		redis.call('PEXPIRE', KEYS[1], ttlMs)
		return 0
	`)

	cbCancelProbeScript = redis.NewScript(`
		local state = redis.call('HGET', KEYS[1], 'state')
		if state == 'half_open' then
			redis.call('HSET', KEYS[1], 'probe_until_ms', 0)
		end
		return 1
	`)
)

type routeBreaker struct {
	mu                  sync.Mutex
	state               CBState
	consecutiveFailures int
	openUntil           time.Time
	halfOpenInFlight    bool
}

// CircuitBreakerManager, her route_id için Redis destekli (fallback: in-memory) Circuit Breaker yönetir.
type CircuitBreakerManager struct {
	redis            *redis.Client
	mu               sync.RWMutex
	breakers         map[int64]*routeBreaker
	failureThreshold int
	openDuration     time.Duration
}

// NewCircuitBreakerManager in-memory Circuit Breaker oluşturur (unit testler ve tek node için).
func NewCircuitBreakerManager(failureThreshold int, openDuration time.Duration) *CircuitBreakerManager {
	return NewDistributedCircuitBreakerManager(nil, failureThreshold, openDuration)
}

// NewDistributedCircuitBreakerManager Redis tabanlı, kesinti anında in-memory fallback yapan Circuit Breaker oluşturur.
func NewDistributedCircuitBreakerManager(redisClient *redis.Client, failureThreshold int, openDuration time.Duration) *CircuitBreakerManager {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if openDuration <= 0 {
		openDuration = 60 * time.Second
	}
	return &CircuitBreakerManager{
		redis:            redisClient,
		breakers:         make(map[int64]*routeBreaker),
		failureThreshold: failureThreshold,
		openDuration:     openDuration,
	}
}

func (m *CircuitBreakerManager) redisKey(routeID int64) string {
	return fmt.Sprintf("%s%d", cbKeyPrefix, routeID)
}

func (m *CircuitBreakerManager) getOrCreate(routeID int64) *routeBreaker {
	m.mu.RLock()
	b, ok := m.breakers[routeID]
	m.mu.RUnlock()
	if ok {
		return b
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if b, ok = m.breakers[routeID]; ok {
		return b
	}
	b = &routeBreaker{state: StateClosed}
	m.breakers[routeID] = b
	return b
}

// Allow, bu route için HTTP isteği atılıp atılamayacağını kontrol eder.
func (m *CircuitBreakerManager) Allow(routeID int64) (allowed bool, retryAfter time.Time) {
	if m.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cbRedisTimeout)
		defer cancel()

		res, err := cbAllowScript.Run(ctx, m.redis, []string{m.redisKey(routeID)}, time.Now().UnixMilli(), cbProbeLockMs).Int64Slice()
		if err == nil && len(res) == 2 {
			if res[0] == 1 {
				if res[1] == 1 {
					log.Printf("CircuitBreaker [route=%d]: OPEN -> HALF-OPEN (dağıtık probe isteği gönderiliyor)", routeID)
				}
				return true, time.Time{}
			}
			return false, time.UnixMilli(res[1])
		}
		log.Printf("CircuitBreaker [route=%d]: Redis Allow hatası (in-memory fallback): %v", routeID, err)
	}

	return m.allowLocal(routeID)
}

func (m *CircuitBreakerManager) allowLocal(routeID int64) (bool, time.Time) {
	b := m.getOrCreate(routeID)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	switch b.state {
	case StateClosed:
		return true, time.Time{}

	case StateOpen:
		if now.After(b.openUntil) {
			b.state = StateHalfOpen
			b.halfOpenInFlight = true
			log.Printf("CircuitBreaker [route=%d]: OPEN -> HALF-OPEN (probe isteği gönderiliyor)", routeID)
			return true, time.Time{}
		}
		return false, b.openUntil

	case StateHalfOpen:
		if b.halfOpenInFlight {
			return false, now.Add(5 * time.Second)
		}
		b.halfOpenInFlight = true
		return true, time.Time{}

	default:
		return true, time.Time{}
	}
}

// RecordSuccess, 2xx yanıtında devreyi kapatır ve hata sayacını sıfırlar.
// RecordSuccess, 2xx yanıtında devreyi kapatır ve hata sayacını sıfırlar.
func (m *CircuitBreakerManager) RecordSuccess(routeID int64) {
	if m.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cbRedisTimeout)
		defer cancel()

		deleted, err := m.redis.Del(ctx, m.redisKey(routeID)).Result()
		if err == nil {
			if deleted > 0 {
				log.Printf("CircuitBreaker [route=%d]: -> CLOSED (hedef normale döndü)", routeID)
			}
			// Önceki bir Redis kesintisinden kalma local OPEN/hata durumunu da temizle
			m.resetLocal(routeID, false)
			return
		}
		log.Printf("CircuitBreaker [route=%d]: Redis RecordSuccess hatası (in-memory fallback): %v", routeID, err)
	}

	m.resetLocal(routeID, true)
}

func (m *CircuitBreakerManager) resetLocal(routeID int64, logTransition bool) {
	m.mu.RLock()
	b, ok := m.breakers[routeID]
	m.mu.RUnlock()
	if !ok {
		return
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if logTransition && b.state != StateClosed {
		log.Printf("CircuitBreaker [route=%d]: %s -> CLOSED (hedef normale döndü)", routeID, b.state)
	}
	b.state = StateClosed
	b.consecutiveFailures = 0
	b.halfOpenInFlight = false
}

// RecordFailure, 5xx veya network timeout hatalarında çağrılır.
func (m *CircuitBreakerManager) RecordFailure(routeID int64) {
	if m.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cbRedisTimeout)
		defer cancel()

		transition, err := cbRecordFailureScript.Run(
			ctx,
			m.redis,
			[]string{m.redisKey(routeID)},
			time.Now().UnixMilli(),
			m.failureThreshold,
			m.openDuration.Milliseconds(),
		).Int()
		if err == nil {
			if transition == 2 {
				log.Printf("CircuitBreaker [route=%d]: HALF-OPEN -> OPEN (dağıtık probe başarısız, %v bekleniyor)", routeID, m.openDuration)
			} else if transition == 1 {
				log.Printf("CircuitBreaker [route=%d]: CLOSED -> OPEN (%d ardışık hata, %v devre açık)", routeID, m.failureThreshold, m.openDuration)
			}
			return
		}
		log.Printf("CircuitBreaker [route=%d]: Redis RecordFailure hatası (in-memory fallback): %v", routeID, err)
	}

	b := m.getOrCreate(routeID)
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.state == StateHalfOpen {
		b.state = StateOpen
		b.openUntil = now.Add(m.openDuration)
		b.halfOpenInFlight = false
		log.Printf("CircuitBreaker [route=%d]: HALF-OPEN -> OPEN (probe başarısız, %v bekleniyor)", routeID, m.openDuration)
		return
	}

	b.consecutiveFailures++
	if b.consecutiveFailures >= m.failureThreshold {
		b.state = StateOpen
		b.openUntil = now.Add(m.openDuration)
		b.consecutiveFailures = 0
		log.Printf("CircuitBreaker [route=%d]: CLOSED -> OPEN (%d ardışık hata, %v devre açık)",
			routeID, m.failureThreshold, m.openDuration)
	}
}

// CancelProbe, HALF-OPEN probe isteği HTTP sonucuna ulaşamadan (4xx, SSRF, config hatası) biterse kilidi açar.
func (m *CircuitBreakerManager) CancelProbe(routeID int64) {
	if m.redis != nil {
		ctx, cancel := context.WithTimeout(context.Background(), cbRedisTimeout)
		defer cancel()

		if err := cbCancelProbeScript.Run(ctx, m.redis, []string{m.redisKey(routeID)}).Err(); err == nil {
			return
		}
	}

	b := m.getOrCreate(routeID)
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == StateHalfOpen && b.halfOpenInFlight {
		b.halfOpenInFlight = false
	}
}
