package queue

import (
	"testing"
	"time"
)

func TestCircuitBreakerLifecycle(t *testing.T) {
	// Testin hızlı çalışması için 3 hata eşiği ve 80ms open süresi
	cb := NewCircuitBreakerManager(3, 80*time.Millisecond)
	const routeID int64 = 101

	// 1. Başlangıçta CLOSED -> izin verilmeli
	if allowed, _ := cb.Allow(routeID); !allowed {
		t.Fatal("başlangıçta devre CLOSED olmalıydı")
	}

	// 2. 2 hata henüz devreyi açmamalı
	cb.RecordFailure(routeID)
	cb.RecordFailure(routeID)
	if allowed, _ := cb.Allow(routeID); !allowed {
		t.Fatal("eşik (3) aşılmadan devre açılmamalıydı")
	}

	// 3. 3. hatada devre OPEN olmalı
	cb.RecordFailure(routeID)
	allowed, retryAfter := cb.Allow(routeID)
	if allowed || !retryAfter.After(time.Now()) {
		t.Fatalf("3. hatadan sonra devre OPEN olmalıydı: allowed=%v retryAfter=%v", allowed, retryAfter)
	}

	// 4. Farklı bir route (202) izole olmalı ve etkilenmemeli
	if otherAllowed, _ := cb.Allow(202); !otherAllowed {
		t.Fatal("route 101 açıkken route 202 etkilenmemeliydi")
	}

	// 5. Open süresi dolunca HALF-OPEN -> sadece 1 probe isteğine izin vermeli
	time.Sleep(100 * time.Millisecond)
	if ok, _ := cb.Allow(routeID); !ok {
		t.Fatal("openDuration dolduktan sonra HALF-OPEN probe isteğine izin verilmeliydi")
	}
	if ok, _ := cb.Allow(routeID); ok {
		t.Fatal("HALF-OPEN probe sürerken ikinci eşzamanlı isteğe izin verilmemeliydi")
	}

	// 6. Probe başarısız olursa tekrar OPEN olmalı
	cb.RecordFailure(routeID)
	if ok, _ := cb.Allow(routeID); ok {
		t.Fatal("başarısız probe sonrası devre tekrar OPEN olmalıydı")
	}

	// 7. Süre tekrar dolunca HALF-OPEN -> RecordSuccess ile CLOSED olmalı
	time.Sleep(100 * time.Millisecond)
	if ok, _ := cb.Allow(routeID); !ok {
		t.Fatal("ikinci HALF-OPEN probe izni verilmeliydi")
	}
	cb.RecordSuccess(routeID)
	if ok, _ := cb.Allow(routeID); !ok {
		t.Fatal("RecordSuccess sonrası devre CLOSED olmalıydı")
	}
}

func TestCircuitBreakerCancelProbe(t *testing.T) {
	cb := NewCircuitBreakerManager(1, 50*time.Millisecond)
	const routeID int64 = 303

	cb.RecordFailure(routeID) // OPEN
	time.Sleep(70 * time.Millisecond)

	// İlk probe izni alındı (halfOpenInFlight = true)
	if ok, _ := cb.Allow(routeID); !ok {
		t.Fatal("HALF-OPEN probe izni bekleniyordu")
	}

	// Probe 4xx/SSRF ile erken biterse CancelProbe kilidi açmalı
	cb.CancelProbe(routeID)

	// Yeni bir probe isteği tekrar geçebilmeli
	if ok, _ := cb.Allow(routeID); !ok {
		t.Fatal("CancelProbe sonrası yeni probe isteğine izin verilmeliydi")
	}
}
