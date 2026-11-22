# GoWebhookMiddleware — Multi-Tenant Webhook Ingest & Delivery Gateway

Yüksek trafikli e-ticaret, ödeme ve SaaS sistemlerinden (**Stripe, Shopify, iyzico, PayTR, GitHub** vb.) gelen webhook'ları kalıcı outbox üzerinde doğrulayan, at-least-once teslimatla hedef ERP/backend sistemlerine güvenilir şekilde ileten **multi-instance Go webhook ara katmanı**.

---

## Mimari Genel Bakış

```text
                        ┌──────────────────────┐
  Webhook İsteği  ─────►│     Nginx (80/443)   │  • Keep-Alive Upstream
  /api/v1/ingest/{slug} │    Reverse Proxy     │  • 1MB Body Limiti & IP Koruması
  /admin (Control UI)   └──────────┬───────────┘  • /metrics Dış Erişime Kapalı (403)
                                   │
                                   ▼
                        ┌──────────────────────┐      ┌──────────────────────────┐
                        │  Go App (8080) x N   │◄────►│       Redis 7 (6379)     │
                        │   (Internal Only)    │      │ • Route Config Cache     │
                        │ • Provider Verifiers │      │ • Route Bazlı Rate Limit │
                        │ • Tenant Key (whk_)  │      │ • Idempotency (SetNX)    │
                        │ • AES-256-GCM Crypto │      │ • Aylık Kota Sayaçları   │
                        │ • Embedded Admin UI  │      │ • Dağıtık Circuit Breaker│
                        └──────────┬───────────┘      │   (Atomik Lua Scripts)   │
                                   │                  └──────────────────────────┘
                                   ▼
                        ┌──────────────────────┐      ┌──────────────────────────┐
                        │  PostgreSQL 16 (5432)│      │     Prometheus (9090)    │
                        │ • tenants / routes   │      │  /metrics Scrape (route) │
                        │ • outbox_events      │      └────────────┬─────────────┘
                        │ • delivery_attempts  │                   │
                        │ • dead_letter_queue  │                   ▼
                        └──────────┬───────────┘      ┌──────────────────────────┐
                                   │                  │      Grafana (3000)      │
                           Worker Pool (Go)           │  Auto-Provisioned        │
                     (FOR UPDATE SKIP LOCKED +        │  route_slug Filtreli     │
                      BATCH_SIZE=50 + Redis CB)       │  Production Dashboard    │
                                   │                  └──────────────────────────┘
                                   │  • SSRF & Redirect Engeli (IPv4 Öncelikli)
                                   │  • Outgoing HMAC-SHA256 İmzası
                                   ▼
                        ┌──────────────────────┐
                        │    Hedef ERP API     │
                        └──────────────────────┘
```

---

## Temel Özellikler

* **Multi-Tenant & IDOR İzolasyonu:** Her müşteri (`tenant`) için tek seferlik `whk_...` API anahtarı (DB'de SHA-256 hash) üretilir. Müşteriler kendi anahtarlarıyla yalnızca kendi route, teslimat denemeleri ve DLQ kayıtlarını yönetebilir; başka tenant kaynaklarına erişim `403 Forbidden`, süper admin uçlarına erişim `401 Unauthorized` ile engellenir.
* **Aylık Event Kotası (`monthly_event_quota`):** Redis üzerinden tenant bazlı aylık kota zorlanır (`X-Quota-Limit`, `X-Quota-Used`). Mükerrer (duplicate) istekler kota harcamaz; limit aşımında `429 Too Many Requests` dönülür ve DB hatalarında sayaç geri alınır.
* **Transactional Outbox & Ölçeklenebilir Worker Pool:** Gelen event'ler Redis idempotency kontrolünden geçip PostgreSQL `outbox_events` tablosuna yazılır. Worker pool, yapılandırılabilir `BATCH_SIZE` (varsayılan `50`) ve `FOR UPDATE SKIP LOCKED` ile race-condition olmadan paralel tüketir. Teslimat semantiği at-least-once'dır; hedef sistem `X-Webhook-Event-Id` ile duplicate teslimatı idempotent biçimde ele almalıdır.
* **Dağıtık (Multi-Instance) Circuit Breaker:** Redis Lua script'leri ile tüm Go instance'ları arasında atomik çalışır. Arka arkaya 5 adet 5xx/timeout hatasında ilgili rotanın devresini 60 saniye `OPEN` yapar, event'lerin retry hakkını tüketmeden erteler ve `HALF-OPEN` modunda 15 saniyelik kendi kendini çözen probe kilidiyle tek test isteği gönderir. Redis kesintisinde otomatik in-memory fallback devreye girer.
* **Yerleşik Sağlayıcı Doğrulayıcıları:** `stripe` (5 dk replay korumalı), `shopify`, `iyzico` (V3), `paytr` (düz metin `OK` ACK destekli), `generic_hmac` ve `none`.
* **Akıllı Retry & Dead Letter Queue (DLQ):**
  * `5xx`, `408`, `429` ve ağ hatalarında jitter'lı **Exponential Backoff** ile yeniden dener.
  * Kalıcı `3xx/4xx` hatalarında veya maksimum deneme aşımında event'i `dead_letter_queue` tablosuna taşır ve opsiyonel Slack uyarısı gönderir.
* **Üretim Güvenliği:**
  * Tüm secret ve hedef auth header'ları veritabanında **AES-256-GCM** ile şifreli saklanır.
  * **SSRF & DNS Rebinding Koruması:** Özel/yerel ağ IP'lerine bağlantı engellenir, IPv4 öncelikli bağlantı kurulur ve `3xx` yönlendirmeleri takip edilmez.
  * **Çıkış İmzası (Outgoing Signature):** Hedef ERP'ye giden her istek `HMAC-SHA256` ile imzalanır.
* **Gömülü Control Plane Paneli (`/admin`):** Tek Go binary'si içine gömülü (`embed.FS`), harici CDN bağımlılığı olmayan yönetim arayüzü (Tenant/Route CRUD, `delivery_attempts` 2KB response snippet inceleme, toplu DLQ Replay).
* **Graceful Shutdown & Otomatik Bakım:** `SIGINT`/`SIGTERM` sinyallerinde aktif istek ve worker'ları veri kaybı olmadan tamamlar. `Sweeper` 5 dk'dan uzun `PROCESSING` kalan yetim kayıtları kurtarır; `RetentionSweeper` 30 günden eski kayıtları 1000'erli batch'ler halinde temizler.

---

## Teknoloji Yığını

| Katman | Teknoloji |
|---|---|
| **Backend** | Go, `net/http`, SQLC, `embed.FS` |
| **Veritabanı** | PostgreSQL 16 (`alpine`) |
| **Önbellek, Kota & Dağıtık CB** | Redis 7 (`alpine`, AOF aktif, Lua scripts) |
| **Reverse Proxy** | Nginx 1.27 (`alpine`) |
| **İzleme & Metrik** | Prometheus, Grafana |
| **Altyapı** | Docker & Docker Compose |

---

## Kurulum ve Çalıştırma

### Production Kurulumu

### Database Migration'ları

Uygulama başlangıcında `internal/database/migrations/*.sql` dosyalarını checksum kontrolüyle sırayla uygular. Yeni migration eklenirken yalnızca yeni, artımlı dosya ekleyin; eski dosyaların içeriğini değiştirmeyin. Docker Compose ilk açılışta `schema.sql` üzerinden tablo altyapısını da oluşturur.

1. Ortam değişkenlerini hazırlayın:
```bash
cp .env.prod.example .env.prod
```

2. Güçlü anahtarlar üretip `.env.prod` içine yazın:
```bash
# 32-byte AES-256-GCM master key (64 hex karakter)
openssl rand -hex 32

# Admin Control Plane API Key
openssl rand -hex 24
```

3. Production stack'i başlatın:
```bash
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

> **Ağ İzolasyonu:** `docker-compose.prod.yml` yapılandırmasında PostgreSQL, Redis ve Prometheus portları dış internete kapalıdır. Grafana yalnızca `127.0.0.1:3000` üzerinden erişilebilir (SSH tüneli veya VPN ile erişin).

### Temel Ortam Değişkenleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SERVER_PORT` | `8080` | Go HTTP sunucu portu (internal) |
| `DATABASE_DSN` | *(zorunlu)* | PostgreSQL bağlantı adresi |
| `REDIS_URL` | *(zorunlu)* | Redis bağlantı adresi |
| `ADMIN_API_KEY` | *(zorunlu)* | Süper admin Control Plane anahtarı |
| `ENCRYPTION_KEY` | *(zorunlu)* | 64 hex karakterlik AES-256-GCM anahtarı |
| `WORKER_COUNT` | `100` | Eşzamanlı worker goroutine sayısı |
| `BATCH_SIZE` | `50` | `FetchPendingOutboxEvents` batch boyutu |
| `ALLOW_PRIVATE_TARGETS` | `false` | Özel/yerel ağ IP'lerine SSRF izni |
| `SLACK_ALERT_WEBHOOK_URL` | *(opsiyonel)* | DLQ bildirimleri için Slack Webhook URL |

### Servis Erişim Adresleri

| Servis | Adres | Not |
|---|---|---|
| **Webhook API (Nginx)** | `http://localhost` | Tüm dış trafik bu kapıdan geçer |
| **Control Plane UI** | `http://localhost/admin` | `X-API-KEY` ile bağlanılır |
| **Health Check** | `http://localhost/api/v1/health` | `200 OK` döner |
| **Prometheus** | `http://localhost:9090` | Local modda açık, prod'da internal |
| **Grafana** | `http://127.0.0.1:3000` | Auto-provisioned dashboard |

> **Güvenlik Notu:** `http://localhost/metrics` adresi Nginx tarafından dış dünyaya kapatılmıştır (`403 Forbidden`). Prometheus, Docker iç ağı üzerinden doğrudan `app:8080/metrics` adresini tarar.

---

## Yönetim Paneli & Control Plane API

Tarayıcıdan **`http://<sunucu-adresi>/admin`** adresine gidin ve `ADMIN_API_KEY` ile bağlanın. Tüm `/api/v1/admin/*` uç noktaları `X-API-KEY` header'ı ile korunur:

| Metod | Endpoint | Yetki | Açıklama |
|---|---|---|---|
| `POST` | `/api/v1/admin/tenants` | Süper Admin | Yeni tenant oluşturur, tek seferlik `whk_...` API key döner |
| `GET` | `/api/v1/admin/tenants` | Süper Admin | Tenant listesini döner |
| `POST` | `/api/v1/admin/routes` | Admin / Tenant | Yeni webhook rotası oluşturur (secret'lar şifrelenir) |
| `GET` | `/api/v1/admin/routes?tenant_id=1` | Admin / Tenant | Tenant'a ait rotaları listeler |
| `PUT` | `/api/v1/admin/routes/{id}` | Admin / Tenant | Rotayı günceller ve Redis cache'ini anında temizler |
| `DELETE` | `/api/v1/admin/routes/{id}` | Admin / Tenant | Rotayı siler ve cache'i temizler |
| `GET` | `/api/v1/admin/attempts?route_id=1&event_id=...` | Admin / Tenant | Son teslimat denemelerini ve 2KB response snippet'larını listeler |
| `GET` | `/api/v1/admin/dlq?tenant_id=1&route_id=1` | Admin / Tenant | Dead Letter Queue kayıtlarını filtreli listeler |
| `POST` | `/api/v1/admin/replay-dlq` | Admin / Tenant | Seçilen `dlq_ids` kayıtlarını atomik olarak tekrar kuyruğa alır |

### Örnek: Yeni Route Oluşturma

```bash
curl -X POST http://localhost/api/v1/admin/routes \
  -H "Content-Type: application/json" \
  -H "X-API-KEY: $ADMIN_API_KEY" \
  -d '{
    "tenant_id": 1,
    "route_slug": "acme-iyzico-prod",
    "provider_type": "iyzico",
    "signing_secret": "IYZICO_SECRET_KEY",
    "outgoing_secret": "ERP_PAYLASILAN_GIZLI_ANAHTAR",
    "target_url": "https://erp.acme.com/api/webhooks/payments",
    "target_headers": {
      "Authorization": "Bearer ERP_INTERNAL_TOKEN"
    },
    "rate_limit_per_sec": 200,
    "max_retries": 5
  }'
```

Oluşturulan rotanın webhook alım adresi:
`POST https://<domain>/api/v1/ingest/acme-iyzico-prod`

---

## Sağlayıcı Entegrasyon Rehberi

| `provider_type` | Doğrulanan Header / Alan | `signing_secret` Formatı | ACK Yanıtı |
|---|---|---|---|
| `stripe` | `Stripe-Signature` (`t=...,v1=...`) + 5 dk replay kontrolü | `whsec_...` | `200 JSON` |
| `shopify` | `X-Shopify-Hmac-Sha256` (Base64 HMAC-SHA256) | Shopify Webhook Secret | `200 JSON` |
| `iyzico` | `X-IYZ-SIGNATURE-V3` (Hex HMAC-SHA256) | iyzico `secretKey` | `200 JSON` |
| `paytr` | Form body `hash` alanı (`application/x-www-form-urlencoded`) | `<merchant_key>:<merchant_salt>` | `200 OK` (düz metin) |
| `generic_hmac` | `X-Webhook-Signature` veya `X-Hub-Signature-256` (`sha256=<hex>`) | Paylaşılan HMAC secret | `200 JSON` |
| `none` | Doğrulama yapılmaz (yalnızca test/iç ağ) | Boş bırakılabilir | `200 JSON` |

> **PayTR Notu:** PayTR bildirimlerinin başarılı sayılması için `signing_secret` mutlaka `merchant_key:merchant_salt` formatında girilmelidir. Sistem PayTR'nin zorunlu kıldığı düz metin `OK` yanıtını otomatik döner.

---

## Hedef ERP Tarafında Çıkış İmzasını Doğrulama

Middleware, hedef ERP'ye gönderdiği her istekte şu header'ları ekler:

* `X-Webhook-Event-Id`: Sağlayıcıdan çıkarılan benzersiz event ID
* `X-Webhook-Event-Type`: Event tipi (örn. `order.created`, `paytr.success`)
* `X-Webhook-Timestamp`: Unix saniye zaman damgası
* `X-Webhook-Signature`: `v1=<hex>` formatında `HMAC-SHA256(outgoing_secret, "<timestamp>.<raw_body>")`

### Node.js (Express) Örneği

```js
const crypto = require("crypto");

function verifyWebhook(req, res, next) {
  const secret = process.env.WEBHOOK_OUTGOING_SECRET;
  const ts = req.header("X-Webhook-Timestamp");
  const sig = req.header("X-Webhook-Signature"); // "v1=..."

  if (!ts || !sig) return res.status(401).send("Missing signature");

  // 5 dakikalık replay attack koruması
  if (Math.abs(Math.floor(Date.now() / 1000) - Number(ts)) > 300) {
    return res.status(401).send("Timestamp expired");
  }

  // req.rawBody ham Buffer olmalıdır (express.raw ile alın)
  const expected =
    "v1=" +
    crypto
      .createHmac("sha256", secret)
      .update(`${ts}.`)
      .update(req.rawBody)
      .digest("hex");

  const valid =
    expected.length === sig.length &&
    crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig));

  if (!valid) return res.status(401).send("Invalid signature");
  next();
}
```

### Go Örneği

```go
func VerifyOutgoingSignature(rawBody []byte, secret, tsHeader, sigHeader string) bool {
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil || math.Abs(float64(time.Now().Unix()-ts)) > 300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(tsHeader))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	expected := "v1=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(sigHeader))
}
```

---

## Gözlemlenebilirlik (Prometheus & Grafana)

Grafana ayağa kalktığında `grafana/provisioning` altındaki **Webhook Middleware — Production Overview** panosunu otomatik yükler. Üstteki `Route` (`$route_slug`) filtresiyle tüm metrikler rota bazlı izlenebilir:

| Panel | PromQL Sorgusu |
|---|---|
| **Saniyelik Gelen Webhook (RPS)** | `sum by (route_slug, status) (rate(webhook_received_total{route_slug=~"$route_slug"}[1m]))` |
| **Worker Teslimat Sonuçları** | `sum by (route_slug, status) (rate(webhook_processed_total{route_slug=~"$route_slug"}[1m]))` |
| **Hedef ERP Gecikmesi (P95)** | `histogram_quantile(0.95, sum by (le, route_slug) (rate(webhook_erp_delivery_duration_seconds_bucket{route_slug=~"$route_slug"}[5m])))` |
| **Anlık Kuyruk Derinliği** | `webhook_queue_depth` |
| **DLQ & Circuit Breaker** | `sum(increase(webhook_processed_total{route_slug=~"$route_slug", status=~"dlq|circuit_open"}[1h]))` |

---

## Testler ve Yük Testi

```bash
# 1. Birim testleri (Provider doğrulayıcıları & Circuit Breaker)
go test -v ./internal/...

# 2. Data race kontrolü ile birim testleri (Docker üzerinden)
docker run --rm -v "${PWD}:/app" -w /app golang:1.26.1 go test -v -race ./internal/...

# 3. Uçtan uca (E2E) entegrasyon testleri — 8 senaryo (cache'siz)
go test -v -count=1 ./test/e2e/...
```

### Yük Testi ve Mock ERP

```bash
# 1. Terminal — Mock ERP Sunucusu (%10 hata, 50-250ms gecikme)
go run ./test/erp_test/mock_erp.go

# 2. Terminal — Eşzamanlı Yük Testi
ROUTE_SLUG=demo-studio-route go run ./test/load_test/loadtest.go
```