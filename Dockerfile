# --- 1. AŞAMA: BUILDER ---
FROM golang:1.26.1-alpine AS builder

WORKDIR /app

# Bağımlılıkları önce kopyala (Docker layer cache optimizasyonu)
COPY go.mod go.sum ./
RUN go mod download

# Tüm kaynak kodu kopyala ve statik binary derle
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-w -s" -o /app/webhook-server ./cmd/server

# --- 2. Runtime Stage ---
FROM alpine:3.21

# HTTPS (ERP/Slack) sertifikaları ve saat dilimi desteği
RUN apk --no-cache add ca-certificates tzdata

# Güvenlik: Root olmayan kullanıcı oluştur
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app
COPY --from=builder /app/webhook-server .

USER appuser

EXPOSE 8080

ENTRYPOINT ["./webhook-server"]