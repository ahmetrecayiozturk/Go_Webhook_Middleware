package config

import (
	"errors"
	"log"
	"os"
	"strconv"
)

type Config struct {
	ServerPort                   string
	DatabaseDSN                  string
	RedisURL                     string
	SlackAlertWebhookUrl         string
	AdminAPIKey                  string
	EncryptionKey                string // 64 hex karakter (32 byte AES-256)
	WorkerCount                  int
	BatchSize                    int
	AllowPrivateTargets          bool
	AllowUnauthenticatedIngest   bool
	RequireHTTPSTargets          bool
	DB_MAX_OPEN_CONNS            int
	DB_MAX_IDLE_CONNS            int
	DB_CONN_MAX_LIFETIME_MINUTES int
}

func Load() (*Config, error) {
	workerCount := parsePositiveInt(os.Getenv("WORKER_COUNT"), 100)
	batchSize := parsePositiveInt(os.Getenv("BATCH_SIZE"), 50)
	databaseDSN := os.Getenv("DATABASE_DSN")
	if databaseDSN == "" {
		return nil, errors.New("DATABASE_DSN environment variable is not set")
	}

	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		return nil, errors.New("REDIS_URL environment variable is not set")
	}

	adminAPIKey := os.Getenv("ADMIN_API_KEY")
	if adminAPIKey == "" {
		return nil, errors.New("ADMIN_API_KEY environment variable is not set")
	}

	encryptionKey := os.Getenv("ENCRYPTION_KEY")
	if encryptionKey == "" {
		return nil, errors.New("ENCRYPTION_KEY environment variable is not set (64 hex chars required)")
	}

	slackAlertWebhookUrl := os.Getenv("SLACK_ALERT_WEBHOOK_URL")
	if slackAlertWebhookUrl == "" {
		log.Println("UYARI: SLACK_ALERT_WEBHOOK_URL tanımlı değil, DLQ Slack bildirimleri devre dışı.")
	}

	allowPrivateTargets := os.Getenv("ALLOW_PRIVATE_TARGETS")
	if allowPrivateTargets != "true" && allowPrivateTargets != "false" {
		log.Println("UYARI: ALLOW_PRIVATE_TARGETS environment variable is not set to 'true' or 'false'. Defaulting to 'false'.")
	}
	allowUnauthenticatedIngest := os.Getenv("ALLOW_UNAUTHENTICATED_INGEST") == "true"
	requireHTTPSTargets := os.Getenv("REQUIRE_HTTPS_TARGETS")
	if requireHTTPSTargets == "" {
		requireHTTPSTargets = "true"
	}
	if requireHTTPSTargets != "true" && requireHTTPSTargets != "false" {
		log.Println("UYARI: REQUIRE_HTTPS_TARGETS environment variable is not true veya false. Varsayilan olarak true kullaniliyor.")
		requireHTTPSTargets = "true"
	}

	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = "8080"
	}

	return &Config{
		ServerPort:                   serverPort,
		DatabaseDSN:                  databaseDSN,
		RedisURL:                     redisURL,
		SlackAlertWebhookUrl:         slackAlertWebhookUrl,
		AdminAPIKey:                  adminAPIKey,
		EncryptionKey:                encryptionKey,
		WorkerCount:                  workerCount,
		BatchSize:                    batchSize,
		AllowPrivateTargets:          allowPrivateTargets == "true",
		AllowUnauthenticatedIngest:   allowUnauthenticatedIngest,
		RequireHTTPSTargets:          requireHTTPSTargets == "true",
		DB_MAX_OPEN_CONNS:            parsePositiveInt(os.Getenv("DB_MAX_OPEN_CONNS"), 25),
		DB_MAX_IDLE_CONNS:            parsePositiveInt(os.Getenv("DB_MAX_IDLE_CONNS"), 25),
		DB_CONN_MAX_LIFETIME_MINUTES: parsePositiveInt(os.Getenv("DB_CONN_MAX_LIFETIME_MINUTES"), 5),
	}, nil
}

func parsePositiveInt(val string, fallback int) int {
	n, err := strconv.Atoi(val)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}
