package database

import (
	"context"
	"fmt"
	"gowebhookmiddleware/internal/config"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

// NewRedisClient, Redis bağlantısını oluşturur ve doğrular.
func NewRedisClient(cfg *config.Config) (*redis.Client, error) {
	// Redis urlsindeki optionları parse ediyoruz burada
	opts, err := redis.ParseURL(cfg.RedisURL)

	if err != nil {
		log.Printf("Redis URL parse edilirken hata çıktı: %v", err)
		return nil, fmt.Errorf("Redis URL parse edilirken hata çıktı: %w", err)
	}
	// Optionsları ayarlıyoruz
	opts.PoolSize = cfg.WorkerCount // Pool boyutunu config üzerinden gelen workercounta göre ayarlayabiliriz
	opts.MinIdleConns = 10          // Minimum boşta bağlantı sayısı

	// Şimdi bu özellikler ile redis clienti oluşturuyoruz
	client := redis.NewClient(opts)

	// Redis bağlantısını test edelim, çok yazdım ama bi daha yazıcam, bu background boş context, bunula max 5 saniye beklenecek şekilde ayarlıyoruz contexti
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("Redis'e bağlanılamadı: %w", err)
	}

	return client, nil

}
