package main

import (
	"context"
	"errors"
	"gowebhookmiddleware/internal/cache"
	"gowebhookmiddleware/internal/config"
	"gowebhookmiddleware/internal/crypto"
	"gowebhookmiddleware/internal/database"
	"gowebhookmiddleware/internal/queue"
	"gowebhookmiddleware/internal/repository/postgres/sqlc_gen"
	"gowebhookmiddleware/internal/server"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Config yüklenirken hata: %v", err)
	}

	cipher, err := crypto.NewCipher(cfg.EncryptionKey)
	if err != nil {
		log.Fatalf("Crypto başlatılamadı: %v", err)
	}

	db, err := database.NewPostgresDb(cfg)
	if err != nil {
		log.Fatalf("PostgreSQL bağlantısı kurulamadı: %v", err)
	}
	if err := database.Migrate(db); err != nil {
		_ = db.Close()
		log.Fatalf("Veritabanı migration'ları uygulanamadı: %v", err)
	}

	redisClient, err := database.NewRedisClient(cfg)
	if err != nil {
		log.Fatalf("Redis bağlantısı kurulamadı: %v", err)
	}

	queries := sqlc_gen.New(db)
	routeCache := cache.NewRouteCache(redisClient, queries)
	webhookHandler := server.NewWebhookHandler(db, redisClient, queries, routeCache, cipher)
	router := server.NewRouter(webhookHandler, cfg.AdminAPIKey)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	workerPool := queue.NewWorkerPool(queries, cfg, cipher, redisClient)
	workerPool.Start(ctx)

	serv := &http.Server{
		Addr:              ":" + cfg.ServerPort,
		Handler:           router,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		log.Printf("HTTP sunucusu :%s portunda dinliyor...", cfg.ServerPort)
		if err := serv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP sunucusu hatası: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Kapatma sinyali alındı, graceful shutdown başlıyor...")

	httpShutdownCtx, httpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer httpCancel()
	if err := serv.Shutdown(httpShutdownCtx); err != nil {
		log.Printf("HTTP shutdown hatası: %v", err)
	}

	workerShutdownCtx, workerCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer workerCancel()
	if err := workerPool.Wait(workerShutdownCtx); err != nil {
		log.Printf("Worker shutdown hatası: %v", err)
	}

	_ = db.Close()
	_ = redisClient.Close()
	log.Println("Servisler güvenli şekilde kapatıldı.")
}
