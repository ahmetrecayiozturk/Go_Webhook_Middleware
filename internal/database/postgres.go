package database

import (
	"context"
	"database/sql"
	"fmt"
	"gowebhookmiddleware/internal/config"
	"log"
	"time"

	// Sürücüyü init() fonksiyonu ile database/sql paketine kaydetmek için blank identifier kullanıyoruz
	_ "github.com/jackc/pgx/v5/stdlib"
)

// NewPostgresDB, PostgreSql connection pool oluşturur ve döndrür.
func NewPostgresDb(cfg *config.Config) (*sql.DB, error) {
	db, err := sql.Open("pgx", cfg.DatabaseDSN)
	if err != nil {
		log.Printf("Db oluşturulken hata çıktı: %v", err)
		return nil, fmt.Errorf("Db oluşturulma hatası: %w", err)
	}

	// Bu değerler sistemin RAM/CPU kapasitesine ve veritabanı sunucusuna göre optimize edilmelidir.
	db.SetMaxOpenConns(cfg.DB_MAX_OPEN_CONNS)                                               // Aynı anda açılabilecek maksimum bağlantı sayısı
	db.SetMaxIdleConns(cfg.DB_MAX_IDLE_CONNS)                                               // Aynı anda açık kalabilecek maksimum boşta bağlantı sayısı
	db.SetConnMaxLifetime(time.Duration(cfg.DB_CONN_MAX_LIFETIME_MINUTES*60) * time.Second) // Bağlantının maksimum ömrü
	db.SetConnMaxIdleTime(time.Duration(cfg.DB_CONN_MAX_LIFETIME_MINUTES*60) * time.Second) // Boşta kalan bağlantının maksimum ömrü

	// Veritabanı bağlantısını test edelim
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("Veritabanına bağlanılamadı: %w", err)
	}

	return db, nil
}
