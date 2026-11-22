package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"gowebhookmiddleware/internal/config"
	"log"
	"sort"
	"time"

	// Sürücüyü init() fonksiyonu ile database/sql paketine kaydetmek için blank identifier kullanıyoruz
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Migrate applies versioned SQL migrations in filename order.
func Migrate(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename VARCHAR(255) PRIMARY KEY,
			checksum VARCHAR(64) NOT NULL,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
	`); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		sqlBytes, err := migrationFiles.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		sum := sha256.Sum256(sqlBytes)
		checksum := hex.EncodeToString(sum[:])

		var appliedChecksum string
		err = db.QueryRowContext(ctx,
			"SELECT checksum FROM schema_migrations WHERE filename = $1",
			name,
		).Scan(&appliedChecksum)
		if err == nil {
			if appliedChecksum != checksum {
				return fmt.Errorf("migration %s checksum mismatch", name)
			}
			continue
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("check migration %s: %w", name, err)
		}

		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
		if _, err := tx.ExecContext(ctx,
			"INSERT INTO schema_migrations(filename, checksum) VALUES ($1, $2)",
			name, checksum,
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("record migration %s: %w", name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration %s: %w", name, err)
		}
		log.Printf("Migration uygulandı: %s", name)
	}
	return nil
}

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
