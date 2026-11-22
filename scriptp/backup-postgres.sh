#!/usr/bin/env bash
set -euo pipefail

BACKUP_DIR="/var/backups/gowebhookmiddleware"
ENV_FILE="/opt/gowebhookmiddleware/.env.prod"
RETENTION_DAYS=14
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$BACKUP_DIR"

# .env.prod içinden POSTGRES_USER ve POSTGRES_DB oku
set -a
source "$ENV_FILE"
set +a

OUT_FILE="${BACKUP_DIR}/webhook_db_${TIMESTAMP}.sql.gz"

docker exec webhook_postgres pg_dump -U "${POSTGRES_USER}" "${POSTGRES_DB:-webhook_db}" | gzip > "$OUT_FILE"
chmod 600 "$OUT_FILE"

# 14 günden eski yedekleri sil
find "$BACKUP_DIR" -type f -name "webhook_db_*.sql.gz" -mtime +${RETENTION_DAYS} -delete

echo "[OK] Yedek alındı: $OUT_FILE"