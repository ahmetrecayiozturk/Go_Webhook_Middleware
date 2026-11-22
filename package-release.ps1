param(
    [string]$Version = "v1.0.0"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Get-Location
$DistDir = Join-Path $ProjectRoot "dist"
$StagingDir = Join-Path $env:TEMP "GoWebhookMiddleware-$Version"
$ZipPath = Join-Path $DistDir "GoWebhookMiddleware-$Version.zip"

# Temizlik
if (Test-Path $StagingDir) { Remove-Item -Recurse -Force $StagingDir }
if (-not (Test-Path $DistDir)) { New-Item -ItemType Directory -Path $DistDir | Out-Null }
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
New-Item -ItemType Directory -Path $StagingDir | Out-Null

# Teslimata dahil edilecek klasör ve dosyalar (demo-studio ve .env HARİÇ)
$IncludeItems = @(
    "cmd", "internal", "nginx", "grafana", "test",
    "Dockerfile", "docker-compose.prod.yml", ".env.prod.example",
    "schema.sql", "query.sql", "sqlc.yaml", "prometheus.yml",
    "go.mod", "go.sum", "README.md"
)

foreach ($item in $IncludeItems) {
    $src = Join-Path $ProjectRoot $item
    if (Test-Path $src) {
        Copy-Item -Path $src -Destination $StagingDir -Recurse -Force
    }
}

# Ekstra güvenlik: Staging içinde kazara .env veya binary kaldıysa sil
Get-ChildItem -Path $StagingDir -Recurse -Include ".env", ".env.prod", "*.exe", "*.log" | Remove-Item -Force -ErrorAction SilentlyContinue

# Zip oluştur
Compress-Archive -Path "$StagingDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal
Remove-Item -Recurse -Force $StagingDir

Write-Host "`n[OK] Temiz teslimat paketi oluşturuldu: $ZipPath" -ForegroundColor Green
Write-Host "Boyut: $([math]::Round((Get-Item $ZipPath).Length / 1KB, 2)) KB" -ForegroundColor Cyan