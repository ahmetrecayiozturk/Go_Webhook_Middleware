package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CounterVec: Yalnızca artan toplam sayılar (route_slug + status)
	WebhooksReceivedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webhook_received_total",
			Help: "Gelen toplam webhook isteği sayısı",
		},
		[]string{"route_slug", "status"},
	)

	// CounterVec: Worker pool tarafından işlenen event sayıları (route_slug + status)
	WebhooksProcessedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "webhook_processed_total",
			Help: "Worker pool tarafından işlenen toplam event sayısı",
		},
		[]string{"route_slug", "status"},
	)

	// Gauge: Anlık artıp azalabilen kuyruk derinliği
	QueueDepth = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "webhook_queue_depth",
			Help: "Worker kanalında anlık bekleyen event sayısı",
		},
	)

	// HistogramVec: Hedef ERP teslimat sürelerinin bucket dağılımı (route_slug)
	ERPDeliveryDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "webhook_erp_delivery_duration_seconds",
			Help:    "Hedefe yapılan HTTP teslimatlarının süre dağılımı",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route_slug"},
	)
)