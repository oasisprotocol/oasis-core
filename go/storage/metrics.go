package storage

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/storage/api"
)

var (
	storageFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_storage_failures",
			Help: "Number of storage failures.",
		},
		[]string{"call"},
	)
	storageGetCalls = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_get_calls",
			Help: "Number of successful storage get calls.",
		},
	)
	storageGetLatency = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "ekiden_storage_get_latency",
			Help: "Storage get latency (sec).",
		},
	)
	storageInsertCalls = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_insert_calls",
			Help: "Number of successful storage insert calls.",
		},
	)
	storageInsertLatency = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "ekiden_storage_insert_latency",
			Help: "Storage insert latency (sec).",
		},
	)
	storageGetKeysCalls = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_get_keys_calls",
			Help: "Number of successful storage get_keys calls.",
		},
	)
	storageGetKeysLatency = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "ekiden_storage_get_keys_latency",
			Help: "Storage get_keys latency (sec).",
		},
	)

	storageCollectors = []prometheus.Collector{
		storageFailures,
		storageGetCalls,
		storageGetLatency,
		storageInsertCalls,
		storageInsertLatency,
		storageGetKeysCalls,
		storageGetKeysLatency,
	}

	_ api.Backend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	api.Backend
}

func (w *metricsWrapper) Get(ctx context.Context, key api.Key) ([]byte, error) {
	start := time.Now()
	value, err := w.Backend.Get(ctx, key)
	storageGetLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(prometheus.Labels{"call": "get"}).Inc()
		return nil, err
	}

	storageGetCalls.Inc()
	return value, err
}

func (w *metricsWrapper) Insert(ctx context.Context, value []byte, expiration uint64) error {
	start := time.Now()
	err := w.Backend.Insert(ctx, value, expiration)
	storageInsertLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(prometheus.Labels{"call": "insert"}).Inc()
		return err
	}

	storageInsertCalls.Inc()
	return err
}

func (w *metricsWrapper) GetKeys(ctx context.Context) ([]*api.KeyInfo, error) {
	start := time.Now()
	kiVec, err := w.Backend.GetKeys(ctx)
	storageGetKeysLatency.Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(prometheus.Labels{"call": "get_keys"}).Inc()
		return nil, err
	}

	storageGetKeysCalls.Inc()
	return kiVec, err
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageCollectors...)
	})

	return &metricsWrapper{Backend: base}
}
