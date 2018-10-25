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
	storageCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ekiden_storage_successes",
			Help: "Number of storage successes.",
		},
		[]string{"call"},
	)
	storageLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_storage_latency",
			Help: "Storage call latency",
		},
		[]string{"call"},
	)
	storageValueSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "ekiden_storage_value_size",
			Help: "Storage call value size",
		},
		[]string{"call"},
	)

	storageCollectors = []prometheus.Collector{
		storageFailures,
		storageCalls,
		storageLatency,
		storageValueSize,
	}

	labelGet         = prometheus.Labels{"call": "get"}
	labelGetBatch    = prometheus.Labels{"call": "get_batch"}
	labelInsert      = prometheus.Labels{"call": "insert"}
	labelInsertBatch = prometheus.Labels{"call": "insert_batch"}
	labelGetKeys     = prometheus.Labels{"call": "get_keys"}

	_ api.Backend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	api.Backend
}

func (w *metricsWrapper) Get(ctx context.Context, key api.Key) ([]byte, error) {
	start := time.Now()
	value, err := w.Backend.Get(ctx, key)
	storageLatency.With(labelGet).Observe(time.Since(start).Seconds())
	storageValueSize.With(labelGet).Observe(float64(len(value)))
	if err != nil {
		storageFailures.With(labelGet).Inc()
		return nil, err
	}

	storageCalls.With(labelGet).Inc()
	return value, err
}

func (w *metricsWrapper) GetBatch(ctx context.Context, keys []api.Key) ([][]byte, error) {
	start := time.Now()
	values, err := w.Backend.GetBatch(ctx, keys)
	storageLatency.With(labelGetBatch).Observe(time.Since(start).Seconds())

	var size int
	for _, value := range values {
		size += len(value)
	}
	storageValueSize.With(labelGetBatch).Observe(float64(size))

	if err != nil {
		storageFailures.With(labelGetBatch).Inc()
		return nil, err
	}

	storageCalls.With(labelGetBatch).Inc()
	return values, err
}

func (w *metricsWrapper) Insert(ctx context.Context, value []byte, expiration uint64) error {
	start := time.Now()
	err := w.Backend.Insert(ctx, value, expiration)
	storageLatency.With(labelInsert).Observe(time.Since(start).Seconds())
	storageValueSize.With(labelInsert).Observe(float64(len(value)))
	if err != nil {
		storageFailures.With(labelInsert).Inc()
		return err
	}

	storageCalls.With(labelInsert).Inc()
	return err
}

func (w *metricsWrapper) InsertBatch(ctx context.Context, values []api.Value) error {
	start := time.Now()
	err := w.Backend.InsertBatch(ctx, values)
	storageLatency.With(labelInsertBatch).Observe(time.Since(start).Seconds())

	var size int
	for _, value := range values {
		size += len(value.Data)
	}
	storageValueSize.With(labelInsertBatch).Observe(float64(size))

	if err != nil {
		storageFailures.With(labelInsertBatch).Inc()
		return err
	}

	storageCalls.With(labelInsertBatch).Inc()
	return err
}

func (w *metricsWrapper) GetKeys(ctx context.Context) (<-chan api.KeyInfo, error) {
	kiChan, err := w.Backend.GetKeys(ctx)
	if err != nil {
		storageFailures.With(labelGetKeys).Inc()
		return nil, err
	}

	storageCalls.With(labelGetKeys).Inc()
	return kiChan, err
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageCollectors...)
	})

	return &metricsWrapper{Backend: base}
}
