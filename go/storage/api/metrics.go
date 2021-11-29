package api

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var (
	storageFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_storage_failures",
			Help: "Number of storage failures.",
		},
		[]string{"call"},
	)
	storageCalls = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "oasis_storage_successes",
			Help: "Number of storage successes.",
		},
		[]string{"call"},
	)
	storageLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_storage_latency",
			Help: "Storage call latency (seconds).",
		},
		[]string{"call"},
	)
	storageValueSize = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "oasis_storage_value_size",
			Help: "Storage call value size (bytes).",
		},
		[]string{"call"},
	)

	storageCollectors = []prometheus.Collector{
		storageFailures,
		storageCalls,
		storageLatency,
		storageValueSize,
	}

	labelApply           = prometheus.Labels{"call": "apply"}
	labelSyncGet         = prometheus.Labels{"call": "sync_get"}
	labelSyncGetPrefixes = prometheus.Labels{"call": "sync_get_prefixes"}
	labelSyncIterate     = prometheus.Labels{"call": "sync_iterate"}

	metricsOnce sync.Once
)

type metricsWrapper struct {
	Backend
}

func (w *metricsWrapper) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	start := time.Now()
	res, err := w.Backend.SyncGet(ctx, request)
	storageLatency.With(labelSyncGet).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelSyncGet).Inc()
		return nil, err
	}

	storageCalls.With(labelSyncGet).Inc()
	return res, err
}

func (w *metricsWrapper) SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error) {
	start := time.Now()
	res, err := w.Backend.SyncGetPrefixes(ctx, request)
	storageLatency.With(labelSyncGetPrefixes).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelSyncGetPrefixes).Inc()
		return nil, err
	}

	storageCalls.With(labelSyncGetPrefixes).Inc()
	return res, err
}

func (w *metricsWrapper) SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error) {
	start := time.Now()
	res, err := w.Backend.SyncIterate(ctx, request)
	storageLatency.With(labelSyncIterate).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelSyncIterate).Inc()
		return nil, err
	}

	storageCalls.With(labelSyncIterate).Inc()
	return res, err
}

type localMetricsWrapper struct {
	metricsWrapper
}

func (w *metricsWrapper) Apply(ctx context.Context, request *ApplyRequest) error {
	start := time.Now()
	err := w.Backend.(LocalBackend).Apply(ctx, request)
	storageLatency.With(labelApply).Observe(time.Since(start).Seconds())

	var size int
	for _, entry := range request.WriteLog {
		size += len(entry.Key) + len(entry.Value)
	}
	storageValueSize.With(labelApply).Observe(float64(size))
	if err != nil {
		storageFailures.With(labelApply).Inc()
		return err
	}

	storageCalls.With(labelApply).Inc()
	return nil
}

func (w *localMetricsWrapper) Checkpointer() checkpoint.CreateRestorer {
	return w.Backend.(LocalBackend).Checkpointer()
}

func (w *localMetricsWrapper) NodeDB() NodeDB {
	return w.Backend.(LocalBackend).NodeDB()
}

type clientMetricsWrapper struct {
	metricsWrapper
}

func (w *clientMetricsWrapper) GetConnectedNodes() []*node.Node {
	return w.Backend.(ClientBackend).GetConnectedNodes()
}

func (w *clientMetricsWrapper) EnsureCommitteeVersion(ctx context.Context, version int64) error {
	return w.Backend.(ClientBackend).EnsureCommitteeVersion(ctx, version)
}

func NewMetricsWrapper(base Backend) Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageCollectors...)
	})

	w := metricsWrapper{Backend: base}

	switch base.(type) {
	case LocalBackend:
		return &localMetricsWrapper{w}
	case ClientBackend:
		return &clientMetricsWrapper{w}
	default:
		return &w
	}
}
