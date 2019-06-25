package storage

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
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

	labelApply      = prometheus.Labels{"call": "apply"}
	labelApplyBatch = prometheus.Labels{"call": "apply_batch"}
	labelGetSubtree = prometheus.Labels{"call": "get_subtree"}
	labelGetPath    = prometheus.Labels{"call": "get_path"}
	labelGetNode    = prometheus.Labels{"call": "get_node"}
	labelGetValue   = prometheus.Labels{"call": "get_value"}

	_ api.Backend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	api.Backend
}

func (w *metricsWrapper) Apply(ctx context.Context, root hash.Hash, expectedNewRoot hash.Hash, log api.WriteLog) ([]*api.MKVSReceipt, error) {
	start := time.Now()
	receipts, err := w.Backend.Apply(ctx, root, expectedNewRoot, log)
	storageLatency.With(labelApply).Observe(time.Since(start).Seconds())

	var size int
	for _, entry := range log {
		size += len(entry.Key) + len(entry.Value)
	}
	storageValueSize.With(labelApply).Observe(float64(size))
	if err != nil {
		storageFailures.With(labelApply).Inc()
		return nil, err
	}

	storageCalls.With(labelApply).Inc()
	return receipts, err
}

func (w *metricsWrapper) ApplyBatch(ctx context.Context, ops []api.ApplyOp) ([]*api.MKVSReceipt, error) {
	start := time.Now()
	receipts, err := w.Backend.ApplyBatch(ctx, ops)
	storageLatency.With(labelApplyBatch).Observe(time.Since(start).Seconds())

	var size int
	for _, op := range ops {
		for _, entry := range op.WriteLog {
			size += len(entry.Key) + len(entry.Value)
		}
	}
	storageValueSize.With(labelApplyBatch).Observe(float64(size))
	if err != nil {
		storageFailures.With(labelApplyBatch).Inc()
		return nil, err
	}

	storageCalls.With(labelApplyBatch).Inc()
	return receipts, err
}

func (w *metricsWrapper) GetSubtree(ctx context.Context, root hash.Hash, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	start := time.Now()
	st, err := w.Backend.GetSubtree(ctx, root, id, maxDepth)
	storageLatency.With(labelGetSubtree).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelGetSubtree).Inc()
		return nil, err
	}

	storageCalls.With(labelGetSubtree).Inc()
	return st, err
}

func (w *metricsWrapper) GetPath(ctx context.Context, root hash.Hash, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	start := time.Now()
	st, err := w.Backend.GetPath(ctx, root, key, startDepth)
	storageLatency.With(labelGetPath).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelGetPath).Inc()
		return nil, err
	}

	storageCalls.With(labelGetPath).Inc()
	return st, err
}

func (w *metricsWrapper) GetNode(ctx context.Context, root hash.Hash, id api.NodeID) (api.Node, error) {
	start := time.Now()
	node, err := w.Backend.GetNode(ctx, root, id)
	storageLatency.With(labelGetNode).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelGetNode).Inc()
		return nil, err
	}

	storageCalls.With(labelGetNode).Inc()
	return node, err
}

func (w *metricsWrapper) GetValue(ctx context.Context, root hash.Hash, id hash.Hash) ([]byte, error) {
	start := time.Now()
	value, err := w.Backend.GetValue(ctx, root, id)
	storageLatency.With(labelGetValue).Observe(time.Since(start).Seconds())
	storageValueSize.With(labelGetValue).Observe(float64(len(value)))
	if err != nil {
		storageFailures.With(labelGetValue).Inc()
		return nil, err
	}

	storageCalls.With(labelGetValue).Inc()
	return value, err
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageCollectors...)
	})

	w := &metricsWrapper{Backend: base}

	return w
}
