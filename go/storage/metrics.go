package storage

import (
	"context"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
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
	storagePrunedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_pruned",
			Help: "Number of pruned nodes.",
		},
	)
	storageFinalizedCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "ekiden_storage_finalized",
			Help: "Number of finalized rounds.",
		},
	)

	storageCollectors = []prometheus.Collector{
		storageFailures,
		storageCalls,
		storageLatency,
		storageValueSize,
		storagePrunedCount,
		storageFinalizedCount,
	}

	labelApply           = prometheus.Labels{"call": "apply"}
	labelApplyBatch      = prometheus.Labels{"call": "apply_batch"}
	labelMerge           = prometheus.Labels{"call": "merge"}
	labelMergeBatch      = prometheus.Labels{"call": "merge_batch"}
	labelSyncGet         = prometheus.Labels{"call": "sync_get"}
	labelSyncGetPrefixes = prometheus.Labels{"call": "sync_get_prefixes"}
	labelSyncIterate     = prometheus.Labels{"call": "sync_iterate"}
	labelHasRoot         = prometheus.Labels{"call": "has_root"}
	labelFinalize        = prometheus.Labels{"call": "finalize"}
	labelPrune           = prometheus.Labels{"call": "prune"}

	_ api.LocalBackend  = (*metricsWrapper)(nil)
	_ api.ClientBackend = (*metricsWrapper)(nil)

	metricsOnce sync.Once
)

type metricsWrapper struct {
	api.Backend
}

func (w *metricsWrapper) GetConnectedNodes() []*node.Node {
	if clientBackend, ok := w.Backend.(api.ClientBackend); ok {
		return clientBackend.GetConnectedNodes()
	}
	return []*node.Node{}
}

func (w *metricsWrapper) WatchRuntime(id signature.PublicKey) error {
	if clientBackend, ok := w.Backend.(api.ClientBackend); ok {
		return clientBackend.WatchRuntime(id)
	}
	return errors.New("storage/metricswrapper: backend not ClientBackend")
}

func (w *metricsWrapper) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) ([]*api.Receipt, error) {
	start := time.Now()
	receipts, err := w.Backend.Apply(ctx, ns, srcRound, srcRoot, dstRound, dstRoot, writeLog)
	storageLatency.With(labelApply).Observe(time.Since(start).Seconds())

	var size int
	for _, entry := range writeLog {
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

func (w *metricsWrapper) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []api.ApplyOp,
) ([]*api.Receipt, error) {
	start := time.Now()
	receipts, err := w.Backend.ApplyBatch(ctx, ns, dstRound, ops)
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

func (w *metricsWrapper) Merge(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	base hash.Hash,
	others []hash.Hash,
) ([]*api.Receipt, error) {
	start := time.Now()
	receipts, err := w.Backend.Merge(ctx, ns, round, base, others)
	storageLatency.With(labelMerge).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelMerge).Inc()
		return nil, err
	}

	storageCalls.With(labelMerge).Inc()
	return receipts, err
}

func (w *metricsWrapper) MergeBatch(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	ops []api.MergeOp,
) ([]*api.Receipt, error) {
	start := time.Now()
	receipts, err := w.Backend.MergeBatch(ctx, ns, round, ops)
	storageLatency.With(labelMergeBatch).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelMergeBatch).Inc()
		return nil, err
	}

	storageCalls.With(labelMergeBatch).Inc()
	return receipts, err
}

func (w *metricsWrapper) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
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

func (w *metricsWrapper) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
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

func (w *metricsWrapper) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
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

func (w *metricsWrapper) HasRoot(root api.Root) bool {
	localBackend, ok := w.Backend.(api.LocalBackend)
	if !ok {
		return false
	}
	start := time.Now()
	flag := localBackend.HasRoot(root)
	storageLatency.With(labelHasRoot).Observe(time.Since(start).Seconds())
	storageCalls.With(labelHasRoot).Inc()
	return flag
}

func (w *metricsWrapper) Finalize(ctx context.Context, namespace common.Namespace, round uint64, roots []hash.Hash) error {
	localBackend, ok := w.Backend.(api.LocalBackend)
	if !ok {
		return api.ErrUnsupported
	}
	start := time.Now()
	err := localBackend.Finalize(ctx, namespace, round, roots)
	storageLatency.With(labelFinalize).Observe(time.Since(start).Seconds())
	storageCalls.With(labelFinalize).Inc()
	if err == nil {
		storageFinalizedCount.Inc()
	}
	return err
}

func (w *metricsWrapper) Prune(ctx context.Context, namespace common.Namespace, round uint64) (int, error) {
	localBackend, ok := w.Backend.(api.LocalBackend)
	if !ok {
		return 0, api.ErrUnsupported
	}
	start := time.Now()
	pruned, err := localBackend.Prune(ctx, namespace, round)
	storageLatency.With(labelPrune).Observe(time.Since(start).Seconds())
	storageCalls.With(labelPrune).Inc()
	storagePrunedCount.Add(float64(pruned))
	return pruned, err
}

func newMetricsWrapper(base api.Backend) api.Backend {
	metricsOnce.Do(func() {
		prometheus.MustRegister(storageCollectors...)
	})

	w := &metricsWrapper{Backend: base}

	return w
}
