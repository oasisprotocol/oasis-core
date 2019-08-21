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

	labelApply      = prometheus.Labels{"call": "apply"}
	labelApplyBatch = prometheus.Labels{"call": "apply_batch"}
	labelGetSubtree = prometheus.Labels{"call": "get_subtree"}
	labelGetPath    = prometheus.Labels{"call": "get_path"}
	labelGetNode    = prometheus.Labels{"call": "get_node"}
	labelHasRoot    = prometheus.Labels{"call": "has_root"}
	labelFinalize   = prometheus.Labels{"call": "finalize"}
	labelPrune      = prometheus.Labels{"call": "prune"}

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

func (w *metricsWrapper) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth api.Depth) (*api.Subtree, error) {
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

func (w *metricsWrapper) GetPath(ctx context.Context, root api.Root, id api.NodeID, key api.Key) (*api.Subtree, error) {
	start := time.Now()
	st, err := w.Backend.GetPath(ctx, root, id, key)
	storageLatency.With(labelGetPath).Observe(time.Since(start).Seconds())
	if err != nil {
		storageFailures.With(labelGetPath).Inc()
		return nil, err
	}

	storageCalls.With(labelGetPath).Inc()
	return st, err
}

func (w *metricsWrapper) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
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
