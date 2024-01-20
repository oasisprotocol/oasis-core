package keymanager

import (
	"context"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

type kmNodeWatcher struct {
	w         *Worker
	consensus consensus.Backend
}

func newKmNodeWatcher(w *Worker) *kmNodeWatcher {
	return &kmNodeWatcher{
		w:         w,
		consensus: w.commonWorker.Consensus,
	}
}

func (knw *kmNodeWatcher) watchNodes() {
	nodesCh, nodesSub, err := knw.consensus.Registry().WatchNodeList(knw.w.ctx)
	if err != nil {
		knw.w.logger.Error("worker/keymanager: failed to watch node list",
			"err", err,
		)
		return
	}
	defer nodesSub.Close()

	watcher, err := nodes.NewVersionedNodeDescriptorWatcher(knw.w.ctx, knw.consensus)
	if err != nil {
		knw.w.logger.Error("worker/keymanager: failed to create node desc watcher",
			"err", err,
		)
		return
	}
	watcherCh, watcherSub, err := watcher.WatchNodeUpdates()
	if err != nil {
		knw.w.logger.Error("worker/keymanager: failed to watch node updates",
			"err", err,
		)
		return
	}
	defer watcherSub.Close()

	var activeNodes map[signature.PublicKey]bool
	for {
		select {
		case nodeList := <-nodesCh:
			watcher.Reset()
			activeNodes = knw.rebuildActiveNodeIDs(nodeList.Nodes)
			for id := range activeNodes {
				if _, err := watcher.WatchNode(knw.w.ctx, id); err != nil {
					knw.w.logger.Error("worker/keymanager: failed to watch node",
						"err", err,
						"id", id,
					)
				}
			}
		case watcherEv := <-watcherCh:
			if watcherEv.Update == nil {
				continue
			}
			if !activeNodes[watcherEv.Update.ID] {
				continue
			}
		case <-knw.w.stopCh:
			return
		}

		// Rebuild the access policy, something has changed.
		var nodes []*node.Node
		peers := make(map[signature.PublicKey]struct{})
		for id := range activeNodes {
			n := watcher.Lookup(id)
			if n == nil {
				continue
			}
			nodes = append(nodes, n)
			peers[n.P2P.ID] = struct{}{}
		}

		knw.w.accessList.UpdateNodes(knw.w.runtimeID, nodes)
		if pm := knw.w.commonWorker.P2P.PeerManager(); pm != nil {
			if pids, err := p2p.PublicKeyMapToPeerIDs(peers); err == nil {
				pm.PeerTagger().SetPeerImportance(p2p.ImportantNodeKeyManager, knw.w.runtime.ID(), pids)
			}
		}
	}
}

func (knw *kmNodeWatcher) rebuildActiveNodeIDs(nodeList []*node.Node) map[signature.PublicKey]bool {
	m := make(map[signature.PublicKey]bool)
	for _, n := range nodeList {
		if !n.HasRoles(node.RoleKeyManager) {
			continue
		}
		for _, rt := range n.Runtimes {
			if rt.ID.Equal(&knw.w.runtimeID) {
				m[n.ID] = true
				break
			}
		}
	}

	return m
}

// kmRuntimeWatcher is a key manager runtime watcher tasked with monitoring
// compute runtimes utilizing the specified key manager and initiating
// a runtime node watcher for each identified runtime.
type kmRuntimeWatcher struct {
	mu sync.RWMutex

	runtimeID common.Namespace
	consensus consensus.Backend

	accessList *AccessList

	clientRuntimes map[common.Namespace]*rtNodeWatcher // Guarded by mutex.

	logger *logging.Logger
}

func newKmRuntimeWatcher(runtimeID common.Namespace, consensus consensus.Backend, accessList *AccessList) *kmRuntimeWatcher {
	logger := logging.GetLogger("worker/keymanager/watcher/rts")

	return &kmRuntimeWatcher{
		runtimeID:      runtimeID,
		consensus:      consensus,
		accessList:     accessList,
		clientRuntimes: make(map[common.Namespace]*rtNodeWatcher),
		logger:         logger,
	}
}

func (w *kmRuntimeWatcher) watch(ctx context.Context) {
	// Subscribe to runtime registrations in order to know which runtimes
	// are using us as a key manager.
	rtCh, rtSub, err := w.consensus.Registry().WatchRuntimes(ctx)
	if err != nil {
		w.logger.Error("failed to watch runtimes",
			"err", err,
		)
		return
	}
	defer rtSub.Close()

	// Wait for all runtime node watchers to finish before exiting.
	var wg sync.WaitGroup
	defer wg.Wait()

	// Start a new runtime node watcher for each detected client runtime.
	for {
		var rt *registry.Runtime
		select {
		case <-ctx.Done():
			return
		case rt = <-rtCh:
		}

		if rt.Kind != registry.KindCompute || rt.KeyManager == nil || !rt.KeyManager.Equal(&w.runtimeID) {
			continue
		}

		if w.getRuntimeNodeWatcher(rt.ID) != nil {
			continue
		}

		w.logger.Info("seen new runtime using us as a key manager",
			"runtime_id", rt.ID,
		)

		rnw := newRtNodeWatcher(rt.ID, w.consensus, w.accessList)

		wg.Add(1)
		go func() {
			defer wg.Done()
			rnw.watch(ctx)
		}()

		w.addRuntimeNodeWatcher(rt.ID, rnw)

		// Update metrics.
		computeRuntimeCount.WithLabelValues(w.runtimeID.String()).Inc()
	}
}

func (w *kmRuntimeWatcher) addRuntimeNodeWatcher(n common.Namespace, crw *rtNodeWatcher) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.clientRuntimes[n] = crw
}

func (w *kmRuntimeWatcher) getRuntimeNodeWatcher(n common.Namespace) *rtNodeWatcher {
	w.mu.RLock()
	defer w.mu.RUnlock()

	return w.clientRuntimes[n]
}

// Runtimes returns a list of compute client runtimes that use the specified key manager.
func (w *kmRuntimeWatcher) Runtimes() []common.Namespace {
	w.mu.RLock()
	defer w.mu.RUnlock()

	rts := make([]common.Namespace, 0, len(w.clientRuntimes))
	for rt := range w.clientRuntimes {
		rts = append(rts, rt)
	}

	return rts
}

// rtNodeWatcher is a runtime node watcher responsible for maintaining
// the access list for the specified runtime, ensuring it remains up-to-date.
type rtNodeWatcher struct {
	runtimeID common.Namespace
	consensus consensus.Backend

	accessList *AccessList

	logger *logging.Logger
}

func newRtNodeWatcher(runtimeID common.Namespace, consensus consensus.Backend, accessList *AccessList) *rtNodeWatcher {
	logger := logging.GetLogger("worker/keymanager/watcher/rt").With("runtime_id", runtimeID)

	return &rtNodeWatcher{
		runtimeID:  runtimeID,
		consensus:  consensus,
		accessList: accessList,
		logger:     logger,
	}
}

func (w *rtNodeWatcher) watch(ctx context.Context) {
	// Subscribe to epoch transitions to regularly update the runtime access list.
	epoCh, epoSub, err := w.consensus.Beacon().WatchLatestEpoch(ctx)
	if err != nil {
		w.logger.Error("failed to watch epochs",
			"err", err,
		)
		return
	}
	defer epoSub.Close()

	watcher, err := nodes.NewVersionedNodeDescriptorWatcher(ctx, w.consensus)
	if err != nil {
		w.logger.Error("failed to create node watcher",
			"err", err,
		)
		return
	}

	ch, sub, err := watcher.WatchNodeUpdates()
	if err != nil {
		w.logger.Error("failed to watch node updates",
			"err", err,
		)
		return
	}
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case <-epoCh:
			func() {
				watcher.Reset()
				defer watcher.Freeze(0)

				cms, err := w.consensus.Scheduler().GetCommittees(ctx, &scheduler.GetCommitteesRequest{
					Height:    consensus.HeightLatest,
					RuntimeID: w.runtimeID,
				})
				if err != nil {
					w.logger.Error("failed to fetch runtime committee",
						"err", err,
					)
					return
				}

				for _, cm := range cms {
					if cm.Kind != scheduler.KindComputeExecutor {
						continue
					}

					for _, member := range cm.Members {
						_, _ = watcher.WatchNode(ctx, member.PublicKey)
					}
				}
			}()
		case nu := <-ch:
			if nu.Reset {
				// Ignore reset events to avoid clearing the access list before setting a new one.
				// This is safe because a reset event is always followed by a freeze event after the
				// nodes have been set (even if the new set is empty).
				continue
			}
		}

		w.accessList.UpdateNodes(w.runtimeID, watcher.GetNodes())
	}
}
