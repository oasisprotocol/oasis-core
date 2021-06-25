package keymanager

import (
	"github.com/oasisprotocol/oasis-core/go/common/accessctl"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes"
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
		policy := accessctl.NewPolicy()

		for _, addr := range knw.w.commonWorker.GetConfig().SentryAddresses {
			sentryNodesPolicy.AddPublicKeyPolicy(&policy, addr.PubKey)
		}

		var nodes []*node.Node
		for id := range activeNodes {
			n := watcher.Lookup(id)
			if n == nil {
				continue
			}
			nodes = append(nodes, n)
		}

		kmNodesPolicy.AddRulesForNodeRoles(&policy, nodes, node.RoleKeyManager)
		knw.w.grpcPolicy.SetAccessPolicy(policy, knw.w.runtime.ID())
		knw.w.logger.Debug("worker/keymanager: new km runtime access policy in effect",
			"policy", policy,
		)
	}
}

func (knw *kmNodeWatcher) rebuildActiveNodeIDs(nodeList []*node.Node) map[signature.PublicKey]bool {
	m := make(map[signature.PublicKey]bool)
	id := knw.w.runtime.ID()
	for _, n := range nodeList {
		if !n.HasRoles(node.RoleKeyManager) {
			continue
		}
		for _, rt := range n.Runtimes {
			if rt.ID.Equal(&id) {
				m[n.ID] = true
				break
			}
		}
	}

	return m
}
