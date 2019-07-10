package client

import (
	"context"
	"crypto/x509"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

// TODO: Consider to refactoring to a watcher per runtime?

var (
	// ErrNoRuntimeState is an error when runtime state is missing.
	ErrNoRuntimeState = errors.New("storage/client/watcher: no runtime state")
	// ErrNoRuntimeConnectedNodes is an error when there are no connected storage nodes for a runtime.
	ErrNoRuntimeConnectedNodes = errors.New("storage/client/watcher: no connected nodes for runtime")
)

// watcherState contains watcher state.
type watcherState struct {
	sync.RWMutex

	logger *logging.Logger

	registeredStorageNodes      []*node.Node
	perRuntimeScheduledNodeKeys map[signature.MapKey][]signature.PublicKey
	perRuntimeClientStates      map[signature.MapKey][]*clientState

	initCh       chan struct{}
	signaledInit bool
}

// clientState contains information about a connected storage node.
type clientState struct {
	node              *node.Node
	client            storage.StorageClient
	conn              *grpc.ClientConn
	resolverCleanupCb func()
}

func (w *watcherState) Cleanup() {
	w.Lock()
	defer w.Unlock()

	for _, states := range w.perRuntimeClientStates {
		for _, clientState := range states {
			if callBack := clientState.resolverCleanupCb; callBack != nil {
				callBack()
			}
			if clientState.conn != nil {
				clientState.conn.Close()
			}
		}
	}
}

func (w *watcherState) getRuntimeClientStatesLocked(runtimeID signature.MapKey) ([]*clientState, error) {
	clientStates := w.perRuntimeClientStates[runtimeID]
	if clientStates == nil {
		w.logger.Error("writeWithClient: no state for runtime",
			"runtime", runtimeID,
		)
		return nil, ErrNoRuntimeState
	}
	n := len(clientStates)
	if n == 0 {
		w.logger.Error("writeWithClient: no connected nodes for runtime",
			"runtime", runtimeID,
		)
		return nil, ErrNoRuntimeConnectedNodes
	}

	return clientStates, nil
}

func (w *watcherState) getConnectedNodes() []*node.Node {
	w.RLock()
	defer w.RUnlock()

	connectedNodes := []*node.Node{}
	for _, states := range w.perRuntimeClientStates {
		for _, state := range states {
			connectedNodes = append(connectedNodes, state.node)
		}
	}
	return connectedNodes
}

func (w *watcherState) watchRuntime(id signature.PublicKey) {
	w.logger.Debug("worker storage: watching runtime",
		"runtime_id", id,
	)
	w.RLock()
	state := w.perRuntimeClientStates[id.ToMapKey()]
	if state != nil {
		w.RUnlock()
		// Nothing to do, already watching the runtime.
		return
	}
	w.RUnlock()
	// XXX: This lock blocks all requests.
	w.Lock()
	defer w.Unlock()
	w.perRuntimeClientStates[id.ToMapKey()] = []*clientState{}
	w.perRuntimeScheduledNodeKeys[id.ToMapKey()] = []signature.PublicKey{}
}

func (w *watcherState) isWatchingRuntime(runtimeID signature.MapKey) bool {
	w.RLock()
	defer w.RUnlock()

	for watchedRuntimeID := range w.perRuntimeClientStates {
		if watchedRuntimeID == runtimeID {
			return true
		}
	}
	return false
}

func (w *watcherState) nodeIsInCommitteeLocked(runtimeID signature.MapKey, node *node.Node) bool {
	scheduledNodeKeys := w.perRuntimeScheduledNodeKeys[runtimeID]
	for _, k := range scheduledNodeKeys {
		if k.ToMapKey() == node.ID.ToMapKey() {
			return true
		}
	}
	return false
}

func (w *watcherState) updateAllStorageNodeConnections() {
	for runtimeID := range w.perRuntimeClientStates {
		w.updateStorageNodeConnections(runtimeID)
	}
}

func (w *watcherState) updateStorageNodeConnections(runtimeID signature.MapKey) {
	// XXX: This lock blocks requests to nodes in all runtimes.
	// Could add separate per runtime-locks, change this to a RLock, but would still
	// need to lock the map when updating it at the end.
	w.Lock()
	defer w.Unlock()

	w.logger.Debug("updating connections to storage nodes",
		"runtime_id", runtimeID,
	)

	nodeList := []*node.Node{}
	for _, node := range w.registeredStorageNodes {
		if w.nodeIsInCommitteeLocked(runtimeID, node) {
			nodeList = append(nodeList, node)
		}
	}

	// TODO: Should we only update connections if keys or addresses have
	// changed?

	// Clean-up previous resolvers.
	clientStates := w.perRuntimeClientStates[runtimeID]
	if clientStates == nil {
		w.logger.Error("failed to update storage node connection, invalid runtimeID",
			"runtime_id", runtimeID,
		)
		return
	}
	for _, states := range clientStates {
		if cleanup := states.resolverCleanupCb; cleanup != nil {
			cleanup()
		}
	}

	connClientStates := []*clientState{}
	numConnNodes := 0

	// Connect to nodes.
	for _, node := range nodeList {
		var opts grpc.DialOption
		if node.Certificate == nil {
			// NOTE: This should only happen in tests, where nodes register
			// without a certificate.
			// TODO: This can be rejected once node_tests register with a
			// certificate.
			opts = grpc.WithInsecure()
			w.logger.Warn("storage committee member registered without certificate, using insecure connection!",
				"member", node,
			)
		} else {
			nodeCert, err := node.Certificate.Parse()
			if err != nil {
				w.logger.Error("failed to parse storage committee member's certificate",
					"member", node,
				)
				continue
			}
			certPool := x509.NewCertPool()
			certPool.AddCert(nodeCert)
			creds := credentials.NewClientTLSFromCert(certPool, "ekiden-node")
			opts = grpc.WithTransportCredentials(creds)
		}

		if len(node.Addresses) == 0 {
			w.logger.Error("cannot update connection, storage committee member does not have any addresses",
				"member", node,
			)
			continue
		}

		manualResolver, address, cleanupCb := manual.NewManualResolver()

		conn, err := grpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name))
		if err != nil {
			w.logger.Error("cannot update connection, failed dialing storage node",
				"node", node,
				"err", err,
			)
			continue
		}
		var resolverState resolver.State
		for _, addr := range node.Addresses {
			resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
		}
		manualResolver.UpdateState(resolverState)

		numConnNodes++
		connClientStates = append(connClientStates, &clientState{
			node:              node,
			client:            storage.NewStorageClient(conn),
			conn:              conn,
			resolverCleanupCb: cleanupCb,
		})
		w.logger.Debug("storage node connection updated",
			"node", node,
		)
	}
	if numConnNodes == 0 {
		w.logger.Error("failed to connect to any of the storage committee members",
			"nodes", nodeList,
		)
		return
	}

	if !w.signaledInit {
		w.signaledInit = true
		close(w.initCh)
	}

	// Update client state.
	w.perRuntimeClientStates[runtimeID] = connClientStates
}

func (w *watcherState) updateStorageNodeList(ctx context.Context, nodes []*node.Node) error {
	storageNodes := []*node.Node{}
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) {
			storageNodes = append(storageNodes, n)
		}
	}

	// XXX: This lock blocks all requests.
	// Could have a separate lock `registeredStorageNodes` list.
	w.Lock()
	defer w.Unlock()
	w.registeredStorageNodes = storageNodes

	return nil
}

func (w *watcherState) updateStorageCommitteeList(ctx context.Context, runtimeID signature.PublicKey, nodes []*scheduler.CommitteeNode) error {
	scheduledStorageNodeKeys := []signature.PublicKey{}
	for _, n := range nodes {
		if n.Role == scheduler.Worker {
			scheduledStorageNodeKeys = append(scheduledStorageNodeKeys, n.PublicKey)
		}
	}

	// XXX: This lock blocks all requests.
	w.Lock()
	defer w.Unlock()
	w.perRuntimeScheduledNodeKeys[runtimeID.ToMapKey()] = scheduledStorageNodeKeys

	return nil
}

func (b *storageClientBackend) watcher(ctx context.Context) {
	schedCh, sub := b.scheduler.WatchCommittees()
	defer sub.Close()

	nodeListCh, sub := b.registry.WatchNodeList()
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-nodeListCh:
			if ev == nil {
				continue
			}
			b.logger.Debug("got new storage node list")
			if err := b.watcherState.updateStorageNodeList(ctx, ev.Nodes); err != nil {
				b.logger.Error("worker: failed to update storage list",
					"err", err,
				)
				continue
			}
			// Update storage node connections for all runtimes.
			b.watcherState.updateAllStorageNodeConnections()

			b.logger.Debug("updated connections to all nodes")
		case committee := <-schedCh:
			b.logger.Debug("worker: scheduler committee for epoch",
				"committee", committee,
				"epoch", committee.ValidFor,
				"kind", committee.Kind,
			)

			if committee.Kind != scheduler.KindStorage {
				continue
			}

			if len(committee.Members) == 0 {
				b.logger.Warn("worker: received empty storage committee")
				continue
			}

			// Update connection if wattching the runtime.
			if b.watcherState.isWatchingRuntime(committee.RuntimeID.ToMapKey()) {
				if err := b.watcherState.updateStorageCommitteeList(ctx, committee.RuntimeID, committee.Members); err != nil {
					b.logger.Error("worker: failed to update storage committee list",
						"err", err,
					)
					continue
				}

				// Update storage node connections for the runtime.
				b.watcherState.updateStorageNodeConnections(committee.RuntimeID.ToMapKey())

				b.logger.Debug("updated connections to nodes",
					"runtime", committee.RuntimeID,
				)
			}
		}
	}
}
