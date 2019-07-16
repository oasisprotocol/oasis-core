package client

import (
	"context"
	"crypto/x509"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

type storageWatcher interface {
	getConnectedNodes() []*node.Node
	getClientStates() []clientState
	cleanup()
	initialized() <-chan struct{}
}

// debugWatcherState is a state with a fixed storage node.
type debugWatcherState struct {
	clientState *clientState
	initCh      chan struct{}
}

func (w *debugWatcherState) getConnectedNodes() []*node.Node {
	return []*node.Node{}
}

func (w *debugWatcherState) getClientStates() []clientState {
	return []clientState{*w.clientState}
}
func (w *debugWatcherState) cleanup() {
}
func (w *debugWatcherState) initialized() <-chan struct{} {
	return w.initCh
}

func newDebugWatcher(state *clientState) storageWatcher {
	initCh := make(chan struct{})
	close(initCh)
	return &debugWatcherState{
		initCh:      initCh,
		clientState: state,
	}
}

// watcherState contains storage watcher state.
type watcherState struct {
	sync.RWMutex

	logger *logging.Logger

	scheduler scheduler.Backend
	registry  registry.Backend

	runtimeID signature.MapKey

	registeredStorageNodes []*node.Node
	scheduledNodes         map[signature.MapKey]bool
	clientStates           []*clientState

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

func (w *watcherState) cleanup() {
	w.Lock()
	defer w.Unlock()

	for _, clientState := range w.clientStates {
		if callBack := clientState.resolverCleanupCb; callBack != nil {
			callBack()
		}
		if clientState.conn != nil {
			clientState.conn.Close()
		}
	}
}

func (w *watcherState) initialized() <-chan struct{} {
	return w.initCh
}

func (w *watcherState) getConnectedNodes() []*node.Node {
	w.RLock()
	defer w.RUnlock()

	connectedNodes := []*node.Node{}
	for _, state := range w.clientStates {
		connectedNodes = append(connectedNodes, state.node)
	}
	return connectedNodes
}

func (w *watcherState) getClientStates() []clientState {
	w.RLock()
	defer w.RUnlock()
	clientStates := []clientState{}
	for _, state := range w.clientStates {
		clientStates = append(clientStates, *state)
	}
	return clientStates
}
func (w *watcherState) updateStorageNodeConnections() {
	// XXX: This lock blocks requests to nodes for this runtime.
	w.Lock()
	defer w.Unlock()

	w.logger.Debug("updating connections to storage nodes")

	nodeList := []*node.Node{}
	for _, node := range w.registeredStorageNodes {
		if w.scheduledNodes[node.ID.ToMapKey()] {
			nodeList = append(nodeList, node)
		}
	}

	// TODO: Should we only update connections if keys or addresses have changed?

	// Clean-up previous resolvers.
	for _, states := range w.clientStates {
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
			// NOTE: This should only happen in tests, where nodes register without a certificate.
			// TODO: This can be rejected once node_tests register with a certificate.
			opts = grpc.WithInsecure()
			w.logger.Warn("storage committee member registered without certificate, using insecure connection!",
				"member", node)
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
	w.clientStates = connClientStates
}

func (w *watcherState) updateRegisteredStorageNodes(nodes []*node.Node) {
	storageNodes := []*node.Node{}
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) {
			storageNodes = append(storageNodes, n)
		}
	}

	w.Lock()
	defer w.Unlock()
	w.registeredStorageNodes = storageNodes
}

func (w *watcherState) updateScheduledNodes(nodes []*scheduler.CommitteeNode) {
	scheduledStorageNodes := make(map[signature.MapKey]bool)
	for _, n := range nodes {
		if n.Role == scheduler.Worker {
			scheduledStorageNodes[n.PublicKey.ToMapKey()] = true
		}
	}

	w.Lock()
	defer w.Unlock()
	w.scheduledNodes = scheduledStorageNodes
}

func (w *watcherState) watch(ctx context.Context) {
	committeeCh, sub := w.scheduler.WatchCommittees()
	defer sub.Close()

	nodeListCh, sub := w.registry.WatchNodeList()
	defer sub.Close()

	for {
		select {
		case <-ctx.Done():
			return
		case nl := <-nodeListCh:
			if nl == nil {
				continue
			}
			w.logger.Debug("got new storage node list",
				"nodes", nl.Nodes,
			)

			w.updateRegisteredStorageNodes(nl.Nodes)

			// Update storage node connections for the runtime.
			w.updateStorageNodeConnections()

			w.logger.Debug("updated connections to all nodes")
		case committee := <-committeeCh:
			if committee.RuntimeID.ToMapKey() != w.runtimeID {
				continue
			}
			if committee.Kind != scheduler.KindStorage {
				continue
			}

			w.logger.Debug("worker: storage committee for epoch",
				"committee", committee,
				"epoch", committee.ValidFor,
				"kind", committee.Kind,
			)

			if len(committee.Members) == 0 {
				w.logger.Warn("worker: received empty storage committee")
				continue
			}

			// Update connection if watching the runtime.
			w.updateScheduledNodes(committee.Members)

			// Update storage node connections for the runtime.
			w.updateStorageNodeConnections()

			w.logger.Debug("updated connections to nodes")
		}
	}
}

func newWatcher(ctx context.Context, runtimeID signature.PublicKey, schedulerBackend scheduler.Backend, registryBackend registry.Backend) storageWatcher {
	logger := logging.GetLogger("storage/client/watcher").With("runtime_id", runtimeID.String())

	watcher := &watcherState{
		initCh:                 make(chan struct{}),
		logger:                 logger,
		runtimeID:              runtimeID.ToMapKey(),
		scheduler:              schedulerBackend,
		registry:               registryBackend,
		registeredStorageNodes: []*node.Node{},
		scheduledNodes:         make(map[signature.MapKey]bool),
		clientStates:           []*clientState{},
	}

	go watcher.watch(ctx)

	return watcher
}
