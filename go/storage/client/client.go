// Package client implements a client for Ekiden storage nodes.
// The client obtains storage info by following scheduler committees.
// NOTE: The client assumes committees for all runtimes share the same
// storage committee.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/x509"
	"io"
	"math/rand"
	"sync"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/grpc/storage"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	urkelDb "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/db/api"
	urkelNode "github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "client"

	// Address to connect to with the storage client.
	cfgDebugClientAddress = "storage.debug.client.address"

	// Path to certificate file for grpc
	cfgDebugClientTLSCertFile = "storage.debug.client.tls"
)

var (
	_ api.Backend       = (*storageClientBackend)(nil)
	_ api.ClientBackend = (*storageClientBackend)(nil)
)

// ErrStorageNotAvailable is the error returned when a storage is not
// available.
var ErrStorageNotAvailable = errors.New("storage client: storage not available")

// storageClientBackend contains all information about the client storage API
// backend, including the backend state and the connected storage committee
// nodes' state.
type storageClientBackend struct {
	logger *logging.Logger

	scheduler scheduler.Backend
	registry  registry.Backend

	state               *backendState
	connectedNodesState *connectedNodesState

	haltCtx      context.Context
	cancelFn     context.CancelFunc
	initCh       chan struct{}
	signaledInit bool
}

// connectedNodesState contains information about the latest connected storage
// committee nodes and their corresponding client states.
type connectedNodesState struct {
	sync.RWMutex

	nodes        []*node.Node
	clientStates []*clientState
}

// clientState contains information about a connected storage node.
type clientState struct {
	client            storage.StorageClient
	conn              *grpc.ClientConn
	resolverCleanupCb func()
}

// backendState contains the most recent list of scheduled storage committees.
type backendState struct {
	sync.RWMutex

	logger *logging.Logger

	storageNodeList []*node.Node
}

// GetConnectedNodes returns registry node information about the connected
// storage nodes.
func (b *storageClientBackend) GetConnectedNodes() []*node.Node {
	b.connectedNodesState.RLock()
	defer b.connectedNodesState.RUnlock()

	return b.connectedNodesState.nodes
}

func (b *storageClientBackend) updateNodeConnections() {
	b.state.RLock()
	defer b.state.RUnlock()

	b.logger.Debug("updating connections to nodes")

	nodeList := b.state.storageNodeList

	// TODO: Should we only update connections if keys or addresses have
	// changed?
	b.connectedNodesState.Lock()
	defer b.connectedNodesState.Unlock()

	connNodes := []*node.Node{}
	connClientStates := []*clientState{}
	numConnNodes := 0

	// Clean-up previous resolvers.
	for _, clientState := range b.connectedNodesState.clientStates {
		if cleanup := clientState.resolverCleanupCb; cleanup != nil {
			cleanup()
		}
	}

	for _, node := range nodeList {
		var opts grpc.DialOption
		if node.Certificate == nil {
			// NOTE: This should only happen in tests, where nodes register
			// without a certificate.
			// TODO: This can be rejected once node_tests register with a
			// certificate.
			opts = grpc.WithInsecure()
			b.logger.Warn("storage committee member registered without certificate, using insecure connection!",
				"member", node,
			)
		} else {
			nodeCert, err := node.Certificate.Parse()
			if err != nil {
				b.logger.Error("failed to parse storage committee member's certificate",
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
			b.logger.Error("cannot update connection, storage committee member does not have any addresses",
				"member", node,
			)
			continue
		}

		manualResolver, address, cleanupCb := manual.NewManualResolver()

		conn, err := grpc.Dial(address, opts, grpc.WithBalancerName(roundrobin.Name))
		if err != nil {
			b.logger.Error("cannot update connection, failed dialing storage node",
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
		connNodes = append(connNodes, node)
		connClientStates = append(connClientStates, &clientState{
			client:            storage.NewStorageClient(conn),
			conn:              conn,
			resolverCleanupCb: cleanupCb,
		})
		b.logger.Debug("storage node connection updated",
			"node", node,
		)
	}
	if numConnNodes == 0 {
		b.logger.Error("failed to connect to any of the storage committee members",
			"members", nodeList,
		)
		return
	}

	if !b.signaledInit {
		b.signaledInit = true
		close(b.initCh)
	}

	// TODO: Stop in-flight storage requests and retry them after new committee
	// is known.
	b.connectedNodesState.nodes = connNodes
	b.connectedNodesState.clientStates = connClientStates
}

func (s *backendState) updateStorageNodeList(ctx context.Context, nodes []*node.Node) error {
	storageNodes := []*node.Node{}
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) {
			storageNodes = append(storageNodes, n)
		}
	}

	s.Lock()
	defer s.Unlock()
	s.storageNodeList = storageNodes

	return nil
}

type grpcResponse struct {
	resp interface{}
	err  error
	// This node pointer is used to identify a (potentially) misbehaving node.
	node *node.Node
}

func (b *storageClientBackend) writeWithClient(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	fn func(context.Context, storage.StorageClient, *node.Node, chan<- *grpcResponse),
	expectedNewRoots []hash.Hash,
) ([]*api.Receipt, error) {
	b.connectedNodesState.RLock()
	defer b.connectedNodesState.RUnlock()

	n := len(b.connectedNodesState.nodes)
	if n == 0 {
		return nil, ErrStorageNotAvailable
	}
	// Use a buffered channel to allow all "write" goroutines to return as soon
	// as they are finished.
	ch := make(chan *grpcResponse, n)
	for i, clientState := range b.connectedNodesState.clientStates {
		go fn(ctx, clientState.client, b.connectedNodesState.nodes[i], ch)
	}
	successes := 0
	receipts := make([]*api.Receipt, 0, n)
	for i := 0; i < n; i++ {
		var response *grpcResponse
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case response = <-ch:
		}
		if response.err != nil {
			b.logger.Error("failed to get response from a storage node",
				"node", response.node,
				"err", response.err,
			)
			continue
		}

		var receiptsRaw []byte
		var err error
		switch resp := response.resp.(type) {
		case *storage.ApplyResponse:
			receiptsRaw = resp.GetReceipts()
		case *storage.ApplyBatchResponse:
			receiptsRaw = resp.GetReceipts()
		default:
			b.logger.Error("got unexpected response type from a storage node",
				"node", response.node,
				"resp", resp,
			)
			continue
		}
		// NOTE: All storage backend implementations of apply operations return
		// a list of storage receipts. However, a concrete storage backend,
		// e.g. storage/leveldb, actually returns a single storage receipt in a
		// list.
		receiptInAList := make([]api.Receipt, 1)
		if err = cbor.Unmarshal(receiptsRaw, receiptInAList); err != nil {
			b.logger.Error("failed to unmarshal receipt in a list from a storage node",
				"node", response.node,
				"err", err,
			)
			continue
		}
		if len(receiptInAList) != 1 {
			b.logger.Error("got more than one receipt from a storage node",
				"node", response.node,
				"num_receipts", len(receiptInAList),
			)
			continue
		}
		receipt := receiptInAList[0]
		// TODO: After we switch to https://github.com/oasislabs/ed25519, use
		// batch verification. This should be implemented as part of:
		// https://github.com/oasislabs/ekiden/issues/1351.
		var receiptBody api.ReceiptBody
		if err = receipt.Open(&receiptBody); err != nil {
			b.logger.Error("failed to open receipt for a storage node",
				"node", response.node,
				"err", err,
			)
			continue
		}
		// Check that obtained root(s) equal the expected new root(s).
		equal := true
		if !receiptBody.Namespace.Equal(&ns) {
			equal = false
		}
		if receiptBody.Round != round {
			equal = false
		}
		if len(receiptBody.Roots) != len(expectedNewRoots) {
			equal = false
		}
		for i := range receiptBody.Roots {
			if receiptBody.Roots[i] != expectedNewRoots[i] {
				equal = false
				break
			}
		}
		if !equal {
			b.logger.Error("obtained root(s) don't equal the expected new root(s)",
				"node", response.node,
				"obtainedRoots", receiptBody.Roots,
				"expectedNewRoots", expectedNewRoots,
			)
			continue
		}
		successes++
		// TODO: Only wait for F+1 successful writes:
		// https://github.com/oasislabs/ekiden/issues/1821.
		receipts = append(receipts, &receipt)
	}
	if successes == 0 {
		return nil, errors.New("storage client: failed to write to any storage node")
	}
	if successes < n {
		b.logger.Warn("write operation was only successfully applied to %d out of %d connected nodes", successes, n)
	}

	return receipts, nil
}

func (b *storageClientBackend) Apply(
	ctx context.Context,
	ns common.Namespace,
	srcRound uint64,
	srcRoot hash.Hash,
	dstRound uint64,
	dstRoot hash.Hash,
	writeLog api.WriteLog,
) ([]*api.Receipt, error) {
	var req storage.ApplyRequest
	req.Namespace, _ = ns.MarshalBinary()
	req.SrcRound = srcRound
	req.SrcRoot, _ = srcRoot.MarshalBinary()
	req.DstRound = dstRound
	req.DstRoot, _ = dstRoot.MarshalBinary()
	req.Log = make([]*storage.LogEntry, 0, len(writeLog))
	for _, e := range writeLog {
		req.Log = append(req.Log, &storage.LogEntry{
			Key:   e.Key,
			Value: e.Value,
		})
	}

	return b.writeWithClient(
		ctx,
		ns,
		dstRound,
		func(ctx context.Context, c storage.StorageClient, node *node.Node, ch chan<- *grpcResponse) {
			resp, err := c.Apply(ctx, &req)
			ch <- &grpcResponse{
				resp: resp,
				err:  err,
				node: node,
			}
		},
		[]hash.Hash{dstRoot},
	)
}

func (b *storageClientBackend) ApplyBatch(
	ctx context.Context,
	ns common.Namespace,
	dstRound uint64,
	ops []api.ApplyOp,
) ([]*api.Receipt, error) {
	var req storage.ApplyBatchRequest
	req.Namespace, _ = ns.MarshalBinary()
	req.DstRound = dstRound
	req.Ops = make([]*storage.ApplyOp, 0, len(ops))
	expectedNewRoots := make([]hash.Hash, 0, len(ops))
	for _, op := range ops {
		var pOp storage.ApplyOp
		pOp.SrcRound = op.SrcRound
		pOp.SrcRoot, _ = op.SrcRoot.MarshalBinary()
		pOp.DstRoot, _ = op.DstRoot.MarshalBinary()
		pOp.Log = make([]*storage.LogEntry, 0, len(op.WriteLog))
		for _, e := range op.WriteLog {
			pOp.Log = append(pOp.Log, &storage.LogEntry{
				Key:   e.Key,
				Value: e.Value,
			})
		}
		req.Ops = append(req.Ops, &pOp)
		expectedNewRoots = append(expectedNewRoots, op.DstRoot)
	}

	return b.writeWithClient(
		ctx,
		ns,
		dstRound,
		func(ctx context.Context, c storage.StorageClient, node *node.Node, ch chan<- *grpcResponse) {
			resp, err := c.ApplyBatch(ctx, &req)
			ch <- &grpcResponse{
				resp: resp,
				err:  err,
				node: node,
			}
		},
		expectedNewRoots,
	)
}

func (b *storageClientBackend) readWithClient(ctx context.Context, fn func(context.Context, storage.StorageClient) (interface{}, error)) (interface{}, error) {
	b.connectedNodesState.RLock()
	defer b.connectedNodesState.RUnlock()

	n := len(b.connectedNodesState.nodes)

	if n == 0 {
		return nil, ErrStorageNotAvailable
	}
	// TODO: Use a more clever approach to choose the order in which to read
	// from the connected nodes:
	// https://github.com/oasislabs/ekiden/issues/1815.
	rng := rand.New(mathrand.New(cryptorand.Reader))

	var err error
	var resp interface{}
	for _, randIndex := range rng.Perm(n) {
		clientState := b.connectedNodesState.clientStates[randIndex]
		resp, err = fn(ctx, clientState.client)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			b.logger.Error("failed to get response from a storage node",
				"node", b.connectedNodesState.nodes[randIndex],
				"err", err,
			)
			continue
		}
		return resp, err
	}
	return nil, err
}

func (b *storageClientBackend) GetSubtree(ctx context.Context, root api.Root, id api.NodeID, maxDepth uint8) (*api.Subtree, error) {
	var req storage.GetSubtreeRequest
	req.Root = root.MarshalCBOR()
	req.MaxDepth = uint32(maxDepth)
	req.Id = &storage.NodeID{Depth: uint32(id.Depth)}
	req.Id.Path, _ = id.Path.MarshalBinary()

	respRaw, err := b.readWithClient(ctx, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
		return c.GetSubtree(ctx, &req)
	})
	if err != nil {
		return nil, err
	}
	resp := respRaw.(*storage.GetSubtreeResponse)

	var subtree api.Subtree
	if err = subtree.UnmarshalBinary(resp.GetSubtree()); err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal subtree")
	}

	return &subtree, nil
}

func (b *storageClientBackend) GetPath(ctx context.Context, root api.Root, key hash.Hash, startDepth uint8) (*api.Subtree, error) {
	var req storage.GetPathRequest
	req.Root = root.MarshalCBOR()
	req.Key, _ = key.MarshalBinary()
	req.StartDepth = uint32(startDepth)

	respRaw, err := b.readWithClient(ctx, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
		return c.GetPath(ctx, &req)
	})
	if err != nil {
		return nil, err
	}
	resp := respRaw.(*storage.GetPathResponse)

	var subtree api.Subtree
	if err = subtree.UnmarshalBinary(resp.GetSubtree()); err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal subtree")
	}

	return &subtree, nil
}

func (b *storageClientBackend) GetNode(ctx context.Context, root api.Root, id api.NodeID) (api.Node, error) {
	var req storage.GetNodeRequest
	req.Root = root.MarshalCBOR()
	req.Id = &storage.NodeID{Depth: uint32(id.Depth)}
	req.Id.Path, _ = id.Path.MarshalBinary()

	respRaw, err := b.readWithClient(ctx, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
		return c.GetNode(ctx, &req)
	})
	if err != nil {
		return nil, err
	}
	resp := respRaw.(*storage.GetNodeResponse)

	n, err := urkelNode.UnmarshalBinary(resp.GetNode())
	if err != nil {
		return nil, errors.Wrap(err, "storage client: failed to unmarshal node")
	}

	return n, nil
}

func (b *storageClientBackend) GetDiff(ctx context.Context, startRoot api.Root, endRoot api.Root) (api.WriteLogIterator, error) {
	var req storage.GetDiffRequest
	req.StartRoot = startRoot.MarshalCBOR()
	req.EndRoot = endRoot.MarshalCBOR()

	respRaw, err := b.readWithClient(ctx, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
		return c.GetDiff(ctx, &req)
	})
	if err != nil {
		return nil, err
	}
	respClient := respRaw.(storage.Storage_GetDiffClient)

	pipe := urkelDb.NewPipeWriteLogIterator(ctx)

	go func() {
		defer pipe.Close()
		for {
			diffResp, err := respClient.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = pipe.PutError(err)
			}

			for _, entry := range diffResp.GetLog() {
				entry := api.LogEntry{
					Key:   entry.Key,
					Value: entry.Value,
				}
				if err := pipe.Put(&entry); err != nil {
					_ = pipe.PutError(err)
				}
			}

			if diffResp.GetFinal() {
				break
			}
		}
	}()

	return &pipe, nil
}

func (b *storageClientBackend) GetCheckpoint(ctx context.Context, root api.Root) (api.WriteLogIterator, error) {
	var req storage.GetCheckpointRequest
	req.Root = root.MarshalCBOR()

	respRaw, err := b.readWithClient(ctx, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
		return c.GetCheckpoint(ctx, &req)
	})
	if err != nil {
		return nil, err
	}
	respClient := respRaw.(storage.Storage_GetCheckpointClient)

	pipe := urkelDb.NewPipeWriteLogIterator(ctx)

	go func() {
		defer pipe.Close()
		for {
			checkpointResp, err := respClient.Recv()
			if err == io.EOF {
				return
			}
			if err != nil {
				b.logger.Error("storage client GetCheckpoint error",
					"err", err)
				_ = pipe.PutError(err)
			}

			for _, entry := range checkpointResp.GetLog() {
				entry := api.LogEntry{
					Key:   entry.Key,
					Value: entry.Value,
				}
				if err := pipe.Put(&entry); err != nil {
					_ = pipe.PutError(err)
				}
			}

			if checkpointResp.GetFinal() {
				return
			}
		}
	}()

	return &pipe, nil
}

func (b *storageClientBackend) Cleanup() {
	b.connectedNodesState.Lock()
	defer b.connectedNodesState.Unlock()

	b.cancelFn()
	for _, clientState := range b.connectedNodesState.clientStates {
		if callBack := clientState.resolverCleanupCb; callBack != nil {
			callBack()
		}
		if clientState.conn != nil {
			clientState.conn.Close()
		}
	}
}

func (b *storageClientBackend) Initialized() <-chan struct{} {
	return b.initCh
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
			b.logger.Debug("got new storage node list", ev.Nodes)
			if err := b.state.updateStorageNodeList(ctx, ev.Nodes); err != nil {
				b.logger.Error("worker: failed to update storage list",
					"err", err,
				)
				continue
			}
			// Update storage node connection.
			b.updateNodeConnections()

			b.logger.Debug("updated connections to nodes")

		case committee := <-schedCh:
			b.logger.Debug("worker: scheduler committee for epoch",
				"committee", committee,
				"epoch", committee.ValidFor,
				"kind", committee.Kind)

			if committee.Kind != scheduler.KindStorage {
				continue
			}

			if len(committee.Members) == 0 {
				b.logger.Warn("worker: received empty storage committee")
				continue
			}

			// Update storage node connection.
			b.updateNodeConnections()

			b.logger.Debug("updated connections to nodes")
		}
	}
}

// New creates a new client
func New(ctx context.Context, schedulerBackend scheduler.Backend, registryBackend registry.Backend) (api.Backend, error) {
	logger := logging.GetLogger("storage/client")

	if viper.GetString(cfgDebugClientAddress) != "" {
		logger.Warn("Storage client in debug mode, connecting to provided client",
			"address", cfgDebugClientAddress,
		)

		var opts grpc.DialOption
		if viper.GetString(cfgDebugClientTLSCertFile) != "" {
			creds, err := credentials.NewClientTLSFromFile(viper.GetString(cfgDebugClientTLSCertFile), "ekiden-node")
			if err != nil {
				logger.Error("failed creating grpc tls client from file",
					"file", viper.GetString(cfgDebugClientTLSCertFile),
					"error", err,
				)
				return nil, err
			}
			opts = grpc.WithTransportCredentials(creds)
		} else {
			opts = grpc.WithInsecure()
		}

		conn, err := grpc.Dial(viper.GetString(cfgDebugClientAddress), opts)
		if err != nil {
			logger.Error("unable to dial debug client",
				"error", err,
			)
			return nil, err
		}
		client := storage.NewStorageClient(conn)

		b := &storageClientBackend{
			logger:    logger,
			scheduler: schedulerBackend,
			registry:  registryBackend,
			connectedNodesState: &connectedNodesState{
				nodes: []*node.Node{&node.Node{}},
				clientStates: []*clientState{&clientState{
					client: client,
					conn:   conn,
				}},
			},
			state:  &backendState{},
			initCh: make(chan struct{}),
		}
		close(b.initCh)

		return b, nil
	}

	b := &storageClientBackend{
		logger:    logger,
		scheduler: schedulerBackend,
		registry:  registryBackend,
		connectedNodesState: &connectedNodesState{
			nodes:        []*node.Node{},
			clientStates: []*clientState{},
		},
		state: &backendState{
			logger:          logger,
			storageNodeList: []*node.Node{},
		},
		initCh: make(chan struct{}),
	}

	b.haltCtx, b.cancelFn = context.WithCancel(ctx)

	go b.watcher(ctx)

	return b, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgDebugClientAddress, "", "Address of node to connect to with the storage client")
		cmd.Flags().String(cfgDebugClientTLSCertFile, "", "Path to tls certificate for grpc")
	}

	for _, v := range []string{
		cfgDebugClientAddress,
		cfgDebugClientTLSCertFile,
	} {
		_ = viper.BindPFlag(v, cmd.Flags().Lookup(v))
	}
}
