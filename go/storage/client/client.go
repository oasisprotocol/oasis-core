// Package client implements a client for Ekiden storage nodes.
// The client obtains storage info by following scheduler committees.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"io"
	"math/rand"
	"sync"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/mathrand"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
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

var (
	// ErrNoWatcher is an error when watcher for runtime is missing.
	ErrNoWatcher = errors.New("storage/client: no watcher for runtime")
	// ErrStorageNotAvailable is the error returned when a storage is not
	// available.
	ErrStorageNotAvailable = errors.New("storage/client: storage not available")
)

// storageClientBackend contains all information about the client storage API
// backend, including the backend state and the connected storage committee
// nodes' state.
type storageClientBackend struct {
	ctx context.Context

	logger *logging.Logger

	initCh       chan struct{}
	signaledInit bool

	debugRuntimeID signature.PublicKey

	scheduler scheduler.Backend
	registry  registry.Backend

	runtimeWatchersLock sync.RWMutex
	runtimeWatchers     map[signature.MapKey]storageWatcher

	haltCtx  context.Context
	cancelFn context.CancelFunc
}

func (b *storageClientBackend) getStorageWatcher(runtimeID signature.MapKey) (storageWatcher, error) {
	b.runtimeWatchersLock.RLock()
	defer b.runtimeWatchersLock.RUnlock()

	watcher := b.runtimeWatchers[runtimeID]
	if watcher == nil {
		b.logger.Error("worker/storage/client: no watcher for runtime",
			"runtime_id", runtimeID,
		)
		return nil, ErrNoWatcher
	}
	return watcher, nil
}

// GetConnectedNodes returns registry node information about all connected
// storage nodes.
func (b *storageClientBackend) GetConnectedNodes() []*node.Node {
	b.runtimeWatchersLock.RLock()
	defer b.runtimeWatchersLock.RUnlock()

	nodes := []*node.Node{}
	for _, watcher := range b.runtimeWatchers {
		nodes = append(nodes, watcher.getConnectedNodes()...)
	}
	return nodes
}

func (b *storageClientBackend) WatchRuntime(id signature.PublicKey) error {
	b.runtimeWatchersLock.RLock()
	watcher := b.runtimeWatchers[id.ToMapKey()]
	if watcher != nil {
		// Already watching, nothing to do.
		b.runtimeWatchersLock.RUnlock()
		return nil
	}
	b.runtimeWatchersLock.RUnlock()

	// Watcher doesn't exist. Start new watcher.
	watcher = newWatcher(b.ctx, id, b.scheduler, b.registry)

	b.runtimeWatchersLock.Lock()
	defer b.runtimeWatchersLock.Unlock()

	b.runtimeWatchers[id.ToMapKey()] = watcher

	// Signal init when first runtime is initialized.
	if !b.signaledInit {
		b.signaledInit = true
		go func() {
			select {
			case <-watcher.initialized():
			case <-b.ctx.Done():
				return
			}
			close(b.initCh)
		}()
	}

	return nil
}

type grpcResponse struct {
	resp interface{}
	err  error
	// This node pointer is used to identify a (potentially) misbehaving node.
	node *node.Node
}

func (b *storageClientBackend) getRequestRuntime(ns common.Namespace) (runtimeID signature.PublicKey, err error) {
	// In debug mode always connect to the debug watcher.
	if b.debugRuntimeID != nil {
		runtimeID = b.debugRuntimeID
	} else {
		// Otherwise, determine runtime from request namsepace.
		return ns.ToRuntimeID()
	}
	return
}

func (b *storageClientBackend) writeWithClient(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	fn func(context.Context, storage.StorageClient, *node.Node, chan<- *grpcResponse),
	expectedNewRoots []hash.Hash,
) ([]*api.Receipt, error) {
	runtimeID, err := b.getRequestRuntime(ns)
	if err != nil {
		b.logger.Error("writeWithClient: failure when deriving runtimeID from storage namespace",
			"namespace", ns,
			"err", err,
		)
		return nil, ErrStorageNotAvailable
	}

	// Get watcher for runtime.
	watcher, err := b.getStorageWatcher(runtimeID.ToMapKey())
	if err != nil {
		b.logger.Error("writeWithClient: cannot get watcher for runtime",
			"runtime_id", runtimeID,
			"err", err,
		)
		return nil, ErrStorageNotAvailable
	}

	watcher.rLockClientStates()
	defer watcher.rUnlockClientStates()
	clientStates := watcher.getClientStates()
	n := len(clientStates)
	if n == 0 {
		b.logger.Error("writeWithClient: no connected nodes for runtime",
			"runtime_id", runtimeID,
		)
		return nil, ErrStorageNotAvailable
	}

	// Use a buffered channel to allow all "write" goroutines to return as soon
	// as they are finished.
	ch := make(chan *grpcResponse, n)
	for _, clientState := range clientStates {
		go fn(ctx, clientState.client, clientState.node, ch)
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

func (b *storageClientBackend) readWithClient(ctx context.Context, ns common.Namespace, fn func(context.Context, storage.StorageClient) (interface{}, error)) (interface{}, error) {
	runtimeID, err := b.getRequestRuntime(ns)
	if err != nil {
		b.logger.Error("readWithClient: failure when deriving runtimeID from storage namespace",
			"namespace", ns,
			"err", err,
		)
		return nil, ErrStorageNotAvailable
	}

	// Get watcher for runtime.
	watcher, err := b.getStorageWatcher(runtimeID.ToMapKey())
	if err != nil {
		b.logger.Error("readWithClient: cannot get watcher for runtime",
			"runtime_id", runtimeID,
			"err", err,
		)
		return nil, ErrStorageNotAvailable
	}

	watcher.rLockClientStates()
	defer watcher.rUnlockClientStates()
	clientStates := watcher.getClientStates()
	n := len(clientStates)
	if n == 0 {
		b.logger.Error("readWithClient: no connected nodes for runtime",
			"runtime_id", runtimeID,
		)
		return nil, ErrStorageNotAvailable
	}

	// TODO: Use a more clever approach to choose the order in which to read
	// from the connected nodes:
	// https://github.com/oasislabs/ekiden/issues/1815.
	rng := rand.New(mathrand.New(cryptorand.Reader))

	var resp interface{}
	for _, randIndex := range rng.Perm(n) {
		clientState := clientStates[randIndex]
		resp, err = fn(ctx, clientState.client)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			b.logger.Error("failed to get response from a storage node",
				"node", clientState.node,
				"err", err,
				"runtime_id", runtimeID,
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

	respRaw, err := b.readWithClient(ctx, root.Namespace, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
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

	respRaw, err := b.readWithClient(ctx, root.Namespace, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
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

	respRaw, err := b.readWithClient(ctx, root.Namespace, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
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

	respRaw, err := b.readWithClient(ctx, startRoot.Namespace, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
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

	respRaw, err := b.readWithClient(ctx, root.Namespace, func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
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
	b.cancelFn()

	b.runtimeWatchersLock.Lock()
	defer b.runtimeWatchersLock.Unlock()
	for _, watcher := range b.runtimeWatchers {
		watcher.cleanup()
	}
}

func (b *storageClientBackend) Initialized() <-chan struct{} {
	return b.initCh
}
