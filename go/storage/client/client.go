// Package client implements a client for Oasis storage nodes.
// The client obtains storage info by following scheduler committees.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"io"
	"math/rand"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/identity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/grpc/storage"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	"github.com/oasislabs/oasis-core/go/storage/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

var (
	_ api.Backend       = (*storageClientBackend)(nil)
	_ api.ClientBackend = (*storageClientBackend)(nil)
)

var (
	// ErrNoWatcher is an error when watcher for runtime is missing.
	ErrNoWatcher = errors.New("storage/client: no watcher for runtime")
	// ErrStorageNotAvailable is the error returned when no storage node is available.
	ErrStorageNotAvailable = errors.New("storage/client: storage not available")
)

const (
	retryInterval = 1 * time.Second
	maxRetries    = 15
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

	identity *identity.Identity

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
	b.runtimeWatchersLock.Lock()
	defer b.runtimeWatchersLock.Unlock()

	watcher := b.runtimeWatchers[id.ToMapKey()]
	if watcher != nil {
		// Already watching, nothing to do.
		return nil
	}

	// Watcher doesn't exist. Start new watcher.
	watcher = newWatcher(b.ctx, id, b.identity, b.scheduler, b.registry)
	b.runtimeWatchers[id.ToMapKey()] = watcher

	// Signal init when the first registered runtime is initialized.
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
	fn func(context.Context, storage.StorageClient, *node.Node) (interface{}, error),
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
		client, node := clientState.client, clientState.node

		go func() {
			var (
				resp       interface{}
				numRetries int
			)
			op := func() error {
				var err error
				resp, err = fn(ctx, client, node)
				if status.Code(err) == codes.PermissionDenied && numRetries < maxRetries {
					// Writes can fail around an epoch transition due to policy errors,
					// make sure to retry in this case (up to maxRetries).
					numRetries++
					return err
				}
				return backoff.Permanent(err)
			}

			sched := backoff.NewConstantBackOff(retryInterval)
			err := backoff.Retry(op, backoff.WithContext(sched, ctx))

			ch <- &grpcResponse{
				resp: resp,
				err:  err,
				node: node,
			}
		}()
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
		case *storage.MergeResponse:
			receiptsRaw = resp.GetReceipts()
		case *storage.MergeBatchResponse:
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
		if err = cbor.Unmarshal(receiptsRaw, &receiptInAList); err != nil {
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
		// https://github.com/oasislabs/oasis-core/issues/1351.
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
		if expectedNewRoots != nil {
			if len(receiptBody.Roots) != len(expectedNewRoots) {
				equal = false
			} else {
				for i := range receiptBody.Roots {
					if receiptBody.Roots[i] != expectedNewRoots[i] {
						equal = false
						break
					}
				}
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
		// https://github.com/oasislabs/oasis-core/issues/1821.
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
		func(ctx context.Context, c storage.StorageClient, node *node.Node) (interface{}, error) {
			return c.Apply(ctx, &req)
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
		func(ctx context.Context, c storage.StorageClient, node *node.Node) (interface{}, error) {
			return c.ApplyBatch(ctx, &req)
		},
		expectedNewRoots,
	)
}

func (b *storageClientBackend) Merge(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	base hash.Hash,
	others []hash.Hash,
) ([]*api.Receipt, error) {
	var req storage.MergeRequest
	req.Namespace, _ = ns.MarshalBinary()
	req.Round = round
	req.Base, _ = base.MarshalBinary()
	req.Others = make([][]byte, 0, len(others))
	for _, h := range others {
		raw, _ := h.MarshalBinary()
		req.Others = append(req.Others, raw)
	}

	return b.writeWithClient(
		ctx,
		ns,
		round+1,
		func(ctx context.Context, c storage.StorageClient, node *node.Node) (interface{}, error) {
			return c.Merge(ctx, &req)
		},
		nil,
	)
}

func (b *storageClientBackend) MergeBatch(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	ops []api.MergeOp,
) ([]*api.Receipt, error) {
	var req storage.MergeBatchRequest
	req.Namespace, _ = ns.MarshalBinary()
	req.Round = round
	req.Ops = make([]*storage.MergeOp, 0, len(ops))
	for _, op := range ops {
		var pOp storage.MergeOp
		pOp.Base, _ = op.Base.MarshalBinary()
		pOp.Others = make([][]byte, 0, len(op.Others))
		for _, h := range op.Others {
			raw, _ := h.MarshalBinary()
			pOp.Others = append(pOp.Others, raw)
		}
		req.Ops = append(req.Ops, &pOp)
	}

	return b.writeWithClient(
		ctx,
		ns,
		round+1,
		func(ctx context.Context, c storage.StorageClient, node *node.Node) (interface{}, error) {
			return c.MergeBatch(ctx, &req)
		},
		nil,
	)
}

func (b *storageClientBackend) readWithClient(
	ctx context.Context,
	ns common.Namespace,
	fn func(context.Context, storage.StorageClient) (interface{}, error),
) (interface{}, error) {
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
	// https://github.com/oasislabs/oasis-core/issues/1815.
	rng := rand.New(mathrand.New(cryptorand.Reader))

	var resp interface{}
	for _, randIndex := range rng.Perm(n) {
		state := clientStates[randIndex]

		resp, err = fn(ctx, state.client)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			b.logger.Error("failed to get response from a storage node",
				"node", state.node,
				"err", err,
				"runtime_id", runtimeID,
			)
			continue
		}
		return resp, err
	}
	return nil, err
}

func (b *storageClientBackend) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	rq := storage.ReadSyncerRequest{
		Request: cbor.Marshal(request),
	}
	rspRaw, err := b.readWithClient(
		ctx,
		request.Tree.Root.Namespace,
		func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
			return c.SyncGet(ctx, &rq)
		},
	)
	if err != nil {
		return nil, err
	}
	rsp := rspRaw.(*storage.ReadSyncerResponse)

	var syncerRsp api.ProofResponse
	if err = cbor.Unmarshal(rsp.Response, &syncerRsp); err != nil {
		return nil, err
	}
	return &syncerRsp, nil
}

func (b *storageClientBackend) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	rq := storage.ReadSyncerRequest{
		Request: cbor.Marshal(request),
	}
	rspRaw, err := b.readWithClient(
		ctx,
		request.Tree.Root.Namespace,
		func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
			return c.SyncGetPrefixes(ctx, &rq)
		},
	)
	if err != nil {
		return nil, err
	}
	rsp := rspRaw.(*storage.ReadSyncerResponse)

	var syncerRsp api.ProofResponse
	if err = cbor.Unmarshal(rsp.Response, &syncerRsp); err != nil {
		return nil, err
	}
	return &syncerRsp, nil
}

func (b *storageClientBackend) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	rq := storage.ReadSyncerRequest{
		Request: cbor.Marshal(request),
	}
	rspRaw, err := b.readWithClient(
		ctx,
		request.Tree.Root.Namespace,
		func(ctx context.Context, c storage.StorageClient) (interface{}, error) {
			return c.SyncIterate(ctx, &rq)
		},
	)
	if err != nil {
		return nil, err
	}
	rsp := rspRaw.(*storage.ReadSyncerResponse)

	var syncerRsp api.ProofResponse
	if err = cbor.Unmarshal(rsp.Response, &syncerRsp); err != nil {
		return nil, err
	}
	return &syncerRsp, nil
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

	pipe := writelog.NewPipeIterator(ctx)

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

	pipe := writelog.NewPipeIterator(ctx)

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
