// Package client implements a client for Oasis storage nodes.
// The client obtains storage info by following scheduler committees.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/mathrand"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

var (
	_ api.Backend       = (*storageClientBackend)(nil)
	_ api.ClientBackend = (*storageClientBackend)(nil)
)

var (
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

	debugRuntimeID *common.Namespace

	runtimeWatcher storageWatcher

	haltCtx  context.Context
	cancelFn context.CancelFunc
}

// GetConnectedNodes returns registry node information about all connected
// storage nodes.
func (b *storageClientBackend) GetConnectedNodes() []*node.Node {
	return b.runtimeWatcher.getConnectedNodes()
}

type grpcResponse struct {
	resp interface{}
	err  error
	// This node pointer is used to identify a (potentially) misbehaving node.
	node *node.Node
}

func (b *storageClientBackend) getRequestRuntime(ns common.Namespace) common.Namespace {
	// In debug mode always connect to the debug watcher.
	if b.debugRuntimeID != nil {
		return *b.debugRuntimeID
	}

	// Otherwise, use the request namespace.
	return ns
}

func (b *storageClientBackend) writeWithClient(
	ctx context.Context,
	ns common.Namespace,
	round uint64,
	fn func(context.Context, api.Backend, *node.Node) (interface{}, error),
	expectedNewRoots []hash.Hash,
) ([]*api.Receipt, error) {
	runtimeID := b.getRequestRuntime(ns)
	clientStates := b.runtimeWatcher.getClientStates()
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
				var rerr error
				resp, rerr = fn(ctx, client, node)
				if status.Code(rerr) == codes.PermissionDenied && numRetries < maxRetries {
					// Writes can fail around an epoch transition due to policy errors,
					// make sure to retry in this case (up to maxRetries).
					numRetries++
					return rerr
				}
				return backoff.Permanent(rerr)
			}

			sched := backoff.NewConstantBackOff(retryInterval)
			rerr := backoff.Retry(op, backoff.WithContext(sched, ctx))

			ch <- &grpcResponse{
				resp: resp,
				err:  rerr,
				node: node,
			}
		}()
	}

	// Accumulate the responses.
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

		var receiptList []*api.Receipt
		var ok bool
		if receiptList, ok = response.resp.([]*api.Receipt); !ok {
			b.logger.Error("got unexpected response type from a storage node",
				"node", response.node,
				"resp", response.resp,
			)
			continue
		}

		// NOTE: All storage backend implementations of apply operations return
		// a list of storage receipts. However, a concrete storage backend,
		// e.g. storage/database, actually returns a single storage receipt
		// in a list.
		if len(receiptList) != 1 {
			b.logger.Error("got more than one receipt from a storage node",
				"node", response.node,
				"num_receipts", len(receiptList),
			)
			continue
		}
		receipt := receiptList[0]

		// Validate the receipt signature, and unmarshal the body.
		//
		// Note: It is theoretically possible to batch the signature
		// verifications, however the straight forward way of doing
		// so is difficult when wanting to return early, ie: after
		// F+1 successes.
		//
		// As it is likely that network delay will dominate, the
		// signature verification is done serially here.
		var receiptBody api.ReceiptBody
		if err := receipt.Open(&receiptBody); err != nil {
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
		// TODO: Only wait for F+1 successful writes:
		// https://github.com/oasislabs/oasis-core/issues/1821.
		receipts = append(receipts, receipt)
	}

	successes := len(receipts)
	if successes == 0 {
		return nil, errors.New("storage client: failed to write to any storage node")
	} else if successes < n {
		b.logger.Warn("write operation only partially applied",
			"connected_nodes", n,
			"successful_writes", successes,
		)
	}

	return receipts, nil
}

func (b *storageClientBackend) Apply(ctx context.Context, request *api.ApplyRequest) ([]*api.Receipt, error) {
	return b.writeWithClient(
		ctx,
		request.Namespace,
		request.DstRound,
		func(ctx context.Context, c api.Backend, node *node.Node) (interface{}, error) {
			return c.Apply(ctx, request)
		},
		[]hash.Hash{request.DstRoot},
	)
}

func (b *storageClientBackend) ApplyBatch(ctx context.Context, request *api.ApplyBatchRequest) ([]*api.Receipt, error) {
	expectedNewRoots := make([]hash.Hash, 0, len(request.Ops))
	for _, op := range request.Ops {
		expectedNewRoots = append(expectedNewRoots, op.DstRoot)
	}

	return b.writeWithClient(
		ctx,
		request.Namespace,
		request.DstRound,
		func(ctx context.Context, c api.Backend, node *node.Node) (interface{}, error) {
			return c.ApplyBatch(ctx, request)
		},
		expectedNewRoots,
	)
}

func (b *storageClientBackend) Merge(ctx context.Context, request *api.MergeRequest) ([]*api.Receipt, error) {
	return b.writeWithClient(
		ctx,
		request.Namespace,
		request.Round+1,
		func(ctx context.Context, c api.Backend, node *node.Node) (interface{}, error) {
			return c.Merge(ctx, request)
		},
		nil,
	)
}

func (b *storageClientBackend) MergeBatch(ctx context.Context, request *api.MergeBatchRequest) ([]*api.Receipt, error) {
	return b.writeWithClient(
		ctx,
		request.Namespace,
		request.Round+1,
		func(ctx context.Context, c api.Backend, node *node.Node) (interface{}, error) {
			return c.MergeBatch(ctx, request)
		},
		nil,
	)
}

func (b *storageClientBackend) readWithClient(
	ctx context.Context,
	ns common.Namespace,
	fn func(context.Context, api.Backend) (interface{}, error),
) (interface{}, error) {
	runtimeID := b.getRequestRuntime(ns)
	clientStates := b.runtimeWatcher.getClientStates()
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

	var (
		err  error
		resp interface{}
	)
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
	rsp, err := b.readWithClient(
		ctx,
		request.Tree.Root.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return c.SyncGet(ctx, request)
		},
	)
	if err != nil {
		return nil, err
	}
	return rsp.(*api.ProofResponse), nil
}

func (b *storageClientBackend) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	rsp, err := b.readWithClient(
		ctx,
		request.Tree.Root.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return c.SyncGetPrefixes(ctx, request)
		},
	)
	if err != nil {
		return nil, err
	}
	return rsp.(*api.ProofResponse), nil
}

func (b *storageClientBackend) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	rsp, err := b.readWithClient(
		ctx,
		request.Tree.Root.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return c.SyncIterate(ctx, request)
		},
	)
	if err != nil {
		return nil, err
	}
	return rsp.(*api.ProofResponse), nil
}

func (b *storageClientBackend) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	rsp, err := b.readWithClient(
		ctx,
		request.StartRoot.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return c.GetDiff(ctx, request)
		},
	)
	if err != nil {
		return nil, err
	}
	return rsp.(api.WriteLogIterator), nil
}

func (b *storageClientBackend) GetCheckpoint(ctx context.Context, request *api.GetCheckpointRequest) (api.WriteLogIterator, error) {
	rsp, err := b.readWithClient(
		ctx,
		request.Root.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return c.GetCheckpoint(ctx, request)
		},
	)
	if err != nil {
		return nil, err
	}
	return rsp.(api.WriteLogIterator), nil
}

func (b *storageClientBackend) Cleanup() {
	b.cancelFn()
	b.runtimeWatcher.cleanup()
}

func (b *storageClientBackend) Initialized() <-chan struct{} {
	return b.runtimeWatcher.initialized()
}
