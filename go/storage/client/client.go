// Package client implements a client for Oasis storage nodes.
// The client obtains storage info by following scheduler committees.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/committee"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var (
	_ api.Backend       = (*storageClientBackend)(nil)
	_ api.ClientBackend = (*storageClientBackend)(nil)
)

// ErrStorageNotAvailable is the error returned when no storage node is available.
var ErrStorageNotAvailable = errors.New("storage/client: storage not available")

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

	committeeClient committee.Client
	runtime         registry.RuntimeDescriptorProvider
}

// Implements api.StorageClient.
func (b *storageClientBackend) GetConnectedNodes() []*node.Node {
	var nodes []*node.Node
	for _, conn := range b.committeeClient.GetConnectionsWithMeta() {
		nodes = append(nodes, conn.Node)
	}
	return nodes
}

// Implements api.StorageClient.
func (b *storageClientBackend) EnsureCommitteeVersion(ctx context.Context, version int64) error {
	return b.committeeClient.EnsureVersion(ctx, version)
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
	fn func(context.Context, api.Backend, *node.Node) (interface{}, error),
	expectedNewRoots []hash.Hash,
) ([]*api.Receipt, error) {
	conns := b.committeeClient.GetConnectionsWithMeta()
	n := len(conns)
	if n == 0 {
		b.logger.Error("writeWithClient: no connected nodes for runtime",
			"runtime_id", ns,
		)
		return nil, ErrStorageNotAvailable
	}

	// Determine the minimum replication factor. In case we don't have a runtime descriptor provider
	// we make the safe choice of assuming that the replication factor is the same as the size of
	// the storage committee.
	minWriteReplication := n
	if b.runtime != nil {
		rt, err := b.runtime.RegistryDescriptor(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch registry descriptor: %w", err)
		}

		minWriteReplication = int(rt.Storage.MinWriteReplication)
	}

	// Use a buffered channel to allow all "write" goroutines to return as soon
	// as they are finished.
	ch := make(chan *grpcResponse, n)
	for _, conn := range conns {
		go func(conn *committee.ClientConnWithMeta) {
			var resp interface{}
			op := func() error {
				var rerr error
				resp, rerr = fn(ctx, api.NewStorageClient(conn.ClientConn), conn.Node)
				switch {
				case status.Code(rerr) == codes.Unavailable:
					// Storage node may be temporarily unavailable.
					return rerr
				case status.Code(rerr) == codes.PermissionDenied:
					// Writes can fail around an epoch transition due to policy errors.
					return rerr
				case errors.Is(rerr, api.ErrNodeNotFound),
					errors.Is(rerr, api.ErrPreviousVersionMismatch),
					errors.Is(rerr, api.ErrRootNotFound):
					// Storage node may not be completely synced yet.
					return rerr
				default:
					// All other errors are permanent.
					return backoff.Permanent(rerr)
				}
			}

			sched := backoff.WithMaxRetries(backoff.NewConstantBackOff(retryInterval), maxRetries)
			rerr := backoff.Retry(op, backoff.WithContext(sched, ctx))

			ch <- &grpcResponse{
				resp: resp,
				err:  rerr,
				node: conn.Node,
			}
		}(conn)
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

		receipts = append(receipts, receipt)
		if len(receipts) >= minWriteReplication {
			break
		}
	}

	successes := len(receipts)
	switch {
	case successes == 0:
		// All writes have failed.
		return nil, errors.New("storage client: failed to write to any storage node")
	case successes < minWriteReplication:
		// Replication was less than the minimum required factor.
		b.logger.Warn("write operation only partially applied",
			"min_write_replication", minWriteReplication,
			"successful_writes", successes,
		)
		if b.runtime != nil {
			// In case the minimum write replication factor is set by the runtime, it doesn't make
			// sense to emit partial receipts as other nodes will not accept them.
			return nil, fmt.Errorf("storage client: write operation only partially applied")
		}
		return receipts, nil
	default:
		return receipts, nil
	}
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

func (b *storageClientBackend) readWithClient(
	ctx context.Context,
	ns common.Namespace,
	fn func(context.Context, api.Backend) (interface{}, error),
) (interface{}, error) {
	var resp interface{}
	op := func() error {
		conns := b.committeeClient.GetConnectionsWithMeta()
		n := len(conns)
		if n == 0 {
			b.logger.Error("readWithClient: no connected nodes for runtime",
				"runtime_id", ns,
			)
			return ErrStorageNotAvailable
		}

		// TODO: Use a more clever approach to choose the order in which to read
		// from the connected nodes:
		// https://github.com/oasisprotocol/oasis-core/issues/1815.
		rng := rand.New(mathrand.New(cryptorand.Reader))

		var err error
		for _, randIndex := range rng.Perm(n) {
			conn := conns[randIndex]

			resp, err = fn(ctx, api.NewStorageClient(conn.ClientConn))
			if ctx.Err() != nil {
				return backoff.Permanent(ctx.Err())
			}
			if err != nil {
				b.logger.Error("failed to get response from a storage node",
					"node", conn.Node,
					"err", err,
					"runtime_id", ns,
				)
				continue
			}
			return nil
		}
		return err
	}

	sched := backoff.WithMaxRetries(backoff.NewConstantBackOff(retryInterval), maxRetries)
	err := backoff.Retry(op, backoff.WithContext(sched, ctx))
	return resp, err
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

func (b *storageClientBackend) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	rsp, err := b.readWithClient(
		ctx,
		request.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return c.GetCheckpoints(ctx, request)
		},
	)
	if err != nil {
		return nil, err
	}
	return rsp.([]*checkpoint.Metadata), nil
}

func (b *storageClientBackend) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	_, err := b.readWithClient(
		ctx,
		chunk.Root.Namespace,
		func(ctx context.Context, c api.Backend) (interface{}, error) {
			return nil, c.GetCheckpointChunk(ctx, chunk, w)
		},
	)
	return err
}

func (b *storageClientBackend) Cleanup() {
}

func (b *storageClientBackend) Initialized() <-chan struct{} {
	return b.committeeClient.Initialized()
}
