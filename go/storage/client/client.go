// Package client implements a client for Oasis storage nodes.
// The client connects to nodes as directed by the node watcher.
package client

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"io"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/nodes/grpc"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
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

// Option is a storage client option.
type Option func(b *storageClientBackend)

// storageClientBackend contains all information about the client storage API
// backend, including the backend state and the connected storage nodes' state.
type storageClientBackend struct {
	ctx context.Context

	logger *logging.Logger

	nodesClient grpc.NodesClient
	runtime     registry.RuntimeDescriptorProvider
}

func (b *storageClientBackend) ensureInitialized(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.Initialized():
	}
	return nil
}

// Implements api.StorageClient.
func (b *storageClientBackend) GetConnectedNodes() []*node.Node {
	var nodes []*node.Node
	for _, conn := range b.nodesClient.GetConnectionsWithMeta() {
		nodes = append(nodes, conn.Node)
	}
	return nodes
}

// Implements api.StorageClient.
func (b *storageClientBackend) EnsureCommitteeVersion(ctx context.Context, version int64) error {
	return b.nodesClient.EnsureVersion(ctx, version)
}

func (b *storageClientBackend) readWithClient(
	ctx context.Context,
	ns common.Namespace,
	fn func(context.Context, api.Backend) (interface{}, error),
) (interface{}, error) {
	if err := b.ensureInitialized(ctx); err != nil {
		return nil, err
	}

	var resp interface{}
	op := func() error {
		conns := b.nodesClient.GetConnectionsMap()
		if len(conns) == 0 {
			b.logger.Error("readWithClient: no connected nodes for runtime",
				"runtime_id", ns,
			)
			return ErrStorageNotAvailable
		}

		var nodes []*grpc.ConnWithNodeMeta
		// If a storage node priority hint is set, prioritize overlapping nodes.
		for _, nodeID := range api.NodePriorityHintFromContext(ctx) {
			c, ok := conns[nodeID]
			if !ok {
				continue
			}
			if !api.IsNodeBlacklistedInContext(ctx, c.Node) {
				nodes = append(nodes, c)
			}
			delete(conns, nodeID)
		}
		prioritySlots := len(nodes)
		// Then add the rest of the nodes in random order.
		for _, c := range conns {
			if !api.IsNodeBlacklistedInContext(ctx, c.Node) {
				nodes = append(nodes, c)
			}
		}

		// TODO: Use a more clever approach to choose the order in which to read
		// from the connected nodes:
		// https://github.com/oasisprotocol/oasis-core/issues/1815.
		rng := rand.New(mathrand.New(cryptorand.Reader))
		priorityNodes := nodes[:prioritySlots]
		rng.Shuffle(len(priorityNodes), func(i, j int) {
			priorityNodes[i], priorityNodes[j] = priorityNodes[j], priorityNodes[i]
		})
		ordinaryNodes := nodes[prioritySlots:]
		rng.Shuffle(len(ordinaryNodes), func(i, j int) {
			ordinaryNodes[i], ordinaryNodes[j] = ordinaryNodes[j], ordinaryNodes[i]
		})

		var err error
		for _, conn := range nodes {
			backend := api.NewStorageClient(conn.ClientConn)

			resp, err = fn(ctx, backend)
			if err != nil {
				b.logger.Error("failed to get response from a storage node",
					"node", conn.Node,
					"err", err,
					"runtime_id", ns,
				)
				if ctx.Err() != nil {
					return backoff.Permanent(ctx.Err())
				}
				continue
			}
			cb := api.NodeSelectionCallbackFromContext(ctx)
			if cb != nil {
				cb(conn.Node)
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
			it, err := c.GetDiff(ctx, request)
			if err != nil {
				return nil, err
			}

			// Convert everything into a static write log iterator so we catch all errors early.
			var wl api.WriteLog
			for {
				more, err := it.Next()
				if err != nil {
					return nil, err
				}
				if !more {
					break
				}

				chunk, err := it.Value()
				if err != nil {
					return nil, err
				}
				wl = append(wl, chunk)
			}
			return writelog.NewStaticIterator(wl), nil
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
	return b.nodesClient.Initialized()
}
