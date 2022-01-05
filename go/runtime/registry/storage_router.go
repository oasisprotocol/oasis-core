package registry

import (
	"context"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
)

var _ api.Backend = (*storageRouter)(nil)

type RouterRuntimeStorageFunc func(ns common.Namespace) (api.Backend, error)

type RouterInitWaitFunc func()

type storageRouter struct {
	getRuntime RouterRuntimeStorageFunc
	initWaiter RouterInitWaitFunc
}

func (sr *storageRouter) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	storage, err := sr.getRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return storage.SyncGet(ctx, request)
}

func (sr *storageRouter) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	storage, err := sr.getRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return storage.SyncGetPrefixes(ctx, request)
}

func (sr *storageRouter) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	storage, err := sr.getRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return storage.SyncIterate(ctx, request)
}

func (sr *storageRouter) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	storage, err := sr.getRuntime(request.StartRoot.Namespace)
	if err != nil {
		return nil, err
	}
	return storage.GetDiff(ctx, request)
}

func (sr *storageRouter) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	storage, err := sr.getRuntime(request.Namespace)
	if err != nil {
		return nil, err
	}
	return storage.GetCheckpoints(ctx, request)
}

func (sr *storageRouter) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	storage, err := sr.getRuntime(chunk.Root.Namespace)
	if err != nil {
		return err
	}
	return storage.GetCheckpointChunk(ctx, chunk, w)
}

func (sr *storageRouter) Cleanup() {
}

func (sr *storageRouter) Initialized() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		sr.initWaiter()
	}()
	return ch
}

func NewStorageRouter(runtimeGetter RouterRuntimeStorageFunc, waiter RouterInitWaitFunc) api.Backend {
	return &storageRouter{
		getRuntime: runtimeGetter,
		initWaiter: waiter,
	}
}
