package registry

import (
	"context"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/storage/api"
)

var _ api.Backend = (*storageRouter)(nil)

type storageRouter struct {
	registry Registry
}

func (sr *storageRouter) getRuntime(ns common.Namespace) (Runtime, error) {
	id, err := ns.ToRuntimeID()
	if err != nil {
		return nil, err
	}
	return sr.registry.GetRuntime(id)
}

func (sr *storageRouter) SyncGet(ctx context.Context, request *api.GetRequest) (*api.ProofResponse, error) {
	rt, err := sr.getRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().SyncGet(ctx, request)
}

func (sr *storageRouter) SyncGetPrefixes(ctx context.Context, request *api.GetPrefixesRequest) (*api.ProofResponse, error) {
	rt, err := sr.getRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().SyncGetPrefixes(ctx, request)
}

func (sr *storageRouter) SyncIterate(ctx context.Context, request *api.IterateRequest) (*api.ProofResponse, error) {
	rt, err := sr.getRuntime(request.Tree.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().SyncIterate(ctx, request)
}

func (sr *storageRouter) Apply(ctx context.Context, request *api.ApplyRequest) ([]*api.Receipt, error) {
	rt, err := sr.getRuntime(request.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().Apply(ctx, request)
}

func (sr *storageRouter) ApplyBatch(ctx context.Context, request *api.ApplyBatchRequest) ([]*api.Receipt, error) {
	rt, err := sr.getRuntime(request.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().ApplyBatch(ctx, request)
}

func (sr *storageRouter) Merge(ctx context.Context, request *api.MergeRequest) ([]*api.Receipt, error) {
	rt, err := sr.getRuntime(request.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().Merge(ctx, request)
}

func (sr *storageRouter) MergeBatch(ctx context.Context, request *api.MergeBatchRequest) ([]*api.Receipt, error) {
	rt, err := sr.getRuntime(request.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().MergeBatch(ctx, request)
}

func (sr *storageRouter) GetDiff(ctx context.Context, request *api.GetDiffRequest) (api.WriteLogIterator, error) {
	rt, err := sr.getRuntime(request.StartRoot.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().GetDiff(ctx, request)
}

func (sr *storageRouter) GetCheckpoint(ctx context.Context, request *api.GetCheckpointRequest) (api.WriteLogIterator, error) {
	rt, err := sr.getRuntime(request.Root.Namespace)
	if err != nil {
		return nil, err
	}
	return rt.Storage().GetCheckpoint(ctx, request)
}

func (sr *storageRouter) Cleanup() {
}

func (sr *storageRouter) Initialized() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		for _, rt := range sr.registry.Runtimes() {
			<-rt.Storage().Initialized()
		}
	}()
	return ch
}
