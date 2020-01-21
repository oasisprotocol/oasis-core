package api

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/writelog"
)

var (
	errInvalidRequestType = fmt.Errorf("invalid request type")

	// ServiceName is the gRPC service name.
	ServiceName = cmnGrpc.NewServiceName("Storage")

	// MethodSyncGet is the SyncGet method.
	MethodSyncGet = ServiceName.NewMethod("SyncGet", GetRequest{})
	// MethodSyncGetPrefixes is the SyncGetPrefixes method.
	MethodSyncGetPrefixes = ServiceName.NewMethod("SyncGetPrefixes", GetPrefixesRequest{})
	// MethodSyncIterate is the SyncIterate method.
	MethodSyncIterate = ServiceName.NewMethod("SyncIterate", IterateRequest{})
	// MethodApply is the Apply method.
	MethodApply = ServiceName.NewMethod("Apply", ApplyRequest{}).
			WithNamespaceExtractor(func(req interface{}) (common.Namespace, error) {
			r, ok := req.(*ApplyRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(req interface{}) bool {
			return true
		})

	// MethodApplyBatch is the ApplyBatch method.
	MethodApplyBatch = ServiceName.NewMethod("ApplyBatch", ApplyBatchRequest{}).
				WithNamespaceExtractor(func(req interface{}) (common.Namespace, error) {
			r, ok := req.(*ApplyBatchRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(req interface{}) bool {
			return true
		})

	// MethodMerge is the Merge method.
	MethodMerge = ServiceName.NewMethod("Merge", MergeRequest{}).
			WithNamespaceExtractor(func(req interface{}) (common.Namespace, error) {
			r, ok := req.(*MergeRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(req interface{}) bool {
			return true
		})

	// MethodMergeBatch is the MergeBatch method.
	MethodMergeBatch = ServiceName.NewMethod("MergeBatch", MergeBatchRequest{}).
				WithNamespaceExtractor(func(req interface{}) (common.Namespace, error) {
			r, ok := req.(*MergeBatchRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(req interface{}) bool {
			return true
		})

	// MethodGetDiff is the GetDiff method.
	MethodGetDiff = ServiceName.NewMethod("GetDiff", GetDiffRequest{}).
			WithNamespaceExtractor(func(req interface{}) (common.Namespace, error) {
			r, ok := req.(*GetDiffRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.StartRoot.Namespace, nil
		}).
		WithAccessControl(func(req interface{}) bool {
			return true
		})

	// MethodGetCheckpoint is the GetCheckpoint method.
	MethodGetCheckpoint = ServiceName.NewMethod("GetCheckpoint", GetCheckpointRequest{}).
				WithNamespaceExtractor(func(req interface{}) (common.Namespace, error) {
			r, ok := req.(*GetCheckpointRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Root.Namespace, nil
		}).
		WithAccessControl(func(req interface{}) bool {
			return true
		})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(ServiceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: MethodSyncGet.ShortName(),
				Handler:    handlerSyncGet,
			},
			{
				MethodName: MethodSyncGetPrefixes.ShortName(),
				Handler:    handlerSyncGetPrefixes,
			},
			{
				MethodName: MethodSyncIterate.ShortName(),
				Handler:    handlerSyncIterate,
			},
			{
				MethodName: MethodApply.ShortName(),
				Handler:    handlerApply,
			},
			{
				MethodName: MethodApplyBatch.ShortName(),
				Handler:    handlerApplyBatch,
			},
			{
				MethodName: MethodMerge.ShortName(),
				Handler:    handlerMerge,
			},
			{
				MethodName: MethodMergeBatch.ShortName(),
				Handler:    handlerMergeBatch,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    MethodGetDiff.ShortName(),
				Handler:       handlerGetDiff,
				ServerStreams: true,
			},
			{
				StreamName:    MethodGetCheckpoint.ShortName(),
				Handler:       handlerGetCheckpoint,
				ServerStreams: true,
			},
		},
	}
)

func handlerSyncGet( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req GetRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).SyncGet(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodSyncGet.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).SyncGet(ctx, req.(*GetRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerSyncGetPrefixes( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req GetPrefixesRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).SyncGetPrefixes(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodSyncGetPrefixes.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).SyncGetPrefixes(ctx, req.(*GetPrefixesRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerSyncIterate( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req IterateRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).SyncIterate(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodSyncIterate.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).SyncIterate(ctx, req.(*IterateRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerApply( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req ApplyRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Apply(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodApply.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Apply(ctx, req.(*ApplyRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerApplyBatch( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req ApplyBatchRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).ApplyBatch(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodApplyBatch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).ApplyBatch(ctx, req.(*ApplyBatchRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerMerge( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req MergeRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Merge(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodMerge.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Merge(ctx, req.(*MergeRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func handlerMergeBatch( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req MergeBatchRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).MergeBatch(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodMergeBatch.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).MergeBatch(ctx, req.(*MergeBatchRequest))
	}
	return interceptor(ctx, &req, info, handler)
}

func sendWriteLogIterator(it WriteLogIterator, opts *SyncOptions, stream grpc.ServerStream) error {
	var totalSent uint64
	skipping := true
	final := false
	done := false
	totalSent = 0

	if len(opts.OffsetKey) == 0 {
		skipping = false
	}

	for {
		var entryArray []LogEntry
		for {
			more, err := it.Next()
			if err != nil {
				return err
			}
			if !more {
				final = true
				break
			}

			entry, err := it.Value()
			if err != nil {
				return err
			}

			if skipping {
				if bytes.Equal(entry.Key, opts.OffsetKey) {
					skipping = false
				}
				continue
			}

			entryArray = append(entryArray, entry)
			totalSent++
			if len(entryArray) >= WriteLogIteratorChunkSize {
				break
			}
			if opts.Limit > 0 && totalSent >= opts.Limit {
				done = true
				break
			}
		}
		chunk := &SyncChunk{
			Final:    final,
			WriteLog: entryArray,
		}

		if err := stream.SendMsg(chunk); err != nil {
			return err
		}

		if done || final {
			break
		}
	}

	return nil
}

func handlerGetDiff(srv interface{}, stream grpc.ServerStream) error {
	var req GetDiffRequest
	if err := stream.RecvMsg(&req); err != nil {
		return err
	}

	ctx := stream.Context()
	it, err := srv.(Backend).GetDiff(ctx, &req)
	if err != nil {
		return err
	}

	return sendWriteLogIterator(it, &req.Options, stream)
}

func handlerGetCheckpoint(srv interface{}, stream grpc.ServerStream) error {
	var req GetCheckpointRequest
	if err := stream.RecvMsg(&req); err != nil {
		return err
	}

	ctx := stream.Context()
	it, err := srv.(Backend).GetCheckpoint(ctx, &req)
	if err != nil {
		return err
	}

	return sendWriteLogIterator(it, &req.Options, stream)
}

// RegisterService registers a new sentry service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type storageClient struct {
	conn *grpc.ClientConn
}

func (c *storageClient) SyncGet(ctx context.Context, request *GetRequest) (*ProofResponse, error) {
	var rsp ProofResponse
	if err := c.conn.Invoke(ctx, MethodSyncGet.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *storageClient) SyncGetPrefixes(ctx context.Context, request *GetPrefixesRequest) (*ProofResponse, error) {
	var rsp ProofResponse
	if err := c.conn.Invoke(ctx, MethodSyncGetPrefixes.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *storageClient) SyncIterate(ctx context.Context, request *IterateRequest) (*ProofResponse, error) {
	var rsp ProofResponse
	if err := c.conn.Invoke(ctx, MethodSyncIterate.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *storageClient) Apply(ctx context.Context, request *ApplyRequest) ([]*Receipt, error) {
	var rsp []*Receipt
	if err := c.conn.Invoke(ctx, MethodApply.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *storageClient) ApplyBatch(ctx context.Context, request *ApplyBatchRequest) ([]*Receipt, error) {
	var rsp []*Receipt
	if err := c.conn.Invoke(ctx, MethodApplyBatch.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *storageClient) Merge(ctx context.Context, request *MergeRequest) ([]*Receipt, error) {
	var rsp []*Receipt
	if err := c.conn.Invoke(ctx, MethodMerge.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *storageClient) MergeBatch(ctx context.Context, request *MergeBatchRequest) ([]*Receipt, error) {
	var rsp []*Receipt
	if err := c.conn.Invoke(ctx, MethodMergeBatch.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func receiveWriteLogIterator(ctx context.Context, stream grpc.ClientStream) WriteLogIterator {
	pipe := writelog.NewPipeIterator(ctx)

	go func() {
		defer pipe.Close()

		for {
			var chunk SyncChunk
			err := stream.RecvMsg(&chunk)
			if err == io.EOF {
				break
			}
			if err != nil {
				_ = pipe.PutError(err)
				continue
			}

			for i := range chunk.WriteLog {
				if err := pipe.Put(&chunk.WriteLog[i]); err != nil {
					_ = pipe.PutError(err)
				}
			}

			if chunk.Final {
				break
			}
		}
	}()

	return &pipe
}

func (c *storageClient) GetDiff(ctx context.Context, request *GetDiffRequest) (WriteLogIterator, error) {
	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], MethodGetDiff.FullName())
	if err != nil {
		return nil, err
	}
	if err = stream.SendMsg(request); err != nil {
		return nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, err
	}

	return receiveWriteLogIterator(ctx, stream), nil
}

func (c *storageClient) GetCheckpoint(ctx context.Context, request *GetCheckpointRequest) (WriteLogIterator, error) {
	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], MethodGetCheckpoint.FullName())
	if err != nil {
		return nil, err
	}
	if err = stream.SendMsg(request); err != nil {
		return nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, err
	}

	return receiveWriteLogIterator(ctx, stream), nil
}

func (c *storageClient) Cleanup() {
}

func (c *storageClient) Initialized() <-chan struct{} {
	return nil
}

// NewStorageClient creates a new gRPC storage client service.
func NewStorageClient(c *grpc.ClientConn) Backend {
	return &storageClient{c}
}
