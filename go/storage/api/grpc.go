package api

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/checkpoint"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
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
			WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*ApplyRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
			return true, nil
		})

	// MethodApplyBatch is the ApplyBatch method.
	MethodApplyBatch = ServiceName.NewMethod("ApplyBatch", ApplyBatchRequest{}).
				WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*ApplyBatchRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
			return true, nil
		})

	// MethodGetDiff is the GetDiff method.
	MethodGetDiff = ServiceName.NewMethod("GetDiff", GetDiffRequest{}).
			WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*GetDiffRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.StartRoot.Namespace, nil
		}).
		WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
			return true, nil
		})

	// MethodGetCheckpoints is the GetCheckpoints method.
	MethodGetCheckpoints = ServiceName.NewMethod("GetCheckpoints", checkpoint.GetCheckpointsRequest{}).
				WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			r, ok := req.(*checkpoint.GetCheckpointsRequest)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return r.Namespace, nil
		}).
		WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
			return true, nil
		})

	// MethodGetCheckpointChunk is the GetCheckpointChunk method.
	MethodGetCheckpointChunk = ServiceName.NewMethod("GetCheckpointChunk", checkpoint.ChunkMetadata{}).
					WithNamespaceExtractor(func(ctx context.Context, req interface{}) (common.Namespace, error) {
			cm, ok := req.(*checkpoint.ChunkMetadata)
			if !ok {
				return common.Namespace{}, errInvalidRequestType
			}
			return cm.Root.Namespace, nil
		}).
		WithAccessControl(func(ctx context.Context, req interface{}) (bool, error) {
			return true, nil
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
				MethodName: MethodGetCheckpoints.ShortName(),
				Handler:    handlerGetCheckpoints,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    MethodGetDiff.ShortName(),
				Handler:       handlerGetDiff,
				ServerStreams: true,
			},
			{
				StreamName:    MethodGetCheckpointChunk.ShortName(),
				Handler:       handlerGetCheckpointChunk,
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

func handlerGetCheckpoints( // nolint: golint
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var req checkpoint.GetCheckpointsRequest
	if err := dec(&req); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetCheckpoints(ctx, &req)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: MethodGetCheckpoints.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetCheckpoints(ctx, req.(*checkpoint.GetCheckpointsRequest))
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

func handlerGetCheckpointChunk(srv interface{}, stream grpc.ServerStream) error {
	var md checkpoint.ChunkMetadata
	if err := stream.RecvMsg(&md); err != nil {
		return err
	}

	return srv.(Backend).GetCheckpointChunk(stream.Context(), &md, cmnGrpc.NewStreamWriter(stream))
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

func (c *storageClient) GetCheckpoints(ctx context.Context, request *checkpoint.GetCheckpointsRequest) ([]*checkpoint.Metadata, error) {
	var rsp []*checkpoint.Metadata
	if err := c.conn.Invoke(ctx, MethodGetCheckpoints.FullName(), request, &rsp); err != nil {
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

func (c *storageClient) GetCheckpointChunk(ctx context.Context, chunk *checkpoint.ChunkMetadata, w io.Writer) error {
	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[1], MethodGetCheckpointChunk.FullName())
	if err != nil {
		return err
	}
	if err = stream.SendMsg(chunk); err != nil {
		return err
	}
	if err = stream.CloseSend(); err != nil {
		return err
	}

	for {
		var part []byte
		switch err = stream.RecvMsg(&part); err {
		case nil:
		case io.EOF:
			return nil
		default:
			return err
		}

		if _, err = w.Write(part); err != nil {
			return err
		}
	}
}

func (c *storageClient) Cleanup() {
}

func (c *storageClient) Initialized() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// NewStorageClient creates a new gRPC storage client service.
func NewStorageClient(c *grpc.ClientConn) Backend {
	return &storageClient{c}
}
