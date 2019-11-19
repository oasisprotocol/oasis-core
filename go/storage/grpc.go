package storage

import (
	"bytes"
	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/accessctl"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	commonGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	"github.com/oasislabs/oasis-core/go/storage/api"

	pb "github.com/oasislabs/oasis-core/go/grpc/storage"
)

const (
	// WriteLogIteratorChunkSize defines the chunk size of write log entries
	// for GetCheckpoint and GetDiff methods.
	WriteLogIteratorChunkSize int = 10
)

var _ pb.StorageServer = (*GrpcServer)(nil)

type GrpcServer struct {
	backend api.Backend
	commonGrpc.RuntimePolicyChecker

	ignoreApply bool
}

func (s *GrpcServer) Apply(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	if s.ignoreApply {
		return nil, errors.New("storage: ignoring apply operation")
	}
	var ns common.Namespace
	if err := ns.UnmarshalBinary(req.GetNamespace()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal namespace")
	}
	if err := s.CheckAccessAllowed(ctx, accessctl.Action("Apply"), ns); err != nil {
		return nil, err
	}

	var srcRoot, dstRoot hash.Hash
	if err := srcRoot.UnmarshalBinary(req.GetSrcRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal src root")
	}
	if err := dstRoot.UnmarshalBinary(req.GetDstRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal dst root")
	}

	var log api.WriteLog
	for _, item := range req.GetLog() {
		log = append(log, api.LogEntry{
			Key:   append([]byte{}, item.GetKey()...),
			Value: append([]byte{}, item.GetValue()...),
		})
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}
	receipts, err := s.backend.Apply(ctx, ns, req.GetSrcRound(), srcRoot, req.GetDstRound(), dstRoot, log)

	if err != nil {
		return nil, err
	}

	return &pb.ApplyResponse{Receipts: cbor.Marshal(receipts)}, nil
}

func (s *GrpcServer) ApplyBatch(ctx context.Context, req *pb.ApplyBatchRequest) (*pb.ApplyBatchResponse, error) {
	if s.ignoreApply {
		return nil, errors.New("storage: ignoring apply operation")
	}
	var ns common.Namespace
	if err := ns.UnmarshalBinary(req.GetNamespace()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal namespace")
	}
	if err := s.CheckAccessAllowed(ctx, accessctl.Action("ApplyBatch"), ns); err != nil {
		return nil, err
	}

	var ops []api.ApplyOp
	for _, op := range req.GetOps() {
		var srcRoot, dstRoot hash.Hash
		if err := srcRoot.UnmarshalBinary(op.GetSrcRoot()); err != nil {
			return nil, errors.Wrap(err, "storage: failed to unmarshal src root")
		}
		if err := dstRoot.UnmarshalBinary(op.GetDstRoot()); err != nil {
			return nil, errors.Wrap(err, "storage: failed to unmarshal dst root")
		}

		var log api.WriteLog
		for _, item := range op.GetLog() {
			log = append(log, api.LogEntry{
				Key:   append([]byte{}, item.GetKey()...),
				Value: append([]byte{}, item.GetValue()...),
			})
		}

		ops = append(ops, api.ApplyOp{
			SrcRound: op.GetSrcRound(),
			SrcRoot:  srcRoot,
			DstRoot:  dstRoot,
			WriteLog: log,
		})
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}
	receipts, err := s.backend.ApplyBatch(ctx, ns, req.GetDstRound(), ops)

	if err != nil {
		return nil, err
	}

	return &pb.ApplyBatchResponse{Receipts: cbor.Marshal(receipts)}, nil
}

func (s *GrpcServer) Merge(ctx context.Context, req *pb.MergeRequest) (*pb.MergeResponse, error) {
	var ns common.Namespace
	if err := ns.UnmarshalBinary(req.GetNamespace()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal namespace")
	}
	if err := s.CheckAccessAllowed(ctx, accessctl.Action("Merge"), ns); err != nil {
		return nil, err
	}

	var base hash.Hash
	if err := base.UnmarshalBinary(req.GetBase()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal base root")
	}

	var others []hash.Hash
	for _, item := range req.GetOthers() {
		var h hash.Hash
		if err := h.UnmarshalBinary(item); err != nil {
			return nil, errors.Wrap(err, "storage: failed to unmarshal other root")
		}
		others = append(others, h)
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}

	receipts, err := s.backend.Merge(ctx, ns, req.GetRound(), base, others)
	if err != nil {
		return nil, err
	}

	return &pb.MergeResponse{Receipts: cbor.Marshal(receipts)}, nil
}

func (s *GrpcServer) MergeBatch(ctx context.Context, req *pb.MergeBatchRequest) (*pb.MergeBatchResponse, error) {
	var ns common.Namespace
	if err := ns.UnmarshalBinary(req.GetNamespace()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal namespace")
	}
	if err := s.CheckAccessAllowed(ctx, accessctl.Action("MergeBatch"), ns); err != nil {
		return nil, err
	}

	var ops []api.MergeOp
	for _, op := range req.GetOps() {
		var base hash.Hash
		if err := base.UnmarshalBinary(op.GetBase()); err != nil {
			return nil, errors.Wrap(err, "storage: failed to unmarshal base root")
		}

		var others []hash.Hash
		for _, item := range op.GetOthers() {
			var h hash.Hash
			if err := h.UnmarshalBinary(item); err != nil {
				return nil, errors.Wrap(err, "storage: failed to unmarshal other root")
			}
			others = append(others, h)
		}

		ops = append(ops, api.MergeOp{
			Base:   base,
			Others: others,
		})
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}
	receipts, err := s.backend.MergeBatch(ctx, ns, req.GetRound(), ops)

	if err != nil {
		return nil, err
	}

	return &pb.MergeBatchResponse{Receipts: cbor.Marshal(receipts)}, nil
}

func (s *GrpcServer) SyncGet(ctx context.Context, req *pb.ReadSyncerRequest) (*pb.ReadSyncerResponse, error) {
	var rq api.GetRequest
	if err := cbor.Unmarshal(req.Request, &rq); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal request")
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}
	rsp, err := s.backend.SyncGet(ctx, &rq)
	if err != nil {
		return nil, err
	}

	return &pb.ReadSyncerResponse{Response: cbor.Marshal(rsp)}, nil
}

func (s *GrpcServer) SyncGetPrefixes(ctx context.Context, req *pb.ReadSyncerRequest) (*pb.ReadSyncerResponse, error) {
	var rq api.GetPrefixesRequest
	if err := cbor.Unmarshal(req.Request, &rq); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal request")
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}
	rsp, err := s.backend.SyncGetPrefixes(ctx, &rq)
	if err != nil {
		return nil, err
	}

	return &pb.ReadSyncerResponse{Response: cbor.Marshal(rsp)}, nil
}

func (s *GrpcServer) SyncIterate(ctx context.Context, req *pb.ReadSyncerRequest) (*pb.ReadSyncerResponse, error) {
	var rq api.IterateRequest
	if err := cbor.Unmarshal(req.Request, &rq); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal request")
	}

	if err := s.ensureBackendInitialized(ctx); err != nil {
		return nil, err
	}
	rsp, err := s.backend.SyncIterate(ctx, &rq)
	if err != nil {
		return nil, err
	}

	return &pb.ReadSyncerResponse{Response: cbor.Marshal(rsp)}, nil
}

// writeLogService implements sending write log iterator for GetDiff and GetCheckpoint methods.
type writeLogService struct {
	opts     *pb.SyncOptions
	iterator api.WriteLogIterator
	send     func(*pb.WriteLogResponse) error
}

func (s *writeLogService) SendWriteLogIterator() error {
	var totalSent uint64
	skipping := true
	final := false
	done := false
	totalSent = 0

	if len(s.opts.GetOffsetKey()) == 0 {
		skipping = false
	}

	for {
		var entryArray []*pb.LogEntry
		for {
			more, err := s.iterator.Next()
			if err != nil {
				return err
			}
			if !more {
				final = true
				break
			}

			entry, err := s.iterator.Value()
			if err != nil {
				return err
			}

			if skipping {
				if bytes.Equal(entry.Key, s.opts.GetOffsetKey()) {
					skipping = false
				}
				continue
			}

			entryArray = append(entryArray, &pb.LogEntry{
				Key:   entry.Key,
				Value: entry.Value,
			})
			totalSent++
			if len(entryArray) >= WriteLogIteratorChunkSize {
				break
			}
			if s.opts.GetLimit() > 0 && totalSent >= s.opts.GetLimit() {
				done = true
				break
			}
		}
		resp := &pb.WriteLogResponse{
			Final: final,
			Log:   entryArray,
		}

		if err := s.send(resp); err != nil {
			return err
		}

		if done || final {
			break
		}
	}

	return nil
}

func (s *GrpcServer) GetDiff(req *pb.GetDiffRequest, stream pb.Storage_GetDiffServer) error {
	var startRoot, endRoot api.Root
	if err := cbor.Unmarshal(req.GetStartRoot(), &startRoot); err != nil {
		return errors.Wrap(err, "storage: failed to unmarshal start root")
	}
	if err := cbor.Unmarshal(req.GetEndRoot(), &endRoot); err != nil {
		return errors.Wrap(err, "storage: failed to unmarshal end root")
	}

	if err := s.CheckAccessAllowed(stream.Context(), accessctl.Action("GetDiff"), startRoot.Namespace); err != nil {
		return err
	}

	if err := s.ensureBackendInitialized(stream.Context()); err != nil {
		return err
	}

	it, err := s.backend.GetDiff(stream.Context(), startRoot, endRoot)
	if err != nil {
		return err
	}

	svc := &writeLogService{
		opts:     req.GetOpts(),
		iterator: it,
		send:     func(resp *pb.WriteLogResponse) error { return stream.Send(resp) },
	}

	return svc.SendWriteLogIterator()
}

func (s *GrpcServer) GetCheckpoint(req *pb.GetCheckpointRequest, stream pb.Storage_GetCheckpointServer) error {
	var root api.Root
	if err := cbor.Unmarshal(req.GetRoot(), &root); err != nil {
		return errors.Wrap(err, "storage: failed to unmarshal root")
	}

	if err := s.CheckAccessAllowed(stream.Context(), accessctl.Action("GetCheckpoint"), root.Namespace); err != nil {
		return err
	}

	if err := s.ensureBackendInitialized(stream.Context()); err != nil {
		return err
	}

	it, err := s.backend.GetCheckpoint(stream.Context(), root)
	if err != nil {
		return err
	}

	svc := &writeLogService{
		opts:     req.GetOpts(),
		iterator: it,
		send:     func(resp *pb.WriteLogResponse) error { return stream.Send(resp) },
	}

	return svc.SendWriteLogIterator()
}

func (s *GrpcServer) ensureBackendInitialized(ctx context.Context) error {
	select {
	case <-s.backend.Initialized():
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// NewGRPCServer initializes and registers a gRPC storage server backend.
// by the provided Backend.
func NewGRPCServer(srv *grpc.Server, b api.Backend, policy commonGrpc.RuntimePolicyChecker, ignoreApply bool) *GrpcServer {
	s := &GrpcServer{
		backend:              b,
		RuntimePolicyChecker: policy,
		ignoreApply:          ignoreApply,
	}

	pb.RegisterStorageServer(srv, s)

	return s
}
