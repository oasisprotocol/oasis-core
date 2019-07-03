package storage

import (
	"bytes"
	"context"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/api"

	pb "github.com/oasislabs/ekiden/go/grpc/storage"
)

const (
	// GetDiffChunkEntryCount defines the maximum number of write log entries
	// that go into a single GetDiff response chunk.
	GetDiffChunkEntryCount int = 10
)

var _ pb.StorageServer = (*grpcServer)(nil)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) Apply(ctx context.Context, req *pb.ApplyRequest) (*pb.ApplyResponse, error) {
	var root hash.Hash
	if err := root.UnmarshalBinary(req.GetRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal root")
	}

	var expectedNewRoot hash.Hash
	if err := expectedNewRoot.UnmarshalBinary(req.GetExpectedNewRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal expected new root")
	}

	var log api.WriteLog
	for _, item := range req.GetLog() {
		log = append(log, api.LogEntry{
			Key:   item.GetKey(),
			Value: item.GetValue(),
		})
	}

	<-s.backend.Initialized()
	receipts, err := s.backend.Apply(ctx, root, expectedNewRoot, log)

	if err != nil {
		return nil, err
	}

	return &pb.ApplyResponse{Receipts: cbor.Marshal(receipts)}, nil
}

func (s *grpcServer) ApplyBatch(ctx context.Context, req *pb.ApplyBatchRequest) (*pb.ApplyBatchResponse, error) {
	var ops []api.ApplyOp
	for _, op := range req.GetOps() {
		var root hash.Hash
		if err := root.UnmarshalBinary(op.GetRoot()); err != nil {
			return nil, errors.Wrap(err, "storage: failed to unmarshal root")
		}

		var expectedNewRoot hash.Hash
		if err := expectedNewRoot.UnmarshalBinary(op.GetExpectedNewRoot()); err != nil {
			return nil, errors.Wrap(err, "storage: failed to unmarshal expected new root")
		}

		var log api.WriteLog
		for _, item := range op.GetLog() {
			log = append(log, api.LogEntry{
				Key:   item.GetKey(),
				Value: item.GetValue(),
			})
		}

		ops = append(ops, api.ApplyOp{
			Root:            root,
			ExpectedNewRoot: expectedNewRoot,
			WriteLog:        log,
		})
	}

	<-s.backend.Initialized()
	receipts, err := s.backend.ApplyBatch(ctx, ops)

	if err != nil {
		return nil, err
	}

	return &pb.ApplyBatchResponse{Receipts: cbor.Marshal(receipts)}, nil
}

func (s *grpcServer) GetSubtree(ctx context.Context, req *pb.GetSubtreeRequest) (*pb.GetSubtreeResponse, error) {
	var root hash.Hash
	if err := root.UnmarshalBinary(req.GetRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal root")
	}

	maxDepth := uint8(req.GetMaxDepth())

	nid := req.GetId()
	var path hash.Hash
	if err := path.UnmarshalBinary(nid.GetPath()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal id")
	}

	nodeID := api.NodeID{
		Path:  path,
		Depth: uint8(nid.GetDepth()),
	}

	<-s.backend.Initialized()
	subtree, err := s.backend.GetSubtree(ctx, root, nodeID, maxDepth)
	if err != nil {
		return nil, err
	}

	serializedSubtree, err := subtree.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &pb.GetSubtreeResponse{Subtree: serializedSubtree}, nil
}

func (s *grpcServer) GetPath(ctx context.Context, req *pb.GetPathRequest) (*pb.GetPathResponse, error) {
	var root hash.Hash
	if err := root.UnmarshalBinary(req.GetRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal root")
	}

	var key hash.Hash
	if err := key.UnmarshalBinary(req.GetKey()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal key")
	}

	startDepth := uint8(req.GetStartDepth())

	<-s.backend.Initialized()
	subtree, err := s.backend.GetPath(ctx, root, key, startDepth)
	if err != nil {
		return nil, err
	}

	serializedSubtree, err := subtree.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &pb.GetPathResponse{Subtree: serializedSubtree}, nil
}

func (s *grpcServer) GetNode(ctx context.Context, req *pb.GetNodeRequest) (*pb.GetNodeResponse, error) {
	var root hash.Hash
	if err := root.UnmarshalBinary(req.GetRoot()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal root")
	}

	nid := req.GetId()
	var path hash.Hash
	if err := path.UnmarshalBinary(nid.GetPath()); err != nil {
		return nil, errors.Wrap(err, "storage: failed to unmarshal id")
	}

	nodeID := api.NodeID{
		Path:  path,
		Depth: uint8(nid.GetDepth()),
	}

	<-s.backend.Initialized()
	node, err := s.backend.GetNode(ctx, root, nodeID)
	if err != nil {
		return nil, err
	}

	serializedNode, err := node.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return &pb.GetNodeResponse{Node: serializedNode}, nil
}

func (s *grpcServer) GetDiff(req *pb.GetDiffRequest, stream pb.Storage_GetDiffServer) error {
	var startHash hash.Hash
	if err := startHash.UnmarshalBinary(req.GetStartHash()); err != nil {
		return errors.Wrap(err, "storage: failed to unmarshal start hash")
	}

	var endHash hash.Hash
	if err := endHash.UnmarshalBinary(req.GetEndHash()); err != nil {
		return errors.Wrap(err, "storage: failed to unmarshal end hash")
	}

	syncOptions := req.GetOpts()

	<-s.backend.Initialized()

	it, err := s.backend.GetDiff(stream.Context(), startHash, endHash)
	if err != nil {
		return err
	}

	var totalSent uint64
	skipping := true
	final := false
	done := false
	totalSent = 0

	if len(syncOptions.GetOffsetKey()) == 0 {
		skipping = false
	}

	for {
		var entryArray []*pb.LogEntry
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
				if bytes.Equal(entry.Key, syncOptions.GetOffsetKey()) {
					skipping = false
				}
				continue
			}

			entryArray = append(entryArray, &pb.LogEntry{
				Key:   entry.Key,
				Value: entry.Value,
			})
			totalSent++
			if (syncOptions.GetLimit() > 0 && totalSent >= syncOptions.GetLimit()) || len(entryArray) >= GetDiffChunkEntryCount {
				done = true
				break
			}
		}
		resp := &pb.GetDiffResponse{
			Final: final,
			Log:   entryArray,
		}

		if err := stream.Send(resp); err != nil {
			return err
		}

		if done || final {
			break
		}
	}

	return nil
}

// NewGRPCServer intializes and registers a grpc storage server backed
// by the provided Backend.
func NewGRPCServer(srv *grpc.Server, b api.Backend) {
	s := &grpcServer{
		backend: b,
	}

	pb.RegisterStorageServer(srv, s)
}
