package registry

import (
	"context"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/registry/api"

	commonPB "github.com/oasislabs/oasis-core/go/grpc/common"
	pb "github.com/oasislabs/oasis-core/go/grpc/registry"
)

var (
	_ pb.EntityRegistryServer  = (*grpcServer)(nil)
	_ pb.RuntimeRegistryServer = (*grpcServer)(nil)
)

type grpcServer struct {
	backend api.Backend
}

func (s *grpcServer) GetEntity(ctx context.Context, req *pb.EntityRequest) (*pb.EntityResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	ent, err := s.backend.GetEntity(ctx, id, req.GetHeight())
	if err != nil {
		return nil, err
	}

	var resp pb.EntityResponse
	if ent != nil {
		resp.Entity = ent.ToProto()
	}

	return &resp, nil
}

func (s *grpcServer) GetEntities(ctx context.Context, req *pb.EntitiesRequest) (*pb.EntitiesResponse, error) {
	ents, err := s.backend.GetEntities(ctx, req.GetHeight())
	if err != nil {
		return nil, err
	}

	pbEnts := make([]*commonPB.Entity, 0, len(ents))
	for _, v := range ents {
		pbEnts = append(pbEnts, v.ToProto())
	}

	return &pb.EntitiesResponse{Entity: pbEnts}, nil
}

func (s *grpcServer) WatchEntities(req *pb.WatchEntityRequest, stream pb.EntityRegistry_WatchEntitiesServer) error {
	ch, sub := s.backend.WatchEntities()
	defer sub.Close()

	for {
		var ev *api.EntityEvent
		var ok bool

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchEntityResponse{
			EventType: pb.WatchEntityResponse_REGISTERED,
			Entity:    ev.Entity.ToProto(),
		}
		if !ev.IsRegistration {
			resp.EventType = pb.WatchEntityResponse_DEREGISTERED
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *grpcServer) GetNode(ctx context.Context, req *pb.NodeRequest) (*pb.NodeResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	node, err := s.backend.GetNode(ctx, id, req.GetHeight())
	if err != nil {
		return nil, err
	}

	var resp pb.NodeResponse
	if node != nil {
		resp.Node = node.ToProto()
	}

	return &resp, nil
}

func (s *grpcServer) GetNodes(ctx context.Context, req *pb.NodesRequest) (*pb.NodesResponse, error) {
	nodes, err := s.backend.GetNodes(ctx, req.GetHeight())
	if err != nil {
		return nil, err
	}

	pbNodes := make([]*commonPB.Node, 0, len(nodes))
	for _, v := range nodes {
		pbNodes = append(pbNodes, v.ToProto())
	}

	return &pb.NodesResponse{Node: pbNodes}, nil
}

func (s *grpcServer) WatchNodes(req *pb.WatchNodeRequest, stream pb.EntityRegistry_WatchNodesServer) error {
	ch, sub := s.backend.WatchNodes()
	defer sub.Close()

	for {
		var ev *api.NodeEvent
		var ok bool

		select {
		case ev, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchNodeResponse{
			EventType: pb.WatchNodeResponse_REGISTERED,
			Node:      ev.Node.ToProto(),
		}
		if !ev.IsRegistration {
			resp.EventType = pb.WatchNodeResponse_DEREGISTERED
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *grpcServer) WatchNodeList(req *pb.WatchNodeListRequest, stream pb.EntityRegistry_WatchNodeListServer) error {
	ch, sub := s.backend.WatchNodeList()
	defer sub.Close()

	for {
		var nl *api.NodeList
		var ok bool

		select {
		case nl, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		nodes := make([]*commonPB.Node, 0, len(nl.Nodes))
		for _, n := range nl.Nodes {
			nodes = append(nodes, n.ToProto())
		}
		resp := &pb.WatchNodeListResponse{
			Node: nodes,
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

func (s *grpcServer) GetRuntime(ctx context.Context, req *pb.RuntimeRequest) (*pb.RuntimeResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	con, err := s.backend.GetRuntime(ctx, id, req.GetHeight())
	if err != nil {
		return nil, err
	}

	var resp pb.RuntimeResponse
	if con != nil {
		resp.Runtime = con.ToProto()
	}

	return &resp, err
}

func (s *grpcServer) GetRuntimes(ctx context.Context, req *pb.RuntimesRequest) (*pb.RuntimesResponse, error) {
	runtimes, err := s.backend.GetRuntimes(ctx, req.GetHeight())
	if err != nil {
		return nil, err
	}

	pbRuntimes := make([]*pb.Runtime, 0, len(runtimes))
	for _, v := range runtimes {
		pbRuntimes = append(pbRuntimes, v.ToProto())
	}

	return &pb.RuntimesResponse{Runtime: pbRuntimes}, nil
}

func (s *grpcServer) WatchRuntimes(req *pb.WatchRuntimesRequest, stream pb.RuntimeRegistry_WatchRuntimesServer) error {
	ch, sub := s.backend.WatchRuntimes()
	defer sub.Close()

	for {
		var con *api.Runtime
		var ok bool

		select {
		case con, ok = <-ch:
		case <-stream.Context().Done():
		}
		if !ok {
			break
		}

		resp := &pb.WatchRuntimesResponse{
			Runtime: con.ToProto(),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

// NewGRPCServer initializes and registers a new gRPC registry server
// backed by the provided Backend.
func NewGRPCServer(srv *grpc.Server, backend api.Backend) {
	s := &grpcServer{
		backend: backend,
	}
	pb.RegisterEntityRegistryServer(srv, s)
	pb.RegisterRuntimeRegistryServer(srv, s)
}
