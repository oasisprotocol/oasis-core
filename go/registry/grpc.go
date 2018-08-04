package registry

import (
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	"github.com/oasislabs/ekiden/go/common/node"

	commonPB "github.com/oasislabs/ekiden/go/grpc/common"
	pb "github.com/oasislabs/ekiden/go/grpc/registry"
)

var _ pb.EntityRegistryServer = (*EntityRegistryServer)(nil)

var registryFailures = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ekiden_registry_failures",
		Help: "Number of registry failures.",
	},
	[]string{"call"},
)
var registryNodes = prometheus.NewCounter(
	prometheus.CounterOpts{
		Name: "ekiden_registry_nodes",
		Help: "Number of registry nodes.",
	},
)
var registryEntities = prometheus.NewGauge(
	prometheus.GaugeOpts{
		Name: "ekiden_registry_entities",
		Help: "Number of registry entities.",
	},
)
var registeryCollectors = []prometheus.Collector{
	registryFailures,
	registryNodes,
	registryEntities,
}

// EntityRegistryServer is an EntityRegistry exposed over gRPC.
type EntityRegistryServer struct {
	backend EntityRegistry
}

// RegisterEntity implements the corresponding gRPC call.
func (s *EntityRegistryServer) RegisterEntity(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	var ent entity.Entity
	if err := ent.FromProto(req.GetEntity()); err != nil {
		return nil, err
	}
	var sig signature.Signature
	if err := sig.FromProto(req.GetSignature()); err != nil {
		return nil, err
	}

	if err := s.backend.RegisterEntity(&ent, &sig); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerEntity"}).Inc()
		return nil, err
	}

	registryEntities.Inc()
	return &pb.RegisterResponse{}, nil
}

// DeregisterEntity implements the corresponding gRPC call.
func (s *EntityRegistryServer) DeregisterEntity(ctx context.Context, req *pb.DeregisterRequest) (*pb.DeregisterResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}
	var sig signature.Signature
	if err := sig.FromProto(req.GetSignature()); err != nil {
		return nil, err
	}

	if err := s.backend.DeregisterEntity(id, &sig); err != nil {
		registryFailures.With(prometheus.Labels{"call": "deregisterEntity"}).Inc()
		return nil, err
	}

	registryEntities.Dec()
	return &pb.DeregisterResponse{}, nil
}

// GetEntity implements the corresponding gRPC call.
func (s *EntityRegistryServer) GetEntity(ctx context.Context, req *pb.EntityRequest) (*pb.EntityResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	var resp pb.EntityResponse
	if ent := s.backend.GetEntity(id); ent != nil {
		resp.Entity = ent.ToProto()
	}

	return &resp, nil
}

// GetEntities implements the corresponding gRPC call.
func (s *EntityRegistryServer) GetEntities(ctx context.Context, req *pb.EntitiesRequest) (*pb.EntitiesResponse, error) {
	ents := s.backend.GetEntities()

	pbEnts := make([]*commonPB.Entity, 0, len(ents))
	for _, v := range ents {
		pbEnts = append(pbEnts, v.ToProto())
	}

	return &pb.EntitiesResponse{Entity: pbEnts}, nil
}

// WatchEntities implements the corresponding gRPC call.
func (s *EntityRegistryServer) WatchEntities(req *pb.WatchEntityRequest, stream pb.EntityRegistry_WatchEntitiesServer) error {
	evCh, sub := s.backend.WatchEntities()
	defer sub.Close()

	for {
		ev, ok := <-evCh
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

// RegisterNode implements the corresponding gRPC call.
func (s *EntityRegistryServer) RegisterNode(ctx context.Context, req *pb.RegisterNodeRequest) (*pb.RegisterNodeResponse, error) {
	var node node.Node
	if err := node.FromProto(req.GetNode()); err != nil {
		return nil, err
	}
	var sig signature.Signature
	if err := sig.FromProto(req.GetSignature()); err != nil {
		return nil, err
	}

	if err := s.backend.RegisterNode(&node, &sig); err != nil {
		registryFailures.With(prometheus.Labels{"call": "registerNode"}).Inc()
		return nil, err
	}

	registryNodes.Inc()
	return &pb.RegisterNodeResponse{}, nil
}

// GetNode implements the corresponding gRPC call.
func (s *EntityRegistryServer) GetNode(ctx context.Context, req *pb.NodeRequest) (*pb.NodeResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	var resp pb.NodeResponse
	if node := s.backend.GetNode(id); node != nil {
		resp.Node = node.ToProto()
	}

	return &resp, nil
}

// GetNodes implements the corresponding gRPC call.
func (s *EntityRegistryServer) GetNodes(ctx context.Context, req *pb.NodesRequest) (*pb.NodesResponse, error) {
	nodes := s.backend.GetNodes()

	// XXX: Epoch????  The underlying implementation doesn't take this
	// argument.

	pbNodes := make([]*commonPB.Node, 0, len(nodes))
	for _, v := range nodes {
		pbNodes = append(pbNodes, v.ToProto())
	}

	return &pb.NodesResponse{Node: pbNodes}, nil
}

// GetNodesForEntity implements the corresponding gRPC call.
func (s *EntityRegistryServer) GetNodesForEntity(ctx context.Context, req *pb.EntityNodesRequest) (*pb.EntityNodesResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	nodes := s.backend.GetNodesForEntity(id)
	pbNodes := make([]*commonPB.Node, 0, len(nodes))
	for _, v := range nodes {
		pbNodes = append(pbNodes, v.ToProto())
	}

	return &pb.EntityNodesResponse{Node: pbNodes}, nil
}

// WatchNodes implements the corresponding gRPC call.
func (s *EntityRegistryServer) WatchNodes(req *pb.WatchNodeRequest, stream pb.EntityRegistry_WatchNodesServer) error {
	evCh, sub := s.backend.WatchNodes()
	defer sub.Close()

	for {
		ev, ok := <-evCh
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

// WatchNodeList implements the corresponding gRPC call.
func (s *EntityRegistryServer) WatchNodeList(req *pb.WatchNodeListRequest, stream pb.EntityRegistry_WatchNodeListServer) error {
	nlCh, sub := s.backend.WatchNodeList()
	defer sub.Close()

	for {
		nl, ok := <-nlCh
		if !ok {
			break
		}
		nodes := make([]*commonPB.Node, 0, len(nl.Nodes))
		for _, n := range nl.Nodes {
			nodes = append(nodes, n.ToProto())
		}
		resp := &pb.WatchNodeListResponse{
			Epoch: uint64(nl.Epoch),
			Node:  nodes,
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}

	return nil
}

// NewEntityRegistryServer initializes and registers a new EntityRegisteryServer
// backed by the provided EntityRegistry.
func NewEntityRegistryServer(srv *grpc.Server, reg EntityRegistry) {
	prometheus.MustRegister(registeryCollectors...)

	s := &EntityRegistryServer{
		backend: reg,
	}
	pb.RegisterEntityRegistryServer(srv, s)
}

// ContractRegistryServer is a contract registry exposed over gRPC.
type ContractRegistryServer struct {
	backend ContractRegistry
}

// RegisterContract implements the corresponding gRPC call.
func (s *ContractRegistryServer) RegisterContract(ctx context.Context, req *pb.RegisterContractRequest) (*pb.RegisterContractResponse, error) {
	return nil, nil
}

// GetContract implements the corresponding gRPC call.
func (s *ContractRegistryServer) GetContract(ctx context.Context, req *pb.ContractRequest) (*pb.ContractResponse, error) {
	var id signature.PublicKey
	if err := id.UnmarshalBinary(req.GetId()); err != nil {
		return nil, err
	}

	var resp pb.ContractResponse
	if con := s.backend.GetContract(id); con != nil {
		resp.Contract = con.ToProto()
	}

	return &resp, nil
}

// GetContracts implements the corresponding gRPC call.
func (s *ContractRegistryServer) GetContracts(req *pb.ContractsRequest, stream pb.ContractRegistry_GetContractsServer) error {
	ch, sub := s.backend.WatchContracts()
	defer sub.Close()

	for {
		con, ok := <-ch
		if !ok {
			break
		}
		resp := &pb.ContractsResponse{
			Contract: con.ToProto(),
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	return nil
}

// NewContractRegistryServer initializes and registers a new
// ContractRegistryServer backed by the provided ContractRegistry.
func NewContractRegistryServer(srv *grpc.Server, reg ContractRegistry) {
	s := &ContractRegistryServer{
		backend: reg,
	}
	pb.RegisterContractRegistryServer(srv, s)
}
