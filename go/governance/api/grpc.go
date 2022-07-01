package api

import (
	"context"

	"google.golang.org/grpc"

	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Governance")

	// methodActiveProposals is the ActiveProposals method.
	methodActiveProposals = serviceName.NewMethod("ActiveProposals", int64(0))
	// methodProposals is the Proposals method.
	methodProposals = serviceName.NewMethod("Proposals", int64(0))
	// methodProposal is the Proposal method.
	methodProposal = serviceName.NewMethod("Proposal", ProposalQuery{})
	// methodVotes is the Votes method.
	methodVotes = serviceName.NewMethod("Votes", ProposalQuery{})
	// methodPendingUpgrades is the PendingUpgrades method.
	methodPendingUpgrades = serviceName.NewMethod("PendingUpgrades", int64(0))
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodConsensusParameters is the ConsensusParameters method.
	methodConsensusParameters = serviceName.NewMethod("ConsensusParameters", int64(0))
	// methodGetEvents is the GetEvents method.
	methodGetEvents = serviceName.NewMethod("GetEvents", int64(0))

	// methodWatchEvents is the WatchEvents method.
	methodWatchEvents = serviceName.NewMethod("WatchEvents", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Backend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodActiveProposals.ShortName(),
				Handler:    handlerActiveProposals,
			},
			{
				MethodName: methodProposals.ShortName(),
				Handler:    handlerProposals,
			},
			{
				MethodName: methodProposal.ShortName(),
				Handler:    handlerProposal,
			},
			{
				MethodName: methodVotes.ShortName(),
				Handler:    handlerVotes,
			},
			{
				MethodName: methodPendingUpgrades.ShortName(),
				Handler:    handlerPendingUpgrades,
			},
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodConsensusParameters.ShortName(),
				Handler:    handlerConsensusParameters,
			},
			{
				MethodName: methodGetEvents.ShortName(),
				Handler:    handlerGetEvents,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchEvents.ShortName(),
				Handler:       handlerWatchEvents,
				ServerStreams: true,
			},
		},
	}
)

func handlerActiveProposals(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).ActiveProposals(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodActiveProposals.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).ActiveProposals(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerProposals(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Proposals(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodProposals.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Proposals(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerVotes(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query ProposalQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Votes(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodVotes.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Votes(ctx, req.(*ProposalQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerProposal(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var query ProposalQuery
	if err := dec(&query); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).Proposal(ctx, &query)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodProposal.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).Proposal(ctx, req.(*ProposalQuery))
	}
	return interceptor(ctx, &query, info, handler)
}

func handlerPendingUpgrades(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).PendingUpgrades(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodPendingUpgrades.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).PendingUpgrades(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerStateToGenesis(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).StateToGenesis(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateToGenesis.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerConsensusParameters(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).ConsensusParameters(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodConsensusParameters.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).ConsensusParameters(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetEvents(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Backend).GetEvents(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetEvents.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(Backend).GetEvents(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerWatchEvents(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Backend).WatchEvents(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.SendMsg(ev); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// RegisterService registers a new governance service with the given gRPC server.
func RegisterService(server *grpc.Server, service Backend) {
	server.RegisterService(&serviceDesc, service)
}

type governanceClient struct {
	conn *grpc.ClientConn
}

func (c *governanceClient) ActiveProposals(ctx context.Context, height int64) ([]*Proposal, error) {
	var rsp []*Proposal
	if err := c.conn.Invoke(ctx, methodActiveProposals.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *governanceClient) Proposals(ctx context.Context, height int64) ([]*Proposal, error) {
	var rsp []*Proposal
	if err := c.conn.Invoke(ctx, methodProposals.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *governanceClient) Proposal(ctx context.Context, request *ProposalQuery) (*Proposal, error) {
	var rsp Proposal
	if err := c.conn.Invoke(ctx, methodProposal.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *governanceClient) Votes(ctx context.Context, request *ProposalQuery) ([]*VoteEntry, error) {
	var rsp []*VoteEntry
	if err := c.conn.Invoke(ctx, methodVotes.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *governanceClient) PendingUpgrades(ctx context.Context, height int64) ([]*upgrade.Descriptor, error) {
	var rsp []*upgrade.Descriptor
	if err := c.conn.Invoke(ctx, methodPendingUpgrades.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *governanceClient) StateToGenesis(ctx context.Context, height int64) (*Genesis, error) {
	var rsp Genesis
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *governanceClient) ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error) {
	var rsp ConsensusParameters
	if err := c.conn.Invoke(ctx, methodConsensusParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *governanceClient) GetEvents(ctx context.Context, height int64) ([]*Event, error) {
	var rsp []*Event
	if err := c.conn.Invoke(ctx, methodGetEvents.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *governanceClient) WatchEvents(ctx context.Context) (<-chan *Event, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchEvents.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Event)
	go func() {
		defer close(ch)

		for {
			var ev Event
			if serr := stream.RecvMsg(&ev); serr != nil {
				return
			}

			select {
			case ch <- &ev:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *governanceClient) Cleanup() {
}

// NewGovernanceClient creates a new gRPC governance client service.
func NewGovernanceClient(c *grpc.ClientConn) Backend {
	return &governanceClient{c}
}
