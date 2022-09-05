package api

import (
	"context"

	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Consensus")
	// lightServiceName is the gRPC service name for the light consensus interface.
	lightServiceName = cmnGrpc.NewServiceName("ConsensusLight")

	// methodSubmitTx is the SubmitTx method.
	methodSubmitTx = serviceName.NewMethod("SubmitTx", transaction.SignedTransaction{})
	// methodSubmitTxWithProof is the SubmitTxWithProof method.
	methodSubmitTxWithProof = serviceName.NewMethod("SubmitTxWithProof", transaction.SignedTransaction{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodEstimateGas is the EstimateGas method.
	methodEstimateGas = serviceName.NewMethod("EstimateGas", &EstimateGasRequest{})
	// methodGetSignerNonce is a GetSignerNonce method.
	methodGetSignerNonce = serviceName.NewMethod("GetSignerNonce", &GetSignerNonceRequest{})
	// methodGetBlock is the GetBlock method.
	methodGetBlock = serviceName.NewMethod("GetBlock", int64(0))
	// methodGetTransactions is the GetTransactions method.
	methodGetTransactions = serviceName.NewMethod("GetTransactions", int64(0))
	// methodGetTransactionsWithResults is the GetTransactionsWithResults method.
	methodGetTransactionsWithResults = serviceName.NewMethod("GetTransactionsWithResults", int64(0))
	// methodGetUnconfirmedTransactions is the GetUnconfirmedTransactions method.
	methodGetUnconfirmedTransactions = serviceName.NewMethod("GetUnconfirmedTransactions", nil)
	// methodGetGenesisDocument is the GetGenesisDocument method.
	methodGetGenesisDocument = serviceName.NewMethod("GetGenesisDocument", nil)
	// methodGetChainContext is the GetChainContext method.
	methodGetChainContext = serviceName.NewMethod("GetChainContext", nil)
	// methodGetStatus is the GetStatus method.
	methodGetStatus = serviceName.NewMethod("GetStatus", nil)
	// methodGetNextBlockState is the GetNextBlockState method.
	methodGetNextBlockState = serviceName.NewMethod("GetNextBlockState", nil)

	// methodWatchBlocks is the WatchBlocks method.
	methodWatchBlocks = serviceName.NewMethod("WatchBlocks", nil)

	// methodGetLightBlock is the GetLightBlock method.
	methodGetLightBlock = lightServiceName.NewMethod("GetLightBlock", int64(0))
	// methodGetLightBlockForState is the GetLightBlockForState method.
	methodGetLightBlockForState = lightServiceName.NewMethod("GetLightBlockForState", int64(0))
	// methodGetParameters is the GetParameters method.
	methodGetParameters = lightServiceName.NewMethod("GetParameters", int64(0))
	// methodStateSyncGet is the StateSyncGet method.
	methodStateSyncGet = lightServiceName.NewMethod("StateSyncGet", syncer.GetRequest{})
	// methodStateSyncGetPrefixes is the StateSyncGetPrefixes method.
	methodStateSyncGetPrefixes = lightServiceName.NewMethod("StateSyncGetPrefixes", syncer.GetPrefixesRequest{})
	// methodStateSyncIterate is the StateSyncIterate method.
	methodStateSyncIterate = lightServiceName.NewMethod("StateSyncIterate", syncer.IterateRequest{})
	// methodSubmitTxNoWait is the SubmitTxNoWait method.
	methodSubmitTxNoWait = lightServiceName.NewMethod("SubmitTxNoWait", transaction.SignedTransaction{})
	// methodSubmitEvidence is the SubmitEvidence method.
	methodSubmitEvidence = lightServiceName.NewMethod("SubmitEvidence", &Evidence{})

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*ClientBackend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSubmitTx.ShortName(),
				Handler:    handlerSubmitTx,
			},
			{
				MethodName: methodSubmitTxWithProof.ShortName(),
				Handler:    handlerSubmitTxWithProof,
			},
			{
				MethodName: methodStateToGenesis.ShortName(),
				Handler:    handlerStateToGenesis,
			},
			{
				MethodName: methodEstimateGas.ShortName(),
				Handler:    handlerEstimateGas,
			},
			{
				MethodName: methodGetSignerNonce.ShortName(),
				Handler:    handlerGetSignerNonce,
			},
			{
				MethodName: methodGetBlock.ShortName(),
				Handler:    handlerGetBlock,
			},
			{
				MethodName: methodGetTransactions.ShortName(),
				Handler:    handlerGetTransactions,
			},
			{
				MethodName: methodGetTransactionsWithResults.ShortName(),
				Handler:    handlerGetTransactionsWithResults,
			},
			{
				MethodName: methodGetUnconfirmedTransactions.ShortName(),
				Handler:    handlerGetUnconfirmedTransactions,
			},
			{
				MethodName: methodGetGenesisDocument.ShortName(),
				Handler:    handlerGetGenesisDocument,
			},
			{
				MethodName: methodGetChainContext.ShortName(),
				Handler:    handlerGetChainContext,
			},
			{
				MethodName: methodGetStatus.ShortName(),
				Handler:    handlerGetStatus,
			},
			{
				MethodName: methodGetNextBlockState.ShortName(),
				Handler:    handlerGetNextBlockState,
			},
		},
		Streams: []grpc.StreamDesc{
			{
				StreamName:    methodWatchBlocks.ShortName(),
				Handler:       handlerWatchBlocks,
				ServerStreams: true,
			},
		},
	}

	// lightServiceDesc is the gRPC service descriptor for the light consensus service.
	lightServiceDesc = grpc.ServiceDesc{
		ServiceName: string(lightServiceName),
		HandlerType: (*LightClientBackend)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodGetLightBlock.ShortName(),
				Handler:    handlerGetLightBlock,
			},
			{
				MethodName: methodGetLightBlockForState.ShortName(),
				Handler:    handlerGetLightBlockForState,
			},
			{
				MethodName: methodGetParameters.ShortName(),
				Handler:    handlerGetParameters,
			},
			{
				MethodName: methodStateSyncGet.ShortName(),
				Handler:    handlerStateSyncGet,
			},
			{
				MethodName: methodStateSyncGetPrefixes.ShortName(),
				Handler:    handlerStateSyncGetPrefixes,
			},
			{
				MethodName: methodStateSyncIterate.ShortName(),
				Handler:    handlerStateSyncIterate,
			},
			{
				MethodName: methodSubmitTxNoWait.ShortName(),
				Handler:    handlerSubmitTxNoWait,
			},
			{
				MethodName: methodSubmitEvidence.ShortName(),
				Handler:    handlerSubmitEvidence,
			},
		},
	}
)

func handlerSubmitTx(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(ClientBackend).SubmitTx(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTx.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(ClientBackend).SubmitTx(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerSubmitTxWithProof(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientBackend).SubmitTxWithProof(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTxWithProof.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).SubmitTxWithProof(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
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
		return srv.(ClientBackend).StateToGenesis(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateToGenesis.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerEstimateGas(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(EstimateGasRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientBackend).EstimateGas(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodEstimateGas.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).EstimateGas(ctx, req.(*EstimateGasRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerGetSignerNonce(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(GetSignerNonceRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ClientBackend).GetSignerNonce(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetSignerNonce.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetSignerNonce(ctx, req.(*GetSignerNonceRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerGetBlock(
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
		return srv.(ClientBackend).GetBlock(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetBlock(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetTransactions(
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
		return srv.(ClientBackend).GetTransactions(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactions.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetTransactions(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetTransactionsWithResults(
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
		return srv.(ClientBackend).GetTransactionsWithResults(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactionsWithResults.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetTransactionsWithResults(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetUnconfirmedTransactions(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(ClientBackend).GetUnconfirmedTransactions(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetUnconfirmedTransactions.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetUnconfirmedTransactions(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetGenesisDocument(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(ClientBackend).GetGenesisDocument(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetGenesisDocument.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetGenesisDocument(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetChainContext(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(ClientBackend).GetChainContext(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetChainContext.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetChainContext(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetStatus(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(ClientBackend).GetStatus(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatus.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetStatus(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetNextBlockState(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	if interceptor == nil {
		return srv.(ClientBackend).GetNextBlockState(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNextBlockState.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ClientBackend).GetNextBlockState(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerWatchBlocks(srv interface{}, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(ClientBackend).WatchBlocks(ctx)
	if err != nil {
		return err
	}
	defer sub.Close()

	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil
			}

			if err := stream.SendMsg(blk); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func handlerGetLightBlock(
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
		return srv.(LightClientBackend).GetLightBlock(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLightBlock.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightClientBackend).GetLightBlock(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetLightBlockForState(
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
		return srv.(LightClientBackend).GetLightBlockForState(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLightBlockForState.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightClientBackend).GetLightBlockForState(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetParameters(
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
		return srv.(LightClientBackend).GetParameters(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetParameters.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightClientBackend).GetParameters(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerStateSyncGet(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(syncer.GetRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightClientBackend).State().SyncGet(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateSyncGet.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightClientBackend).State().SyncGet(ctx, req.(*syncer.GetRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerStateSyncGetPrefixes(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(syncer.GetPrefixesRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightClientBackend).State().SyncGetPrefixes(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateSyncGetPrefixes.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightClientBackend).State().SyncGetPrefixes(ctx, req.(*syncer.GetPrefixesRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerStateSyncIterate(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(syncer.IterateRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(LightClientBackend).State().SyncIterate(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateSyncIterate.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(LightClientBackend).State().SyncIterate(ctx, req.(*syncer.IterateRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerSubmitTxNoWait(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(LightClientBackend).SubmitTxNoWait(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTxNoWait.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(LightClientBackend).SubmitTxNoWait(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerSubmitEvidence(
	srv interface{},
	ctx context.Context,
	dec func(interface{}) error,
	interceptor grpc.UnaryServerInterceptor,
) (interface{}, error) {
	rq := new(Evidence)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(LightClientBackend).SubmitEvidence(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitEvidence.FullName(),
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return nil, srv.(LightClientBackend).SubmitEvidence(ctx, req.(*Evidence))
	}
	return interceptor(ctx, rq, info, handler)
}

// RegisterService registers a new client backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service ClientBackend) {
	server.RegisterService(&serviceDesc, service)
	RegisterLightService(server, service)
}

// RegisterLightService registers a new light client backend service with the given gRPC server.
func RegisterLightService(server *grpc.Server, service LightClientBackend) {
	server.RegisterService(&lightServiceDesc, service)
}

type consensusLightClient struct {
	conn *grpc.ClientConn
}

// Implements LightClientBackend.
func (c *consensusLightClient) GetLightBlock(ctx context.Context, height int64) (*LightBlock, error) {
	var rsp LightBlock
	if err := c.conn.Invoke(ctx, methodGetLightBlock.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Implements LightClientBackend.
func (c *consensusLightClient) GetLightBlockForState(ctx context.Context, height int64) (*LightBlock, error) {
	var rsp LightBlock
	if err := c.conn.Invoke(ctx, methodGetLightBlockForState.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Implements LightClientBackend.
func (c *consensusLightClient) GetParameters(ctx context.Context, height int64) (*Parameters, error) {
	var rsp Parameters
	if err := c.conn.Invoke(ctx, methodGetParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

type stateReadSync struct {
	c *consensusLightClient
}

// Implements syncer.ReadSyncer.
func (rs *stateReadSync) SyncGet(ctx context.Context, request *syncer.GetRequest) (*syncer.ProofResponse, error) {
	var rsp syncer.ProofResponse
	if err := rs.c.conn.Invoke(ctx, methodStateSyncGet.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Implements syncer.ReadSyncer.
func (rs *stateReadSync) SyncGetPrefixes(ctx context.Context, request *syncer.GetPrefixesRequest) (*syncer.ProofResponse, error) {
	var rsp syncer.ProofResponse
	if err := rs.c.conn.Invoke(ctx, methodStateSyncGetPrefixes.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Implements syncer.ReadSyncer.
func (rs *stateReadSync) SyncIterate(ctx context.Context, request *syncer.IterateRequest) (*syncer.ProofResponse, error) {
	var rsp syncer.ProofResponse
	if err := rs.c.conn.Invoke(ctx, methodStateSyncIterate.FullName(), request, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

// Implements LightClientBackend.
func (c *consensusLightClient) State() syncer.ReadSyncer {
	return &stateReadSync{c}
}

// Implements LightClientBackend.
func (c *consensusLightClient) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.conn.Invoke(ctx, methodSubmitTxNoWait.FullName(), tx, nil)
}

// Implements LightClientBackend.
func (c *consensusLightClient) SubmitEvidence(ctx context.Context, evidence *Evidence) error {
	return c.conn.Invoke(ctx, methodSubmitEvidence.FullName(), evidence, nil)
}

type consensusClient struct {
	consensusLightClient

	conn *grpc.ClientConn
}

func (c *consensusClient) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.conn.Invoke(ctx, methodSubmitTx.FullName(), tx, nil)
}

func (c *consensusClient) SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error) {
	var proof transaction.Proof
	if err := c.conn.Invoke(ctx, methodSubmitTxWithProof.FullName(), tx, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func (c *consensusClient) StateToGenesis(ctx context.Context, height int64) (*genesis.Document, error) {
	var rsp genesis.Document
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) EstimateGas(ctx context.Context, req *EstimateGasRequest) (transaction.Gas, error) {
	var gas transaction.Gas
	if err := c.conn.Invoke(ctx, methodEstimateGas.FullName(), req, &gas); err != nil {
		return transaction.Gas(0), err
	}
	return gas, nil
}

func (c *consensusClient) GetSignerNonce(ctx context.Context, req *GetSignerNonceRequest) (uint64, error) {
	var nonce uint64
	if err := c.conn.Invoke(ctx, methodGetSignerNonce.FullName(), req, &nonce); err != nil {
		return nonce, err
	}
	return nonce, nil
}

func (c *consensusClient) GetBlock(ctx context.Context, height int64) (*Block, error) {
	var rsp Block
	if err := c.conn.Invoke(ctx, methodGetBlock.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetTransactions.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *consensusClient) GetTransactionsWithResults(ctx context.Context, height int64) (*TransactionsWithResults, error) {
	var rsp TransactionsWithResults
	if err := c.conn.Invoke(ctx, methodGetTransactionsWithResults.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetUnconfirmedTransactions.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *consensusClient) GetGenesisDocument(ctx context.Context) (*genesis.Document, error) {
	var rsp genesis.Document
	if err := c.conn.Invoke(ctx, methodGetGenesisDocument.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) GetChainContext(ctx context.Context) (string, error) {
	var rsp string
	if err := c.conn.Invoke(ctx, methodGetChainContext.FullName(), nil, &rsp); err != nil {
		return "", err
	}
	return rsp, nil
}

func (c *consensusClient) GetStatus(ctx context.Context) (*Status, error) {
	var rsp Status
	if err := c.conn.Invoke(ctx, methodGetStatus.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) GetNextBlockState(ctx context.Context) (*NextBlockState, error) {
	var rsp NextBlockState
	if err := c.conn.Invoke(ctx, methodGetNextBlockState.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *consensusClient) WatchBlocks(ctx context.Context) (<-chan *Block, pubsub.ClosableSubscription, error) {
	ctx, sub := pubsub.NewContextSubscription(ctx)

	stream, err := c.conn.NewStream(ctx, &serviceDesc.Streams[0], methodWatchBlocks.FullName())
	if err != nil {
		return nil, nil, err
	}
	if err = stream.SendMsg(nil); err != nil {
		return nil, nil, err
	}
	if err = stream.CloseSend(); err != nil {
		return nil, nil, err
	}

	ch := make(chan *Block)
	go func() {
		defer close(ch)

		for {
			var blk Block
			if serr := stream.RecvMsg(&blk); serr != nil {
				return
			}

			select {
			case ch <- &blk:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, sub, nil
}

func (c *consensusClient) Beacon() beacon.Backend {
	return beacon.NewBeaconClient(c.conn)
}

func (c *consensusClient) Registry() registry.Backend {
	return registry.NewRegistryClient(c.conn)
}

func (c *consensusClient) Staking() staking.Backend {
	return staking.NewStakingClient(c.conn)
}

func (c *consensusClient) Scheduler() scheduler.Backend {
	return scheduler.NewSchedulerClient(c.conn)
}

func (c *consensusClient) Governance() governance.Backend {
	return governance.NewGovernanceClient(c.conn)
}

func (c *consensusClient) RootHash() roothash.Backend {
	return roothash.NewRootHashClient(c.conn)
}

// NewConsensusClient creates a new gRPC consensus client service.
func NewConsensusClient(c *grpc.ClientConn) ClientBackend {
	return &consensusClient{
		consensusLightClient: consensusLightClient{c},
		conn:                 c,
	}
}

// NewConsensusLightClient creates a new gRPC consensus light client service.
func NewConsensusLightClient(c *grpc.ClientConn) LightClientBackend {
	return &consensusLightClient{c}
}
