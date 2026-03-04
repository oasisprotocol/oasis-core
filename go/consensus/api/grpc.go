package api

import (
	"context"

	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	vault "github.com/oasisprotocol/oasis-core/go/vault/api"
)

var (
	// serviceName is the gRPC service name.
	serviceName = cmnGrpc.NewServiceName("Consensus")

	// methodSubmitTx is the SubmitTx method.
	methodSubmitTx = serviceName.NewMethod("SubmitTx", transaction.SignedTransaction{})
	// methodSubmitTxNoWait is the SubmitTxNoWait method.
	methodSubmitTxNoWait = serviceName.NewMethod("SubmitTxNoWait", transaction.SignedTransaction{})
	// methodSubmitTxWithProof is the SubmitTxWithProof method.
	methodSubmitTxWithProof = serviceName.NewMethod("SubmitTxWithProof", transaction.SignedTransaction{})
	// methodStateToGenesis is the StateToGenesis method.
	methodStateToGenesis = serviceName.NewMethod("StateToGenesis", int64(0))
	// methodEstimateGas is the EstimateGas method.
	methodEstimateGas = serviceName.NewMethod("EstimateGas", &EstimateGasRequest{})
	// methodMinGasPrice is the MinGasPrice method.
	methodMinGasPrice = serviceName.NewMethod("MinGasPrice", nil)
	// methodGetBlock is the GetBlock method.
	methodGetBlock = serviceName.NewMethod("GetBlock", int64(0))
	// methodGetBlockResults is the GetBlockResults method.
	methodGetBlockResults = serviceName.NewMethod("GetBlockResults", int64(0))
	// methodGetLightBlock is the GetLightBlock method.
	methodGetLightBlock = serviceName.NewMethod("GetLightBlock", int64(0))
	// methodGetValidators is the GetValidators method.
	methodGetValidators = serviceName.NewMethod("GetValidators", int64(0))
	// methodGetLatestHeight is the GetLatestHeight method.
	methodGetLatestHeight = serviceName.NewMethod("GetLatestHeight", nil)
	// methodGetLastRetainedHeight is the GetLastRetainedHeight method.
	methodGetLastRetainedHeight = serviceName.NewMethod("GetLastRetainedHeight", nil)
	// methodGetTransactions is the GetTransactions method.
	methodGetTransactions = serviceName.NewMethod("GetTransactions", int64(0))
	// methodGetTransactionsWithResults is the GetTransactionsWithResults method.
	methodGetTransactionsWithResults = serviceName.NewMethod("GetTransactionsWithResults", int64(0))
	// methodGetTransactionsWithProofs is the GetTransactionsWithProofs method.
	methodGetTransactionsWithProofs = serviceName.NewMethod("GetTransactionsWithProofs", int64(0))
	// methodGetUnconfirmedTransactions is the GetUnconfirmedTransactions method.
	methodGetUnconfirmedTransactions = serviceName.NewMethod("GetUnconfirmedTransactions", nil)
	// methodGetGenesisDocument is the GetGenesisDocument method.
	methodGetGenesisDocument = serviceName.NewMethod("GetGenesisDocument", nil)
	// methodStateSyncGet is the StateSyncGet method.
	methodStateSyncGet = serviceName.NewMethod("StateSyncGet", syncer.GetRequest{})
	// methodStateSyncGetPrefixes is the StateSyncGetPrefixes method.
	methodStateSyncGetPrefixes = serviceName.NewMethod("StateSyncGetPrefixes", syncer.GetPrefixesRequest{})
	// methodStateSyncIterate is the StateSyncIterate method.
	methodStateSyncIterate = serviceName.NewMethod("StateSyncIterate", syncer.IterateRequest{})
	// methodGetChainContext is the GetChainContext method.
	methodGetChainContext = serviceName.NewMethod("GetChainContext", nil)
	// methodGetStatus is the GetStatus method.
	methodGetStatus = serviceName.NewMethod("GetStatus", nil)
	// methodGetNextBlockState is the GetNextBlockState method.
	methodGetNextBlockState = serviceName.NewMethod("GetNextBlockState", nil)
	// methodGetParameters is the GetParameters method.
	methodGetParameters = serviceName.NewMethod("GetParameters", int64(0))
	// methodSubmitEvidence is the SubmitEvidence method.
	methodSubmitEvidence = serviceName.NewMethod("SubmitEvidence", &Evidence{})

	// methodWatchBlocks is the WatchBlocks method.
	methodWatchBlocks = serviceName.NewMethod("WatchBlocks", nil)

	// serviceDesc is the gRPC service descriptor.
	serviceDesc = grpc.ServiceDesc{
		ServiceName: string(serviceName),
		HandlerType: (*Services)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: methodSubmitTx.ShortName(),
				Handler:    handlerSubmitTx,
			},
			{
				MethodName: methodSubmitTxNoWait.ShortName(),
				Handler:    handlerSubmitTxNoWait,
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
				MethodName: methodMinGasPrice.ShortName(),
				Handler:    handlerMinGasPrice,
			},
			{
				MethodName: methodGetBlock.ShortName(),
				Handler:    handlerGetBlock,
			},
			{
				MethodName: methodGetBlockResults.ShortName(),
				Handler:    handlerGetBlockResults,
			},
			{
				MethodName: methodGetLightBlock.ShortName(),
				Handler:    handlerGetLightBlock,
			},
			{
				MethodName: methodGetValidators.ShortName(),
				Handler:    handlerGetValidators,
			},
			{
				MethodName: methodGetLatestHeight.ShortName(),
				Handler:    handlerGetLatestHeight,
			},
			{
				MethodName: methodGetLastRetainedHeight.ShortName(),
				Handler:    handlerGetLastRetainedHeight,
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
				MethodName: methodGetTransactionsWithProofs.ShortName(),
				Handler:    handlerGetTransactionsWithProofs,
			},
			{
				MethodName: methodGetUnconfirmedTransactions.ShortName(),
				Handler:    handlerGetUnconfirmedTransactions,
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
			{
				MethodName: methodGetParameters.ShortName(),
				Handler:    handlerGetParameters,
			},
			{
				MethodName: methodSubmitEvidence.ShortName(),
				Handler:    handlerSubmitEvidence,
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
)

func handlerSubmitTx(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Services).Core().SubmitTx(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTx.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return nil, srv.(Services).Core().SubmitTx(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerSubmitTxNoWait(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Services).Core().SubmitTxNoWait(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTxNoWait.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return nil, srv.(Services).Core().SubmitTxNoWait(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerSubmitTxWithProof(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(transaction.SignedTransaction)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().SubmitTxWithProof(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitTxWithProof.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().SubmitTxWithProof(ctx, req.(*transaction.SignedTransaction))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerStateToGenesis(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().StateToGenesis(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateToGenesis.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().StateToGenesis(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerEstimateGas(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(EstimateGasRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().EstimateGas(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodEstimateGas.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().EstimateGas(ctx, req.(*EstimateGasRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerMinGasPrice(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().MinGasPrice(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodMinGasPrice.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().MinGasPrice(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetBlock(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetBlock(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBlock.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetBlock(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetBlockResults(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetBlockResults(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetBlockResults.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetBlockResults(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetLightBlock(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetLightBlock(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLightBlock.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetLightBlock(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetValidators(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetValidators(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetValidators.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetValidators(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetLatestHeight(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetLatestHeight(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLatestHeight.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetLatestHeight(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetLastRetainedHeight(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetLastRetainedHeight(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetLastRetainedHeight.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetLastRetainedHeight(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetTransactions(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetTransactions(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactions.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetTransactions(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetTransactionsWithResults(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetTransactionsWithResults(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactionsWithResults.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetTransactionsWithResults(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetTransactionsWithProofs(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetTransactionsWithProofs(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetTransactionsWithProofs.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetTransactionsWithProofs(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerGetUnconfirmedTransactions(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetUnconfirmedTransactions(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetUnconfirmedTransactions.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetUnconfirmedTransactions(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerStateSyncGet(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(syncer.GetRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().State().SyncGet(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateSyncGet.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().State().SyncGet(ctx, req.(*syncer.GetRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerStateSyncGetPrefixes(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(syncer.GetPrefixesRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().State().SyncGetPrefixes(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateSyncGetPrefixes.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().State().SyncGetPrefixes(ctx, req.(*syncer.GetPrefixesRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerStateSyncIterate(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(syncer.IterateRequest)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().State().SyncIterate(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodStateSyncIterate.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().State().SyncIterate(ctx, req.(*syncer.IterateRequest))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerGetGenesisDocument(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetGenesisDocument(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetGenesisDocument.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetGenesisDocument(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetChainContext(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetChainContext(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetChainContext.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetChainContext(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetStatus(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetStatus(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetStatus.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetStatus(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetNextBlockState(
	srv any,
	ctx context.Context,
	_ func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	if interceptor == nil {
		return srv.(Services).Core().GetNextBlockState(ctx)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetNextBlockState.FullName(),
	}
	handler := func(ctx context.Context, _ any) (any, error) {
		return srv.(Services).Core().GetNextBlockState(ctx)
	}
	return interceptor(ctx, nil, info, handler)
}

func handlerGetParameters(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	var height int64
	if err := dec(&height); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(Services).Core().GetParameters(ctx, height)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodGetParameters.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return srv.(Services).Core().GetParameters(ctx, req.(int64))
	}
	return interceptor(ctx, height, info, handler)
}

func handlerSubmitEvidence(
	srv any,
	ctx context.Context,
	dec func(any) error,
	interceptor grpc.UnaryServerInterceptor,
) (any, error) {
	rq := new(Evidence)
	if err := dec(rq); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return nil, srv.(Services).Core().SubmitEvidence(ctx, rq)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: methodSubmitEvidence.FullName(),
	}
	handler := func(ctx context.Context, req any) (any, error) {
		return nil, srv.(Services).Core().SubmitEvidence(ctx, req.(*Evidence))
	}
	return interceptor(ctx, rq, info, handler)
}

func handlerWatchBlocks(srv any, stream grpc.ServerStream) error {
	if err := stream.RecvMsg(nil); err != nil {
		return err
	}

	ctx := stream.Context()
	ch, sub, err := srv.(Services).Core().WatchBlocks(ctx)
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

// RegisterService registers a new client backend service with the given gRPC server.
func RegisterService(server *grpc.Server, service Services) {
	server.RegisterService(&serviceDesc, service)
}

// Client is a gRPC consensus client.
type Client struct {
	conn *grpc.ClientConn
}

// NewClient creates a new gRPC consensus client.
func NewClient(c *grpc.ClientConn) *Client {
	return &Client{
		conn: c,
	}
}

func (c *Client) SubmitTx(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.conn.Invoke(ctx, methodSubmitTx.FullName(), tx, nil)
}

func (c *Client) SubmitTxNoWait(ctx context.Context, tx *transaction.SignedTransaction) error {
	return c.conn.Invoke(ctx, methodSubmitTxNoWait.FullName(), tx, nil)
}

func (c *Client) SubmitTxWithProof(ctx context.Context, tx *transaction.SignedTransaction) (*transaction.Proof, error) {
	var proof transaction.Proof
	if err := c.conn.Invoke(ctx, methodSubmitTxWithProof.FullName(), tx, &proof); err != nil {
		return nil, err
	}
	return &proof, nil
}

func (c *Client) StateToGenesis(ctx context.Context, height int64) (*genesis.Document, error) {
	var rsp genesis.Document
	if err := c.conn.Invoke(ctx, methodStateToGenesis.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) EstimateGas(ctx context.Context, req *EstimateGasRequest) (transaction.Gas, error) {
	var gas transaction.Gas
	if err := c.conn.Invoke(ctx, methodEstimateGas.FullName(), req, &gas); err != nil {
		return transaction.Gas(0), err
	}
	return gas, nil
}

func (c *Client) MinGasPrice(ctx context.Context) (*quantity.Quantity, error) {
	var rsp quantity.Quantity
	if err := c.conn.Invoke(ctx, methodMinGasPrice.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetBlock(ctx context.Context, height int64) (*Block, error) {
	var rsp Block
	if err := c.conn.Invoke(ctx, methodGetBlock.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetBlockResults(ctx context.Context, height int64) (*BlockResults, error) {
	var rsp BlockResults
	if err := c.conn.Invoke(ctx, methodGetBlockResults.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetLightBlock(ctx context.Context, height int64) (*LightBlock, error) {
	var rsp LightBlock
	if err := c.conn.Invoke(ctx, methodGetLightBlock.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetValidators(ctx context.Context, height int64) (*Validators, error) {
	var rsp Validators
	if err := c.conn.Invoke(ctx, methodGetValidators.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetLatestHeight(ctx context.Context) (int64, error) {
	var rsp int64
	if err := c.conn.Invoke(ctx, methodGetLatestHeight.FullName(), nil, &rsp); err != nil {
		return 0, err
	}
	return rsp, nil
}

func (c *Client) GetLastRetainedHeight(ctx context.Context) (int64, error) {
	var height int64
	if err := c.conn.Invoke(ctx, methodGetLastRetainedHeight.FullName(), nil, &height); err != nil {
		return 0, err
	}
	return height, nil
}

func (c *Client) GetTransactions(ctx context.Context, height int64) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetTransactions.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (c *Client) GetTransactionsWithResults(ctx context.Context, height int64) (*TransactionsWithResults, error) {
	var rsp TransactionsWithResults
	if err := c.conn.Invoke(ctx, methodGetTransactionsWithResults.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetTransactionsWithProofs(ctx context.Context, height int64) (*TransactionsWithProofs, error) {
	var rsp TransactionsWithProofs
	if err := c.conn.Invoke(ctx, methodGetTransactionsWithProofs.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetUnconfirmedTransactions(ctx context.Context) ([][]byte, error) {
	var rsp [][]byte
	if err := c.conn.Invoke(ctx, methodGetUnconfirmedTransactions.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

type stateReadSync struct {
	c *Client
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

func (c *Client) State() syncer.ReadSyncer {
	return &stateReadSync{c}
}

func (c *Client) GetGenesisDocument(ctx context.Context) (*genesis.Document, error) {
	var rsp genesis.Document
	if err := c.conn.Invoke(ctx, methodGetGenesisDocument.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetChainContext(ctx context.Context) (string, error) {
	var rsp string
	if err := c.conn.Invoke(ctx, methodGetChainContext.FullName(), nil, &rsp); err != nil {
		return "", err
	}
	return rsp, nil
}

func (c *Client) GetStatus(ctx context.Context) (*Status, error) {
	var rsp Status
	if err := c.conn.Invoke(ctx, methodGetStatus.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetNextBlockState(ctx context.Context) (*NextBlockState, error) {
	var rsp NextBlockState
	if err := c.conn.Invoke(ctx, methodGetNextBlockState.FullName(), nil, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) GetParameters(ctx context.Context, height int64) (*Parameters, error) {
	var rsp Parameters
	if err := c.conn.Invoke(ctx, methodGetParameters.FullName(), height, &rsp); err != nil {
		return nil, err
	}
	return &rsp, nil
}

func (c *Client) SubmitEvidence(ctx context.Context, evidence *Evidence) error {
	return c.conn.Invoke(ctx, methodSubmitEvidence.FullName(), evidence, nil)
}

func (c *Client) WatchBlocks(ctx context.Context) (<-chan *Block, pubsub.ClosableSubscription, error) {
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

// ServicesClient is a gRPC consensus services client.
type ServicesClient struct {
	conn *grpc.ClientConn
}

// NewServicesClient creates a new gRPC consensus services client.
func NewServicesClient(c *grpc.ClientConn) *ServicesClient {
	return &ServicesClient{
		conn: c,
	}
}

func (c *ServicesClient) Beacon() beacon.Backend {
	return beacon.NewClient(c.conn)
}

func (c *ServicesClient) Core() Backend {
	return NewClient(c.conn)
}

func (c *ServicesClient) Governance() governance.Backend {
	return governance.NewClient(c.conn)
}

func (c *ServicesClient) KeyManager() keymanager.Backend {
	return keymanager.NewClient(c.conn)
}

func (c *ServicesClient) Registry() registry.Backend {
	return registry.NewClient(c.conn)
}

func (c *ServicesClient) RootHash() roothash.Backend {
	return roothash.NewClient(c.conn)
}

func (c *ServicesClient) Scheduler() scheduler.Backend {
	return scheduler.NewClient(c.conn)
}

func (c *ServicesClient) Staking() staking.Backend {
	return staking.NewClient(c.conn)
}

func (c *ServicesClient) Vault() vault.Backend {
	return vault.NewClient(c.conn)
}
