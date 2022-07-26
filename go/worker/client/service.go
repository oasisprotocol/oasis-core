package client

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
)

type service struct {
	w *Worker
}

func (s *service) submitTx(ctx context.Context, request *api.SubmitTxRequest) (<-chan *api.SubmitTxResult, *protocol.Error, error) {
	rt := s.w.runtimes[request.RuntimeID]
	if rt == nil {
		return nil, nil, api.ErrNoHostedRuntime
	}

	return rt.SubmitTx(ctx, request.Data)
}

// Implements api.RuntimeClient.
func (s *service) SubmitTx(ctx context.Context, request *api.SubmitTxRequest) ([]byte, error) {
	resp, err := s.SubmitTxMeta(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp.CheckTxError != nil {
		return nil, errors.WithContext(api.ErrCheckTxFailed, resp.CheckTxError.String())
	}
	return resp.Output, nil
}

// Implements api.RuntimeClient.
func (s *service) SubmitTxMeta(ctx context.Context, request *api.SubmitTxRequest) (*api.SubmitTxMetaResponse, error) {
	respCh, checkTxErr, err := s.submitTx(ctx, request)
	if err != nil {
		return nil, err
	}
	if checkTxErr != nil {
		return &api.SubmitTxMetaResponse{
			CheckTxError: checkTxErr,
		}, nil
	}

	// Wait for result.
	for {
		var resp *api.SubmitTxResult
		var ok bool

		select {
		case <-ctx.Done():
			// The context we're working in was canceled, abort.
			return nil, ctx.Err()
		case resp, ok = <-respCh:
			if !ok {
				return nil, fmt.Errorf("client: channel closed unexpectedly")
			}
			return resp.Result, resp.Error
		}
	}
}

// Implements api.RuntimeClient.
func (s *service) SubmitTxNoWait(ctx context.Context, request *api.SubmitTxRequest) error {
	_, checkTxErr, err := s.submitTx(ctx, request)
	if err != nil {
		return err
	}
	if checkTxErr != nil {
		return errors.WithContext(api.ErrCheckTxFailed, checkTxErr.String())
	}
	return nil
}

// Implements api.RuntimeClient.
func (s *service) CheckTx(ctx context.Context, request *api.CheckTxRequest) error {
	rt := s.w.runtimes[request.RuntimeID]
	if rt == nil {
		return api.ErrNoHostedRuntime
	}

	resp, err := rt.CheckTx(ctx, request.Data)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.WithContext(api.ErrCheckTxFailed, resp.Error.String())
	}

	return nil
}

// Implements api.RuntimeClient.
func (s *service) WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(runtimeID)
	if err != nil {
		return nil, nil, err
	}
	return rt.History().WatchBlocks()
}

// Implements api.RuntimeClient.
func (s *service) GetGenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error) {
	return s.w.commonWorker.Consensus.RootHash().GetGenesisBlock(ctx, &roothash.RuntimeRequest{
		RuntimeID: runtimeID,
		Height:    consensus.HeightLatest,
	})
}

// Implements api.RuntimeClient.
func (s *service) GetBlock(ctx context.Context, request *api.GetBlockRequest) (*block.Block, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}
	return rt.History().GetBlock(ctx, request.Round)
}

// Implements api.RuntimeClient.
func (s *service) GetLastRetainedBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(runtimeID)
	if err != nil {
		return nil, err
	}
	blk, err := rt.History().GetEarliestBlock(ctx)
	if err != nil {
		return nil, err
	}

	// If the client is stateful, take storage into account to avoid returning a block for which
	// we don't actually have state available. This may be because there is only a later checkpoint
	// available.
	if lsb, ok := rt.Storage().(storage.LocalBackend); ok {
		version := lsb.NodeDB().GetEarliestVersion()

		if version > blk.Header.Round {
			blk, err = rt.History().GetBlock(ctx, version)
			if err != nil {
				return nil, err
			}
		}
	}
	return blk, nil
}

func (s *service) getTxnTree(backend storage.Backend, blk *block.Block) *transaction.Tree {
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round,
		Type:      storage.RootTypeIO,
		Hash:      blk.Header.IORoot,
	}

	return transaction.NewTree(backend, ioRoot)
}

// Implements api.RuntimeClient.
func (s *service) GetTransactions(ctx context.Context, request *api.GetTransactionsRequest) ([][]byte, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	blk, err := s.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	tree := s.getTxnTree(rt.Storage(), blk)
	defer tree.Close()

	txs, err := tree.GetTransactions(ctx)
	if err != nil {
		return nil, err
	}

	inputs := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		inputs = append(inputs, tx.Input)
	}

	return inputs, nil
}

// Implements api.RuntimeClient.
func (s *service) GetTransactionsWithResults(ctx context.Context, request *api.GetTransactionsRequest) ([]*api.TransactionWithResults, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	blk, err := s.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	tree := s.getTxnTree(rt.Storage(), blk)
	defer tree.Close()

	txs, err := tree.GetTransactions(ctx)
	if err != nil {
		return nil, err
	}

	tags, err := tree.GetTags(ctx)
	if err != nil {
		return nil, err
	}
	eventsByHash := make(map[hash.Hash][]*api.PlainEvent)
	for _, tag := range tags {
		eventsByHash[tag.TxHash] = append(eventsByHash[tag.TxHash], &api.PlainEvent{
			Key:   tag.Key,
			Value: tag.Value,
		})
	}

	var results []*api.TransactionWithResults
	for _, tx := range txs {
		results = append(results, &api.TransactionWithResults{
			Tx:     tx.Input,
			Result: tx.Output,
			Events: eventsByHash[tx.Hash()],
		})
	}

	return results, nil
}

// Implements api.RuntimeClient.
func (s *service) GetEvents(ctx context.Context, request *api.GetEventsRequest) ([]*api.Event, error) {
	rt, err := s.w.commonWorker.RuntimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	blk, err := s.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	tree := s.getTxnTree(rt.Storage(), blk)
	defer tree.Close()

	tags, err := tree.GetTags(ctx)
	if err != nil {
		return nil, err
	}

	events := make([]*api.Event, 0, len(tags))
	for _, tag := range tags {
		events = append(events, &api.Event{
			Key:    tag.Key,
			Value:  tag.Value,
			TxHash: tag.TxHash,
		})
	}
	return events, nil
}

// Implements api.RuntimeClient.
func (s *service) Query(ctx context.Context, request *api.QueryRequest) (*api.QueryResponse, error) {
	rt := s.w.runtimes[request.RuntimeID]
	if rt == nil {
		return nil, api.ErrNoHostedRuntime
	}

	data, err := rt.Query(ctx, request.Round, request.Method, request.Args)
	if err != nil {
		return nil, err
	}
	return &api.QueryResponse{Data: data}, nil
}
