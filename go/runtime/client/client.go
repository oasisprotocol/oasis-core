// Package client contains the runtime client.
package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	keymanagerAPI "github.com/oasislabs/oasis-core/go/keymanager/api"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/client"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	roothash "github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/runtime/client/api"
	enclaverpc "github.com/oasislabs/oasis-core/go/runtime/enclaverpc/api"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
	"github.com/oasislabs/oasis-core/go/runtime/tagindexer"
	"github.com/oasislabs/oasis-core/go/runtime/transaction"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
	txnscheduler "github.com/oasislabs/oasis-core/go/worker/txnscheduler/api"
)

var (
	_ api.RuntimeClient    = (*runtimeClient)(nil)
	_ enclaverpc.Transport = (*runtimeClient)(nil)
)

const (
	maxRetryElapsedTime = 60 * time.Second
	maxRetryInterval    = 10 * time.Second
)

type clientCommon struct {
	roothash        roothash.Backend
	storage         storage.Backend
	scheduler       scheduler.Backend
	registry        registry.Backend
	consensus       consensus.Backend
	keyManager      *keymanager.Client
	runtimeRegistry runtimeRegistry.Registry

	ctx context.Context
}

type submitContext struct {
	ctx        context.Context
	cancelFunc func()
	closeCh    chan struct{}
}

func (c *submitContext) cancel() {
	c.cancelFunc()
	<-c.closeCh
}

type runtimeClient struct {
	sync.Mutex

	common *clientCommon

	watchers map[common.Namespace]*blockWatcher

	logger *logging.Logger
}

func (c *runtimeClient) tagIndexer(runtimeID common.Namespace) (tagindexer.QueryableBackend, error) {
	rt, err := c.common.runtimeRegistry.GetRuntime(runtimeID)
	if err != nil {
		return nil, err
	}

	return rt.TagIndexer(), nil
}

func (c *runtimeClient) doSubmitTxToLeader(
	submitCtx *submitContext,
	req *txnscheduler.SubmitTxRequest,
	client txnscheduler.TransactionScheduler,
	resultCh chan error,
) {
	defer close(submitCtx.closeCh)

	op := func() error {
		_, err := client.SubmitTx(submitCtx.ctx, req)
		if submitCtx.ctx.Err() != nil {
			return backoff.Permanent(submitCtx.ctx.Err())
		}
		if err == txnscheduler.ErrNotLeader || status.Code(err) == codes.Unavailable {
			return err
		}
		if err != nil {
			return backoff.Permanent(err)
		}
		return nil
	}

	sched := backoff.NewExponentialBackOff()
	sched.MaxInterval = maxRetryInterval
	sched.MaxElapsedTime = maxRetryElapsedTime
	bctx := backoff.WithContext(sched, submitCtx.ctx)
	resultCh <- backoff.Retry(op, bctx)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) SubmitTx(ctx context.Context, request *api.SubmitTxRequest) ([]byte, error) {
	req := &txnscheduler.SubmitTxRequest{
		RuntimeID: request.RuntimeID,
		Data:      request.Data,
	}

	var watcher *blockWatcher
	var ok bool
	var err error
	c.Lock()
	if watcher, ok = c.watchers[request.RuntimeID]; !ok {
		watcher, err = newWatcher(c.common, request.RuntimeID)
		if err != nil {
			c.Unlock()
			return nil, err
		}
		if err = watcher.Start(); err != nil {
			c.Unlock()
			return nil, err
		}
		c.watchers[request.RuntimeID] = watcher
	}
	c.Unlock()

	respCh := make(chan *watchResult)
	var requestID hash.Hash
	requestID.FromBytes(request.Data)
	watcher.newCh <- &watchRequest{
		id:     &requestID,
		ctx:    ctx,
		respCh: respCh,
	}

	var submitCtx *submitContext
	submitResultCh := make(chan error, 1)
	defer close(submitResultCh)
	defer func() {
		if submitCtx != nil {
			submitCtx.cancel()
		}
	}()

	for {
		var resp *watchResult
		var ok bool

		select {
		case <-ctx.Done():
			// The context we're working in was canceled, abort.
			return nil, context.Canceled

		case submitResult := <-submitResultCh:
			// The last call to doSubmitTxToLeader produced a result;
			// handle it and make sure the subcontext is cleaned up.
			if submitResult != nil {
				if submitResult == context.Canceled {
					return nil, submitResult
				}
				c.logger.Error("can't send transaction to leader, waiting for next epoch", "err", submitResult)
			}
			submitCtx.cancel()
			submitCtx = nil
			continue

		case resp, ok = <-respCh:
			// The main event is getting a response from the watcher, handled below.
		}

		if !ok {
			return nil, errors.New("client: block watch channel closed unexpectedly (unknown error)")
		}

		if resp.newTxnschedulerClient != nil {
			if submitCtx != nil {
				submitCtx.cancel()
				select {
				case <-submitResultCh:
				default:
				}
			}
			childCtx, cancelFunc := context.WithCancel(ctx)
			submitCtx = &submitContext{
				ctx:        childCtx,
				cancelFunc: cancelFunc,
				closeCh:    make(chan struct{}),
			}
			go c.doSubmitTxToLeader(submitCtx, req, resp.newTxnschedulerClient, submitResultCh)
			continue
		} else if resp.err != nil {
			return nil, resp.err
		}

		return resp.result, nil
	}
}

// Implements api.RuntimeClient.
func (c *runtimeClient) WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	return c.common.roothash.WatchBlocks(runtimeID)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetBlock(ctx context.Context, request *api.GetBlockRequest) (*block.Block, error) {
	if request.Round == api.RoundLatest {
		return c.common.roothash.GetLatestBlock(ctx, request.RuntimeID, consensus.HeightLatest)
	}

	rt, err := c.common.runtimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	return rt.History().GetBlock(ctx, request.Round)
}

func (c *runtimeClient) getTxnTree(blk *block.Block) *transaction.Tree {
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		Hash:      blk.Header.IORoot,
	}

	return transaction.NewTree(c.common.storage, ioRoot)
}

func (c *runtimeClient) getTxnByHash(ctx context.Context, blk *block.Block, txHash hash.Hash) (*transaction.Transaction, error) {
	tree := c.getTxnTree(blk)
	defer tree.Close()

	return tree.GetTransaction(ctx, txHash)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetTx(ctx context.Context, request *api.GetTxRequest) (*api.TxResult, error) {
	tagIndexer, err := c.tagIndexer(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	txHash, err := tagIndexer.QueryTxnByIndex(ctx, blk.Header.Round, request.Index)
	if err != nil {
		return nil, err
	}

	tx, err := c.getTxnByHash(ctx, blk, txHash)
	if err != nil {
		return nil, err
	}

	return &api.TxResult{
		Block:  blk,
		Index:  request.Index,
		Input:  tx.Input,
		Output: tx.Output,
	}, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetTxByBlockHash(ctx context.Context, request *api.GetTxByBlockHashRequest) (*api.TxResult, error) {
	tagIndexer, err := c.tagIndexer(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	blk, err := c.GetBlockByHash(ctx, &api.GetBlockByHashRequest{RuntimeID: request.RuntimeID, BlockHash: request.BlockHash})
	if err != nil {
		return nil, err
	}

	txHash, err := tagIndexer.QueryTxnByIndex(ctx, blk.Header.Round, request.Index)
	if err != nil {
		return nil, err
	}

	tx, err := c.getTxnByHash(ctx, blk, txHash)
	if err != nil {
		return nil, err
	}

	return &api.TxResult{
		Block:  blk,
		Index:  request.Index,
		Input:  tx.Input,
		Output: tx.Output,
	}, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetTxs(ctx context.Context, request *api.GetTxsRequest) ([][]byte, error) {
	if request.IORoot.IsEmpty() {
		return [][]byte{}, nil
	}

	ioRoot := storage.Root{
		Round: request.Round,
		Hash:  request.IORoot,
	}
	copy(ioRoot.Namespace[:], request.RuntimeID[:])

	tree := transaction.NewTree(c.common.storage, ioRoot)
	defer tree.Close()

	txs, err := tree.GetTransactions(ctx)
	if err != nil {
		return nil, err
	}

	inputs := [][]byte{}
	for _, tx := range txs {
		inputs = append(inputs, tx.Input)
	}

	return inputs, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetBlockByHash(ctx context.Context, request *api.GetBlockByHashRequest) (*block.Block, error) {
	tagIndexer, err := c.tagIndexer(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	round, err := tagIndexer.QueryBlock(ctx, request.BlockHash)
	if err != nil {
		return nil, err
	}

	return c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: round})
}

// Implements api.RuntimeClient.
func (c *runtimeClient) QueryTx(ctx context.Context, request *api.QueryTxRequest) (*api.TxResult, error) {
	tagIndexer, err := c.tagIndexer(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	round, txHash, txIndex, err := tagIndexer.QueryTxn(ctx, request.Key, request.Value)
	if err != nil {
		return nil, err
	}

	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: round})
	if err != nil {
		return nil, err
	}

	tx, err := c.getTxnByHash(ctx, blk, txHash)
	if err != nil {
		return nil, err
	}

	return &api.TxResult{
		Block:  blk,
		Index:  txIndex,
		Input:  tx.Input,
		Output: tx.Output,
	}, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) QueryTxs(ctx context.Context, request *api.QueryTxsRequest) ([]*api.TxResult, error) {
	tagIndexer, err := c.tagIndexer(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	results, err := tagIndexer.QueryTxns(ctx, request.Query)
	if err != nil {
		return nil, err
	}

	output := []*api.TxResult{}
	for round, txResults := range results {
		// Fetch block for the given round.
		var blk *block.Block
		blk, err = c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: round})
		if err != nil {
			return nil, err
		}

		tree := c.getTxnTree(blk)
		defer tree.Close()

		// Extract transaction data for the specified indices.
		for _, txResult := range txResults {
			tx, err := tree.GetTransaction(ctx, txResult.TxHash)
			if err != nil {
				return nil, err
			}

			output = append(output, &api.TxResult{
				Block:  blk,
				Index:  txResult.TxIndex,
				Input:  tx.Input,
				Output: tx.Output,
			})
		}
	}

	return output, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) WaitBlockIndexed(ctx context.Context, request *api.WaitBlockIndexedRequest) error {
	tagIndexer, err := c.tagIndexer(request.RuntimeID)
	if err != nil {
		return err
	}

	return tagIndexer.WaitBlockIndexed(ctx, request.Round)
}

// Implements enclaverpc.Transport.
func (c *runtimeClient) CallEnclave(ctx context.Context, request *enclaverpc.CallEnclaveRequest) ([]byte, error) {
	switch request.Endpoint {
	case keymanagerAPI.EnclaveRPCEndpoint:
		// Key manager.
		return c.common.keyManager.CallRemote(ctx, request.RuntimeID, request.Payload)
	default:
		c.logger.Warn("failed to route EnclaveRPC call",
			"endpoint", request.Endpoint,
		)
		return nil, fmt.Errorf("unknown EnclaveRPC endpoint: %s", request.Endpoint)
	}
}

// Cleanup stops all running block watchers and waits for them to finish.
func (c *runtimeClient) Cleanup() {
	// Watchers.
	for _, watcher := range c.watchers {
		watcher.Stop()
	}
	for _, watcher := range c.watchers {
		<-watcher.Quit()
	}
}

// New returns a new runtime client instance.
func New(
	ctx context.Context,
	dataDir string,
	roothash roothash.Backend,
	scheduler scheduler.Backend,
	registry registry.Backend,
	consensus consensus.Backend,
	keyManager *keymanager.Client,
	runtimeRegistry runtimeRegistry.Registry,
) (api.RuntimeClient, error) {
	c := &runtimeClient{
		common: &clientCommon{
			roothash:        roothash,
			storage:         runtimeRegistry.StorageRouter(),
			scheduler:       scheduler,
			registry:        registry,
			consensus:       consensus,
			keyManager:      keyManager,
			runtimeRegistry: runtimeRegistry,
			ctx:             ctx,
		},
		watchers: make(map[common.Namespace]*blockWatcher),
		logger:   logging.GetLogger("runtime/client"),
	}
	return c, nil
}
