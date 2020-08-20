// Package client contains the runtime client.
package client

import (
	"context"
	"fmt"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanagerAPI "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/client"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/tagindexer"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
	executor "github.com/oasisprotocol/oasis-core/go/worker/compute/executor/api"
)

var (
	_ api.RuntimeClient    = (*runtimeClient)(nil)
	_ enclaverpc.Transport = (*runtimeClient)(nil)
)

type clientCommon struct {
	storage         storage.Backend
	consensus       consensus.Backend
	runtimeRegistry runtimeRegistry.Registry
	// p2p may be nil.
	p2p *p2p.P2P

	ctx context.Context
}

type runtimeClient struct {
	sync.Mutex

	common *clientCommon

	watchers  map[common.Namespace]*blockWatcher
	kmClients map[common.Namespace]*keymanager.Client

	logger *logging.Logger
}

func (c *runtimeClient) tagIndexer(runtimeID common.Namespace) (tagindexer.QueryableBackend, error) {
	rt, err := c.common.runtimeRegistry.GetRuntime(runtimeID)
	if err != nil {
		return nil, err
	}

	return rt.TagIndexer(), nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) SubmitTx(ctx context.Context, request *api.SubmitTxRequest) ([]byte, error) {
	if c.common.p2p == nil {
		return nil, fmt.Errorf("client: cannot submit transaction, p2p disabled")
	}

	var watcher *blockWatcher
	var ok bool
	var err error
	c.Lock()
	if watcher, ok = c.watchers[request.RuntimeID]; !ok {
		watcher, err = newWatcher(c.common, request.RuntimeID, c.common.p2p)
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

	for {
		var resp *watchResult
		var ok bool

		select {
		case <-ctx.Done():
			// The context we're working in was canceled, abort.
			return nil, context.Canceled

		case resp, ok = <-respCh:
			// The main event is getting a response from the watcher, handled below.
			if resp.result == nil {
				break
			}

			return resp.result, nil
		}

		if !ok {
			return nil, fmt.Errorf("client: block watch channel closed unexpectedly (unknown error)")
		}

		c.common.p2p.Publish(context.Background(), request.RuntimeID, &p2p.Message{
			Tx: &executor.Tx{
				Data: request.Data,
			},
			GroupVersion: resp.groupVersion,
		})
	}
}

// Implements api.RuntimeClient.
func (c *runtimeClient) WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	return c.common.consensus.RootHash().WatchBlocks(runtimeID)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetGenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error) {
	return c.common.consensus.RootHash().GetGenesisBlock(ctx, runtimeID, consensus.HeightLatest)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetBlock(ctx context.Context, request *api.GetBlockRequest) (*block.Block, error) {
	rt, err := c.common.runtimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}

	switch request.Round {
	case api.RoundLatest:
		return rt.History().GetLatestBlock(ctx)
	default:
		return rt.History().GetBlock(ctx, request.Round)
	}
}

func (c *runtimeClient) getTxnTree(blk *block.Block) *transaction.Tree {
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round,
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
		Version: request.Round,
		Hash:    request.IORoot,
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
			return nil, fmt.Errorf("failed to fetch block: %w", err)
		}

		tree := c.getTxnTree(blk)
		defer tree.Close()

		// Extract transaction data for the specified indices.
		var txHashes []hash.Hash
		for _, txResult := range txResults {
			txHashes = append(txHashes, txResult.TxHash)
		}

		txes, err := tree.GetTransactionMultiple(ctx, txHashes)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch transaction data: %w", err)
		}
		for _, txResult := range txResults {
			tx, ok := txes[txResult.TxHash]
			if !ok {
				return nil, fmt.Errorf("transaction %s not found", txResult.TxHash)
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
		rt, err := c.common.runtimeRegistry.GetRuntime(request.RuntimeID)
		if err != nil {
			return nil, err
		}

		var km *keymanager.Client
		c.Lock()
		if km = c.kmClients[rt.ID()]; km == nil {
			c.logger.Debug("creating new key manager client instance")

			km, err = keymanager.New(c.common.ctx, rt, c.common.consensus.KeyManager(), c.common.consensus.Registry(), nil)
			if err != nil {
				c.Unlock()
				c.logger.Error("failed to create key manager client instance",
					"err", err,
				)
				return nil, api.ErrInternal
			}
			c.kmClients[rt.ID()] = km
		}
		c.Unlock()

		return km.CallRemote(ctx, request.Payload)
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
	consensus consensus.Backend,
	runtimeRegistry runtimeRegistry.Registry,
	p2p *p2p.P2P,
) (api.RuntimeClient, error) {
	c := &runtimeClient{
		common: &clientCommon{
			storage:         runtimeRegistry.StorageRouter(),
			consensus:       consensus,
			runtimeRegistry: runtimeRegistry,
			ctx:             ctx,
			p2p:             p2p,
		},
		watchers:  make(map[common.Namespace]*blockWatcher),
		kmClients: make(map[common.Namespace]*keymanager.Client),
		logger:    logging.GetLogger("runtime/client"),
	}
	return c, nil
}
