package client

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/balancer/roundrobin"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/resolver"
	"google.golang.org/grpc/status"

	"github.com/cenkalti/backoff"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/client/indexer"
	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/grpc/txnscheduler"
	keymanager "github.com/oasislabs/ekiden/go/keymanager/client"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/runtime/transaction"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

const (
	cfgIndexBackend  = "client.indexer.backend"
	cfgIndexRuntimes = "client.indexer.runtimes"
)

var (
	// ErrIndexerDisabled is an error when the indexer is disabled.
	ErrIndexerDisabled = errors.New("client: indexer not enabled")
)

const (
	maxRetryElapsedTime = 60 * time.Second
	maxRetryInterval    = 10 * time.Second
)

type clientCommon struct {
	roothash   roothash.Backend
	storage    storage.Backend
	scheduler  scheduler.Backend
	registry   registry.Backend
	consensus  common.ConsensusBackend
	keyManager *keymanager.Client

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

// Client is implements submitting transactions to the transaction scheduler committee leader.
type Client struct {
	sync.Mutex
	common   *clientCommon
	watchers map[signature.MapKey]*blockWatcher

	indexers       map[signature.MapKey]*indexer.Service
	indexerBackend indexer.Backend

	logger *logging.Logger
}

func (c *Client) doSubmitTxToLeader(submitCtx *submitContext, req *txnscheduler.SubmitTxRequest, nodeMeta *node.Node, resultCh chan error) {
	defer close(submitCtx.closeCh)

	nodeCert, err := nodeMeta.Committee.ParseCertificate()
	if err != nil {
		resultCh <- err
		return
	}
	certPool := x509.NewCertPool()
	certPool.AddCert(nodeCert)

	creds := credentials.NewClientTLSFromCert(certPool, "ekiden-node")

	manualResolver, address, cleanup := manual.NewManualResolver()
	defer cleanup()

	conn, err := grpc.DialContext(submitCtx.ctx, address, grpc.WithTransportCredentials(creds), grpc.WithBalancerName(roundrobin.Name))
	if err != nil {
		resultCh <- err
		return
	}
	defer conn.Close()
	client := txnscheduler.NewTransactionSchedulerClient(conn)

	var resolverState resolver.State
	for _, addr := range nodeMeta.Committee.Addresses {
		resolverState.Addresses = append(resolverState.Addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.UpdateState(resolverState)

	op := func() error {
		_, err := client.SubmitTx(submitCtx.ctx, req)
		if submitCtx.ctx.Err() != nil {
			return backoff.Permanent(submitCtx.ctx.Err())
		}
		if status.Code(err) == codes.Unavailable {
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

// SubmitTx submits a new transaction to the committee leader and returns its results.
func (c *Client) SubmitTx(ctx context.Context, txData []byte, runtimeID signature.PublicKey) ([]byte, error) {
	if werr := c.WaitSync(ctx); werr != nil {
		return nil, werr
	}

	req := &txnscheduler.SubmitTxRequest{
		RuntimeId: runtimeID,
		Data:      txData,
	}

	mapKey := runtimeID.ToMapKey()

	var watcher *blockWatcher
	var ok bool
	var err error
	c.Lock()
	if watcher, ok = c.watchers[mapKey]; !ok {
		watcher, err = newWatcher(c.common, runtimeID)
		if err != nil {
			c.Unlock()
			return nil, err
		}
		if err = watcher.Start(); err != nil {
			c.Unlock()
			return nil, err
		}
		c.watchers[mapKey] = watcher
	}
	c.Unlock()

	respCh := make(chan *watchResult)
	var requestID hash.Hash
	requestID.FromBytes(txData)
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

		if resp.newLeader != nil {
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
			go c.doSubmitTxToLeader(submitCtx, req, resp.newLeader, submitResultCh)
			continue
		} else if resp.err != nil {
			return nil, resp.err
		}

		return resp.result, nil
	}
}

// WaitSync waits on the consensus backend given at construction to finish syncing.
func (c *Client) WaitSync(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.common.consensus.Synced():
		return nil
	}
}

// IsSynced checks if the consensus backend given at construction has finished syncing.
func (c *Client) IsSynced(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-c.common.consensus.Synced():
		return true, nil
	default:
		return false, nil
	}
}

// WatchBlocks subscribes to blocks for the given runtime.
func (c *Client) WatchBlocks(ctx context.Context, runtimeID signature.PublicKey) (<-chan *roothash.AnnotatedBlock, *pubsub.Subscription, error) {
	return c.common.roothash.WatchBlocks(runtimeID)
}

// GetBlock returns the block at a specific round.
//
// Pass RoundLatest to get the latest block.
func (c *Client) GetBlock(ctx context.Context, runtimeID signature.PublicKey, round uint64) (*block.Block, error) {
	if round == RoundLatest {
		return c.common.roothash.GetLatestBlock(ctx, runtimeID)
	}
	return c.common.roothash.GetBlock(ctx, runtimeID, round)
}

func (c *Client) getTxnTree(ctx context.Context, blk *block.Block) (*transaction.Tree, error) {
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		Hash:      blk.Header.IORoot,
	}

	return transaction.NewTree(ctx, c.common.storage, ioRoot)
}

func (c *Client) getTxnByHash(ctx context.Context, blk *block.Block, txHash hash.Hash) (*transaction.Transaction, error) {
	tree, err := c.getTxnTree(ctx, blk)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	return tree.GetTransaction(ctx, txHash)
}

// GetTxn returns the transaction at a specific block round and index.
//
// Pass RoundLatest for the round to get the latest block.
func (c *Client) GetTxn(ctx context.Context, runtimeID signature.PublicKey, round uint64, index uint32) (*TxnResult, error) {
	if c.indexerBackend == nil {
		return nil, ErrIndexerDisabled
	}

	blk, err := c.GetBlock(ctx, runtimeID, round)
	if err != nil {
		return nil, err
	}

	txHash, err := c.indexerBackend.QueryTxnByIndex(ctx, runtimeID, blk.Header.Round, index)
	if err != nil {
		return nil, err
	}

	tx, err := c.getTxnByHash(ctx, blk, txHash)
	if err != nil {
		return nil, err
	}

	return &TxnResult{
		Block:     blk,
		BlockHash: blk.Header.EncodedHash(),
		Index:     index,
		Input:     tx.Input,
		Output:    tx.Output,
	}, nil
}

// GetTxnByBlockHash returns the transaction at a specific block hash and index.
func (c *Client) GetTxnByBlockHash(ctx context.Context, runtimeID signature.PublicKey, blockHash hash.Hash, index uint32) (*TxnResult, error) {
	if c.indexerBackend == nil {
		return nil, ErrIndexerDisabled
	}

	blk, err := c.QueryBlock(ctx, runtimeID, blockHash)
	if err != nil {
		return nil, err
	}

	txHash, err := c.indexerBackend.QueryTxnByIndex(ctx, runtimeID, blk.Header.Round, index)
	if err != nil {
		return nil, err
	}

	tx, err := c.getTxnByHash(ctx, blk, txHash)
	if err != nil {
		return nil, err
	}

	return &TxnResult{
		Block:     blk,
		BlockHash: blk.Header.EncodedHash(),
		Index:     index,
		Input:     tx.Input,
		Output:    tx.Output,
	}, nil
}

// GetTransactions returns a list of transactions under the given transaction root.
func (c *Client) GetTransactions(ctx context.Context, runtimeID signature.PublicKey, round uint64, rootHash hash.Hash) ([][]byte, error) {
	if rootHash.IsEmpty() {
		return [][]byte{}, nil
	}

	ioRoot := storage.Root{
		Round: round,
		Hash:  rootHash,
	}
	copy(ioRoot.Namespace[:], runtimeID[:])

	tree, err := transaction.NewTree(ctx, c.common.storage, ioRoot)
	if err != nil {
		return nil, err
	}
	defer tree.Close()

	txs, err := tree.GetTransactions(ctx)
	if err != nil {
		return nil, err
	}

	var inputs [][]byte
	for _, tx := range txs {
		inputs = append(inputs, tx.Input)
	}

	return inputs, nil
}

// QueryBlock queries the block index of a given runtime.
func (c *Client) QueryBlock(ctx context.Context, runtimeID signature.PublicKey, blockHash hash.Hash) (*block.Block, error) {
	if c.indexerBackend == nil {
		return nil, ErrIndexerDisabled
	}

	round, err := c.indexerBackend.QueryBlock(ctx, runtimeID, blockHash)
	if err != nil {
		return nil, err
	}

	return c.GetBlock(ctx, runtimeID, round)
}

// QueryTxn queries the transaction index of a given runtime.
func (c *Client) QueryTxn(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (*TxnResult, error) {
	if c.indexerBackend == nil {
		return nil, ErrIndexerDisabled
	}

	round, txHash, txIndex, err := c.indexerBackend.QueryTxn(ctx, runtimeID, key, value)
	if err != nil {
		return nil, err
	}

	blk, err := c.GetBlock(ctx, runtimeID, round)
	if err != nil {
		return nil, err
	}

	tx, err := c.getTxnByHash(ctx, blk, txHash)
	if err != nil {
		return nil, err
	}

	return &TxnResult{
		Block:     blk,
		BlockHash: blk.Header.EncodedHash(),
		Index:     txIndex,
		Input:     tx.Input,
		Output:    tx.Output,
	}, nil
}

// QueryTxns queries the transaction index of a given runtime with a complex
// query and returns multiple results.
func (c *Client) QueryTxns(ctx context.Context, runtimeID signature.PublicKey, query indexer.Query) ([]*TxnResult, error) {
	if c.indexerBackend == nil {
		return nil, ErrIndexerDisabled
	}

	results, err := c.indexerBackend.QueryTxns(ctx, runtimeID, query)
	if err != nil {
		return nil, err
	}

	var output []*TxnResult
	for round, txResults := range results {
		// Fetch block for the given round.
		var blk *block.Block
		blk, err = c.GetBlock(ctx, runtimeID, round)
		if err != nil {
			return nil, err
		}

		tree, err := c.getTxnTree(ctx, blk)
		if err != nil {
			return nil, err
		}
		defer tree.Close()

		// Extract transaction data for the specified indices.
		blockHash := blk.Header.EncodedHash()
		for _, txResult := range txResults {
			tx, err := tree.GetTransaction(ctx, txResult.TxHash)
			if err != nil {
				return nil, err
			}

			output = append(output, &TxnResult{
				Block:     blk,
				BlockHash: blockHash,
				Index:     txResult.TxIndex,
				Input:     tx.Input,
				Output:    tx.Output,
			})
		}
	}

	return output, nil
}

// WaitBlockIndexed waits for a block to be indexed by the indexer.
func (c *Client) WaitBlockIndexed(ctx context.Context, runtimeID signature.PublicKey, round uint64) error {
	if c.indexerBackend == nil {
		return ErrIndexerDisabled
	}

	return c.indexerBackend.WaitBlockIndexed(ctx, runtimeID, round)
}

// CallEnclave proxies an EnclaveRPC call to the given endpoint.
//
// The endpoint should be an URI in the form <endpoint-type>://<id> where the
// <endpoint-type> is one of the known endpoint types and the <id> is an
// endpoint-specific identifier.
func (c *Client) CallEnclave(ctx context.Context, endpoint string, data []byte) ([]byte, error) {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, err
	}

	switch endpointURL.Scheme {
	case EndpointKeyManager:
		var runtimeID signature.PublicKey
		if err = runtimeID.UnmarshalHex(endpointURL.Host); err != nil {
			return nil, errors.Wrap(err, "malformed key manager EnclaveRPC endpoint")
		}

		return c.common.keyManager.CallRemote(ctx, runtimeID, data)
	default:
		c.logger.Warn("failed to route EnclaveRPC call",
			"endpoint", endpoint,
		)
		return nil, fmt.Errorf("unknown EnclaveRPC endpoint: %s", endpoint)
	}
}

// Cleanup stops all running block watchers and indexers and waits for them
// to finish.
func (c *Client) Cleanup() {
	// Watchers.
	for _, watcher := range c.watchers {
		watcher.Stop()
	}
	for _, watcher := range c.watchers {
		<-watcher.Quit()
	}

	// Indexers.
	for _, indexer := range c.indexers {
		indexer.Stop()
	}
	for _, indexer := range c.indexers {
		<-indexer.Quit()
	}
	if c.indexerBackend != nil {
		c.indexerBackend.Stop()
	}
}

// New returns a new instance of the Client service.
func New(
	ctx context.Context,
	dataDir string,
	roothash roothash.Backend,
	storage storage.Backend,
	scheduler scheduler.Backend,
	registry registry.Backend,
	consensus common.ConsensusBackend,
	keyManager *keymanager.Client,
) (*Client, error) {
	c := &Client{
		common: &clientCommon{
			roothash:   roothash,
			storage:    storage,
			scheduler:  scheduler,
			registry:   registry,
			consensus:  consensus,
			keyManager: keyManager,
			ctx:        ctx,
		},
		watchers: make(map[signature.MapKey]*blockWatcher),
		indexers: make(map[signature.MapKey]*indexer.Service),
		logger:   logging.GetLogger("client"),
	}

	// Initialize the tag indexer(s) when configured.
	indexRuntimes := viper.GetStringSlice(cfgIndexRuntimes)
	if indexRuntimes != nil {
		var impl indexer.Backend
		var err error

		backend := viper.GetString(cfgIndexBackend)
		switch strings.ToLower(backend) {
		case indexer.BleveBackendName:
			impl, err = indexer.NewBleveBackend(dataDir)
		default:
			return nil, errors.Errorf("client: unsupported indexer backend: %s", backend)
		}
		if err != nil {
			return nil, err
		}
		c.indexerBackend = impl

		for _, rawID := range indexRuntimes {
			var id signature.PublicKey
			if err = id.UnmarshalHex(rawID); err != nil {
				return nil, err
			}

			var idx *indexer.Service
			idx, err = indexer.New(id, c.indexerBackend, roothash, storage)
			if err != nil {
				return nil, err
			}

			c.indexers[id.ToMapKey()] = idx
		}

		// Start all indexers.
		for _, indexer := range c.indexers {
			if err = indexer.Start(); err != nil {
				return nil, err
			}
		}
	}

	return c, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().String(cfgIndexBackend, indexer.BleveBackendName, "Tag indexer backend")
		cmd.Flags().StringSlice(cfgIndexRuntimes, nil, "IDs of runtimes to index tags for")
	}

	for _, v := range []string{
		cfgIndexBackend,
		cfgIndexRuntimes,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}
