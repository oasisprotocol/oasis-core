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
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/grpc/resolver/manual"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/grpc/txnscheduler"
	"github.com/oasislabs/ekiden/go/keymanager"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
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
	// ErrBadIndexOrCorrupted is an error when either the storage is corrupted or
	// the specified transaction index was bad.
	ErrBadIndexOrCorrupted = errors.New("bad transaction index or corrupted storage")
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
	keyManager *keymanager.KeyManager

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

	nodeCert, err := nodeMeta.Certificate.Parse()
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

	var addresses []resolver.Address
	for _, addr := range nodeMeta.Addresses {
		addresses = append(addresses, resolver.Address{Addr: addr.String()})
	}
	manualResolver.NewAddress(addresses)

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
	requestID.From(txData)
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
func (c *Client) WatchBlocks(ctx context.Context, runtimeID signature.PublicKey) (<-chan *block.Block, *pubsub.Subscription, error) {
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

func (c *Client) getTxnData(ctx context.Context, blk *block.Block) ([][]byte, [][]byte, error) {
	if blk.Header.InputHash.IsEmpty() {
		return [][]byte{}, [][]byte{}, nil
	}

	// Fetch transaction input and output.
	var inputHash storage.Key
	copy(inputHash[:], blk.Header.InputHash[:])
	var outputHash storage.Key
	copy(outputHash[:], blk.Header.OutputHash[:])

	txn, err := c.common.storage.GetBatch(ctx, []storage.Key{inputHash, outputHash})
	if err != nil {
		return nil, nil, err
	}

	var inputs [][]byte
	if err := cbor.Unmarshal(txn[0], &inputs); err != nil {
		return nil, nil, errors.Wrap(err, "client: failed to unmarshal transaction inputs")
	}

	var outputs [][]byte
	if err := cbor.Unmarshal(txn[1], &outputs); err != nil {
		return nil, nil, errors.Wrap(err, "client: failed to unmarshal transaction outputs")
	}

	return inputs, outputs, nil
}

func (c *Client) getTxnDataAtIndex(ctx context.Context, blk *block.Block, index uint32) ([]byte, []byte, error) {
	inputs, outputs, err := c.getTxnData(ctx, blk)
	if err != nil {
		return nil, nil, err
	}

	if int(index) >= len(inputs) {
		return nil, nil, ErrBadIndexOrCorrupted
	}
	if int(index) >= len(outputs) {
		return nil, nil, ErrBadIndexOrCorrupted
	}

	return inputs[index], outputs[index], nil
}

// GetTxn returns the transaction at a specific block round and index.
//
// Pass RoundLatest for the round to get the latest block.
func (c *Client) GetTxn(ctx context.Context, runtimeID signature.PublicKey, round uint64, index uint32) (*TxnResult, error) {
	blk, err := c.GetBlock(ctx, runtimeID, round)
	if err != nil {
		return nil, err
	}

	input, output, err := c.getTxnDataAtIndex(ctx, blk, index)
	if err != nil {
		return nil, err
	}

	return &TxnResult{
		Block:     blk,
		BlockHash: blk.Header.EncodedHash(),
		Index:     index,
		Input:     input,
		Output:    output,
	}, nil
}

// GetTxnByBlockHash returns the transaction at a specific block hash and index.
func (c *Client) GetTxnByBlockHash(ctx context.Context, runtimeID signature.PublicKey, blockHash hash.Hash, index uint32) (*TxnResult, error) {
	blk, err := c.QueryBlock(ctx, runtimeID, indexer.TagBlockHash, blockHash[:])
	if err != nil {
		return nil, err
	}

	input, output, err := c.getTxnDataAtIndex(ctx, blk, index)
	if err != nil {
		return nil, err
	}

	return &TxnResult{
		Block:     blk,
		BlockHash: blk.Header.EncodedHash(),
		Index:     index,
		Input:     input,
		Output:    output,
	}, nil
}

// GetTransactions returns a list of transactions under the given transaction root.
func (c *Client) GetTransactions(ctx context.Context, runtimeID signature.PublicKey, root hash.Hash) ([][]byte, error) {
	if root.IsEmpty() {
		return [][]byte{}, nil
	}

	// Fetch transaction input and output.
	var key storage.Key
	copy(key[:], root[:])

	// TODO: Change after transactions are in MKVS.
	txn, err := c.common.storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var txns [][]byte
	if err := cbor.Unmarshal(txn, &txns); err != nil {
		return nil, errors.Wrap(err, "client: failed to unmarshal transactions")
	}

	return txns, nil
}

// QueryBlock queries the block index of a given runtime.
func (c *Client) QueryBlock(ctx context.Context, runtimeID signature.PublicKey, key, value []byte) (*block.Block, error) {
	if c.indexerBackend == nil {
		return nil, ErrIndexerDisabled
	}

	round, err := c.indexerBackend.QueryBlock(ctx, runtimeID, key, value)
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

	round, txnIdx, err := c.indexerBackend.QueryTxn(ctx, runtimeID, key, value)
	if err != nil {
		return nil, err
	}

	blk, err := c.GetBlock(ctx, runtimeID, round)
	if err != nil {
		return nil, err
	}

	input, output, err := c.getTxnDataAtIndex(ctx, blk, txnIdx)
	if err != nil {
		return nil, err
	}

	return &TxnResult{
		Block:     blk,
		BlockHash: blk.Header.EncodedHash(),
		Index:     txnIdx,
		Input:     input,
		Output:    output,
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
	for round, indices := range results {
		// Fetch block for the given round.
		var blk *block.Block
		blk, err = c.GetBlock(ctx, runtimeID, round)
		if err != nil {
			return nil, err
		}

		var inputs, outputs [][]byte
		inputs, outputs, err = c.getTxnData(ctx, blk)
		if err != nil {
			return nil, err
		}

		// Extract transaction data for the specified indices.
		blockHash := blk.Header.EncodedHash()
		for _, idx := range indices {
			if int(idx) >= len(inputs) || int(idx) >= len(outputs) {
				return nil, ErrBadIndexOrCorrupted
			}

			output = append(output, &TxnResult{
				Block:     blk,
				BlockHash: blockHash,
				Index:     uint32(idx),
				Input:     inputs[idx],
				Output:    outputs[idx],
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
	keyManager *keymanager.KeyManager,
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
