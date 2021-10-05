// Package client contains the runtime client.
package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/p2p"
)

const (
	// CfgMaxTransactionAge is the number of consensus blocks after which
	// submitted transactions will be considered expired.
	CfgMaxTransactionAge = "runtime.client.max_transaction_age"

	minMaxTransactionAge = 30

	// hostedRuntimeProvisionTimeout is the maximum amount of time to wait for the hosted runtime
	// to be provisioned before cancelling the request.
	hostedRuntimeProvisionTimeout = 30 * time.Second
)

var (
	_ api.RuntimeClient = (*runtimeClient)(nil)

	// Flags has the flags used by the runtime client.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
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
	quitCh chan struct{}

	hosts        map[common.Namespace]*clientHost
	txSubmitters map[common.Namespace]*txSubmitter

	maxTransactionAge int64

	logger *logging.Logger
}

func (c *runtimeClient) getHostedRuntime(ctx context.Context, runtimeID common.Namespace) (host.RichRuntime, error) {
	clientHost, ok := c.hosts[runtimeID]
	if !ok {
		return nil, api.ErrNoHostedRuntime
	}
	wrtCtx, cancel := context.WithTimeout(ctx, hostedRuntimeProvisionTimeout)
	hrt, err := clientHost.WaitHostedRuntime(wrtCtx)
	cancel()
	if err != nil {
		return nil, api.ErrNoHostedRuntime
	}
	return hrt, nil
}

func (c *runtimeClient) submitTx(ctx context.Context, request *api.SubmitTxRequest) (<-chan *txResult, error) {
	if c.common.p2p == nil {
		return nil, fmt.Errorf("client: cannot submit transaction, p2p disabled")
	}

	// Make sure that the runtime is actually among the supported runtimes for this node as
	// otherwise we will not be able to actually get any results back.
	if _, err := c.common.runtimeRegistry.GetRuntime(request.RuntimeID); err != nil {
		return nil, fmt.Errorf("client: cannot resolve runtime: %w", err)
	}

	// Make sure consensus is synced.
	select {
	case <-c.common.consensus.Synced():
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		return nil, api.ErrNotSynced
	}

	respCh := make(chan *txResult, 1)

	// Perform a local transaction check when a hosted runtime is available.
	if _, ok := c.hosts[request.RuntimeID]; ok {
		resp, err := c.checkTx(ctx, &api.CheckTxRequest{
			RuntimeID: request.RuntimeID,
			Data:      request.Data,
		})
		if err != nil {
			return nil, err
		}
		if !resp.IsSuccess() {
			respCh <- &txResult{
				result: &api.SubmitTxMetaResponse{
					CheckTxError: &resp.Error,
				},
			}
			close(respCh)
			return respCh, nil
		}
	}

	var submitter *txSubmitter
	var ok bool
	c.Lock()
	if submitter, ok = c.txSubmitters[request.RuntimeID]; !ok {
		submitter = newTxSubmitter(c.common, request.RuntimeID, c.common.p2p, c.maxTransactionAge)
		submitter.Start()
		c.txSubmitters[request.RuntimeID] = submitter
	}
	c.Unlock()

	// Send a request for watching a new runtime transaction.
	req := &txRequest{
		ctx:    ctx,
		respCh: respCh,
		req:    request,
	}
	req.id.FromBytes(request.Data)
	select {
	case <-ctx.Done():
		// The context we're working in was canceled, abort.
		return nil, ctx.Err()
	case <-c.common.ctx.Done():
		// Client is shutting down.
		return nil, fmt.Errorf("client: shutting down")
	case submitter.newCh <- req:
	}

	return respCh, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) SubmitTx(ctx context.Context, request *api.SubmitTxRequest) ([]byte, error) {
	resp, err := c.SubmitTxMeta(ctx, request)
	if err != nil {
		return nil, err
	}
	if resp.CheckTxError != nil {
		return nil, errors.WithContext(api.ErrCheckTxFailed, resp.CheckTxError.String())
	}
	return resp.Output, nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) SubmitTxMeta(ctx context.Context, request *api.SubmitTxRequest) (*api.SubmitTxMetaResponse, error) {
	respCh, err := c.submitTx(ctx, request)
	if err != nil {
		return nil, err
	}

	// Wait for result.
	for {
		var resp *txResult
		var ok bool

		select {
		case <-ctx.Done():
			// The context we're working in was canceled, abort.
			return nil, ctx.Err()
		case <-c.common.ctx.Done():
			// Client is shutting down.
			return nil, fmt.Errorf("client: shutting down")
		case resp, ok = <-respCh:
			if !ok {
				return nil, fmt.Errorf("client: block watch channel closed unexpectedly (unknown error)")
			}
			return resp.result, resp.err
		}
	}
}

// Implements api.RuntimeClient.
func (c *runtimeClient) SubmitTxNoWait(ctx context.Context, request *api.SubmitTxRequest) error {
	_, err := c.submitTx(ctx, request)
	return err
}

func (c *runtimeClient) checkTx(ctx context.Context, request *api.CheckTxRequest) (*protocol.CheckTxResult, error) {
	rt, err := c.getHostedRuntime(ctx, request.RuntimeID)
	if err != nil {
		return nil, err
	}

	// Get current blocks.
	rs, err := c.common.consensus.RootHash().GetRuntimeState(ctx, &roothash.RuntimeRequest{
		RuntimeID: request.RuntimeID,
		Height:    consensus.HeightLatest,
	})
	if err != nil {
		return nil, fmt.Errorf("client: failed to get runtime %s state: %w", request.RuntimeID, err)
	}
	lb, err := c.common.consensus.GetLightBlock(ctx, rs.CurrentBlockHeight)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get light block at height %d: %w", rs.CurrentBlockHeight, err)
	}
	epoch, err := c.common.consensus.Beacon().GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get current epoch: %w", err)
	}
	maxMessages := rs.Runtime.Executor.MaxMessages

	resp, err := rt.CheckTx(ctx, rs.CurrentBlock, lb, epoch, maxMessages, transaction.RawBatch{request.Data})
	if err != nil {
		return nil, fmt.Errorf("client: local transaction check failed: %w", err)
	}
	return &resp[0], nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) CheckTx(ctx context.Context, request *api.CheckTxRequest) error {
	resp, err := c.checkTx(ctx, request)
	if err != nil {
		return err
	}
	if !resp.IsSuccess() {
		return errors.WithContext(api.ErrCheckTxFailed, resp.Error.String())
	}

	return nil
}

// Implements api.RuntimeClient.
func (c *runtimeClient) WatchBlocks(ctx context.Context, runtimeID common.Namespace) (<-chan *roothash.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	return c.common.consensus.RootHash().WatchBlocks(ctx, runtimeID)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetGenesisBlock(ctx context.Context, runtimeID common.Namespace) (*block.Block, error) {
	return c.common.consensus.RootHash().GetGenesisBlock(ctx, &roothash.RuntimeRequest{
		RuntimeID: runtimeID,
		Height:    consensus.HeightLatest,
	})
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetBlock(ctx context.Context, request *api.GetBlockRequest) (*block.Block, error) {
	rt, err := c.common.runtimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}
	return rt.History().GetBlock(ctx, request.Round)
}

func (c *runtimeClient) getTxnTree(blk *block.Block) *transaction.Tree {
	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round,
		Type:      storage.RootTypeIO,
		Hash:      blk.Header.IORoot,
	}

	return transaction.NewTree(c.common.storage, ioRoot)
}

// Implements api.RuntimeClient.
func (c *runtimeClient) GetTransactions(ctx context.Context, request *api.GetTransactionsRequest) ([][]byte, error) {
	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	tree := c.getTxnTree(blk)
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
func (c *runtimeClient) GetTransactionsWithResults(ctx context.Context, request *api.GetTransactionsRequest) ([]*api.TransactionWithResults, error) {
	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	tree := c.getTxnTree(blk)
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
func (c *runtimeClient) GetEvents(ctx context.Context, request *api.GetEventsRequest) ([]*api.Event, error) {
	blk, err := c.GetBlock(ctx, &api.GetBlockRequest{RuntimeID: request.RuntimeID, Round: request.Round})
	if err != nil {
		return nil, err
	}

	tree := c.getTxnTree(blk)
	defer tree.Close()

	tags, err := tree.GetTags(ctx)
	if err != nil {
		return nil, err
	}

	var events []*api.Event
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
func (c *runtimeClient) Query(ctx context.Context, request *api.QueryRequest) (*api.QueryResponse, error) {
	hrt, err := c.getHostedRuntime(ctx, request.RuntimeID)
	if err != nil {
		return nil, err
	}
	rt, err := c.common.runtimeRegistry.GetRuntime(request.RuntimeID)
	if err != nil {
		return nil, err
	}
	annBlk, err := rt.History().GetAnnotatedBlock(ctx, request.Round)
	if err != nil {
		return nil, fmt.Errorf("client: failed to fetch annotated block from history: %w", err)
	}

	// Get consensus state at queried round.
	lb, err := c.common.consensus.GetLightBlock(ctx, annBlk.Height)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get light block at height %d: %w", annBlk.Height, err)
	}
	epoch, err := c.common.consensus.Beacon().GetEpoch(ctx, annBlk.Height)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get epoch at height %d: %w", annBlk.Height, err)
	}

	// Fetch the active descriptor so we can get the current message limits.
	rtDsc, err := rt.ActiveDescriptor(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get active runtime descriptor: %w", err)
	}
	maxMessages := rtDsc.Executor.MaxMessages

	data, err := hrt.Query(ctx, annBlk.Block, lb, epoch, maxMessages, request.Method, request.Args)
	if err != nil {
		return nil, err
	}
	return &api.QueryResponse{Data: data}, nil
}

// Implements service.BackgroundService.
func (c *runtimeClient) Name() string {
	return "runtime client"
}

// Implements service.BackgroundService.
func (c *runtimeClient) Start() error {
	for _, host := range c.hosts {
		if err := host.Start(); err != nil {
			return err
		}
	}
	go func() {
		defer close(c.quitCh)
		for _, host := range c.hosts {
			<-host.Quit()
		}
	}()
	return nil
}

// Implements service.BackgroundService.
func (c *runtimeClient) Stop() {
	// Watchers.
	c.Lock()
	for _, submitter := range c.txSubmitters {
		submitter.Stop()
	}
	c.Unlock()
	// Hosts.
	for _, host := range c.hosts {
		host.Stop()
	}
}

// Implements service.BackgroundService.
func (c *runtimeClient) Quit() <-chan struct{} {
	return c.quitCh
}

// Cleanup waits for all block watchers to finish.
func (c *runtimeClient) Cleanup() {
	// Watchers.
	c.Lock()
	for _, submitter := range c.txSubmitters {
		<-submitter.Quit()
	}
	c.Unlock()
}

// New returns a new runtime client instance.
func New(
	ctx context.Context,
	dataDir string,
	consensus consensus.Backend,
	runtimeRegistry runtimeRegistry.Registry,
	p2p *p2p.P2P,
) (api.RuntimeClientService, error) {
	maxTransactionAge := viper.GetInt64(CfgMaxTransactionAge)
	if maxTransactionAge < minMaxTransactionAge && !cmdFlags.DebugDontBlameOasis() {
		return nil, fmt.Errorf("max transaction age too low: %d, minimum: %d", maxTransactionAge, minMaxTransactionAge)
	}

	c := &runtimeClient{
		common: &clientCommon{
			storage:         runtimeRegistry.StorageRouter(),
			consensus:       consensus,
			runtimeRegistry: runtimeRegistry,
			ctx:             ctx,
			p2p:             p2p,
		},
		quitCh:            make(chan struct{}),
		hosts:             make(map[common.Namespace]*clientHost),
		txSubmitters:      make(map[common.Namespace]*txSubmitter),
		maxTransactionAge: maxTransactionAge,
		logger:            logging.GetLogger("runtime/client"),
	}

	// Create all configured runtime hosts.
	for _, rt := range runtimeRegistry.Runtimes() {
		if !rt.HasHost() {
			continue
		}

		host, err := newClientHost(rt, consensus)
		if err != nil {
			return nil, fmt.Errorf("failed to create new client host for %s: %w", rt.ID(), err)
		}
		c.hosts[rt.ID()] = host
	}

	return c, nil
}

func init() {
	Flags.Int64(CfgMaxTransactionAge, 1500, "number of consensus blocks after which submitted transactions will be considered expired")

	_ = viper.BindPFlags(Flags)
}
