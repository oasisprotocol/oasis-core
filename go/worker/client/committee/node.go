package committee

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/eapache/channels"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtime "github.com/oasisprotocol/oasis-core/go/runtime/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/bundle/component"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	"github.com/oasisprotocol/oasis-core/go/worker/registration"
)

type pendingTx struct {
	chs map[chan *api.SubmitTxResult]struct{}
}

type wantTx struct {
	txHash hash.Hash
	ch     chan *api.SubmitTxResult
	remove bool
}

// Node is a client node.
type Node struct {
	commonNode   *committee.Node
	roleProvider registration.RoleProvider

	stopCh   chan struct{}
	stopOnce sync.Once
	quitCh   chan struct{}
	initCh   chan struct{}

	txCh *channels.InfiniteChannel

	logger *logging.Logger
}

// Name returns the service name.
func (n *Node) Name() string {
	return "client committee node"
}

// Start starts the service.
func (n *Node) Start() error {
	go n.worker()
	return nil
}

// Stop halts the service.
func (n *Node) Stop() {
	n.stopOnce.Do(func() { close(n.stopCh) })
}

// Quit returns a channel that will be closed when the service terminates.
func (n *Node) Quit() <-chan struct{} {
	return n.quitCh
}

// Cleanup performs the service specific post-termination cleanup.
func (n *Node) Cleanup() {
}

// Initialized returns a channel that will be closed when the node is
// initialized and ready to service requests.
func (n *Node) Initialized() <-chan struct{} {
	return n.initCh
}

// HandleNewBlockLocked is guarded by CrossNode.
func (n *Node) HandleNewBlockLocked(*runtime.BlockInfo) {
	// Nothing to do here.
}

// HandleRuntimeHostEventLocked is guarded by CrossNode.
func (n *Node) HandleRuntimeHostEventLocked(ev *host.Event) {
	if n.roleProvider == nil {
		return
	}

	switch {
	case ev.Started != nil:
		n.roleProvider.SetAvailable(n.commonNode.RegisterNodeRuntime)
	case ev.FailedToStart != nil, ev.Stopped != nil:
		n.roleProvider.SetUnavailable()
	default:
	}
}

// SubmitTxSubscription is a subscription to a transaction submission result.
type SubmitTxSubscription struct {
	txHash hash.Hash
	ch     chan *api.SubmitTxResult

	n *Node
}

// Result returns a channel that will receive the transaction submission result once the transaction
// has been included in a block.
func (sr *SubmitTxSubscription) Result() <-chan *api.SubmitTxResult {
	return sr.ch
}

// Stop notifies the client to stop watching for the transaction submission result.
func (sr *SubmitTxSubscription) Stop() {
	sr.n.txCh.In() <- &wantTx{
		txHash: sr.txHash,
		ch:     sr.ch,
		remove: true,
	}
}

// SubmitTx submits the transaction to the transaction pool, waits for it to be checked and returns
// a subscription that gets a notification when the transaction is included in a block.
//
// When the caller is not interested in the transaction execution result, it should call `Stop` on
// the returned subscription. Not doing so may leak resources associated with tracking the submitted
// transaction.
func (n *Node) SubmitTx(ctx context.Context, tx []byte) (*SubmitTxSubscription, *protocol.Error, error) {
	// Make sure consensus is synced.
	select {
	case <-n.commonNode.Consensus.Synced():
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
		return nil, nil, api.ErrNotSynced
	}

	// Submit transaction to the pool and wait for it to get checked.
	result, err := n.commonNode.TxPool.SubmitTx(ctx, tx, true, false)
	if err != nil {
		return nil, nil, err
	}
	if !result.IsSuccess() {
		return nil, &result.Error, nil
	}

	txHash := hash.NewFromBytes(tx)
	ch := make(chan *api.SubmitTxResult, 1)
	n.txCh.In() <- &wantTx{
		txHash: txHash,
		ch:     ch,
	}

	sub := &SubmitTxSubscription{
		txHash: txHash,
		ch:     ch,
		n:      n,
	}
	return sub, nil, nil
}

func (n *Node) CheckTx(ctx context.Context, tx []byte) (*protocol.CheckTxResult, error) {
	return n.commonNode.TxPool.SubmitTx(ctx, tx, true, true)
}

func (n *Node) Query(ctx context.Context, round uint64, method string, args []byte, comp *component.ID) ([]byte, error) {
	hrt := n.commonNode.GetHostedRuntime()

	// Fetch the active descriptor so we can get the current message limits.
	n.commonNode.CrossNode.Lock()
	dsc := n.commonNode.CurrentDescriptor
	blk := n.commonNode.CurrentBlock
	n.commonNode.CrossNode.Unlock()

	if dsc == nil || blk == nil {
		return nil, api.ErrNoHostedRuntime
	}
	maxMessages := dsc.Executor.MaxMessages

	annBlk, err := n.commonNode.Runtime.History().GetAnnotatedBlock(ctx, round)
	if err != nil {
		return nil, fmt.Errorf("client: failed to fetch annotated block from history: %w", err)
	}

	lb, err := n.commonNode.Consensus.Core().GetLightBlock(ctx, annBlk.Height)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get light block at height %d: %w", annBlk.Height, err)
	}
	epoch, err := n.commonNode.Consensus.Beacon().GetEpoch(ctx, annBlk.Height)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get epoch at height %d: %w", annBlk.Height, err)
	}

	// Route to correct component -- an empty component implies RONL.
	if comp == nil {
		comp = &component.ID_RONL
	}
	rt, ok := hrt.Component(*comp)
	if !ok {
		return nil, fmt.Errorf("component '%s' not found", comp)
	}
	dst := host.NewRichRuntime(rt)

	return dst.Query(ctx, annBlk.Block, lb, epoch, maxMessages, method, args)
}

func (n *Node) checkBlock(ctx context.Context, blk *block.Block, pending map[hash.Hash]*pendingTx) error {
	if blk.Header.IORoot.IsEmpty() {
		return nil
	}

	// If there's no pending transactions, we can skip the check.
	if len(pending) == 0 {
		return nil
	}

	tree := transaction.NewTree(n.commonNode.Runtime.Storage(), blk.Header.StorageRootIO())
	defer tree.Close()

	// Check if there's anything interesting in this block.
	var txHashes []hash.Hash
	for txHash := range pending {
		txHashes = append(txHashes, txHash)
	}

	matches, err := tree.GetTransactionMultiple(ctx, txHashes)
	if err != nil {
		return fmt.Errorf("error getting block I/O from storage: %w", err)
	}

	var processed []hash.Hash
	for txHash, tx := range matches {
		pTx := pending[txHash]
		for ch := range pTx.chs {
			ch <- &api.SubmitTxResult{
				Result: &api.SubmitTxMetaResponse{
					Round:      blk.Header.Round,
					BatchOrder: tx.BatchOrder,
					Output:     tx.Output,
				},
			}
			close(ch)
		}
		delete(pending, txHash)
		processed = append(processed, txHash)
	}

	// Remove processed transactions from pool.
	n.commonNode.TxPool.HandleTxsUsed(processed)

	return nil
}

func (n *Node) worker() {
	defer close(n.quitCh)

	// Wait for the common node to be initialized.
	select {
	case <-n.commonNode.Initialized():
	case <-n.stopCh:
		close(n.initCh)
		return
	}

	n.logger.Info("starting committee node")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-n.stopCh
		cancel()
	}()

	// Subscribe to blocks being synced to local storage.
	blkCh, blkSub, err := n.commonNode.Runtime.History().WatchBlocks()
	if err != nil {
		close(n.initCh)
		return
	}
	defer blkSub.Close()

	// We are initialized.
	close(n.initCh)

	var (
		recheckTicker *backoff.Ticker
		blocks        []*block.Block
	)
	pending := make(map[hash.Hash]*pendingTx)
	for {
		var recheckCh <-chan time.Time
		if recheckTicker != nil {
			recheckCh = recheckTicker.C
		}

		select {
		case <-n.stopCh:
			n.logger.Info("termination requested")
			return
		case rtx := <-n.txCh.Out():
			tx := rtx.(*wantTx)
			existingTx, ok := pending[tx.txHash]

			switch tx.remove {
			case false:
				// Interest in the transaction.
				if !ok {
					existingTx = &pendingTx{
						chs: make(map[chan *api.SubmitTxResult]struct{}),
					}
					pending[tx.txHash] = existingTx
				}

				existingTx.chs[tx.ch] = struct{}{}
			case true:
				// Removal of interest in the transaction.
				if !ok {
					continue
				}

				delete(existingTx.chs, tx.ch)
				if len(existingTx.chs) == 0 {
					delete(pending, tx.txHash)
				}
			}
			continue
		case blk := <-blkCh:
			blocks = append(blocks, blk.Block)
		case <-recheckCh:
		}

		// Check blocks.
		var failedBlocks []*block.Block
		for _, blk := range blocks {
			if err := n.checkBlock(ctx, blk, pending); err != nil {
				n.logger.Error("error checking block",
					"err", err,
					"round", blk.Header.Round,
				)
				failedBlocks = append(failedBlocks, blk)
			}
		}
		if len(failedBlocks) > 0 {
			n.logger.Warn("failed roothash blocks",
				"num_failed_blocks", len(failedBlocks),
			)

			// Start recheck ticker.
			if recheckTicker == nil {
				boff := cmnBackoff.NewExponentialBackOff()
				boff.InitialInterval = 5 * time.Second
				recheckTicker = backoff.NewTicker(boff)
			}
		} else if recheckTicker != nil {
			recheckTicker.Stop()
			recheckTicker = nil
		}
		blocks = failedBlocks
	}
}

// NewNode creates a new client node.
func NewNode(commonNode *committee.Node, roleProvider registration.RoleProvider) (*Node, error) {
	n := &Node{
		commonNode:   commonNode,
		roleProvider: roleProvider,
		stopCh:       make(chan struct{}),
		quitCh:       make(chan struct{}),
		initCh:       make(chan struct{}),
		txCh:         channels.NewInfiniteChannel(),
		logger:       logging.GetLogger("worker/client/committee").With("runtime_id", commonNode.Runtime.ID()),
	}
	return n, nil
}
