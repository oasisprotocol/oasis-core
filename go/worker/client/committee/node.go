package committee

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/eapache/channels"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	"github.com/oasisprotocol/oasis-core/go/runtime/host"
	"github.com/oasisprotocol/oasis-core/go/runtime/host/protocol"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/runtime/txpool"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/common/committee"
)

type pendingTx struct {
	txHash hash.Hash
	ch     chan *api.SubmitTxResult
}

// Node is a client node.
type Node struct {
	commonNode *committee.Node

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

func (n *Node) HandlePeerTx(context.Context, []byte) error {
	// Nothing to do here.
	return nil
}

// HandleEpochTransitionLocked is guarded by CrossNode.
func (n *Node) HandleEpochTransitionLocked(*committee.EpochSnapshot) {
}

// HandleNewBlockEarlyLocked is guarded by CrossNode.
func (n *Node) HandleNewBlockEarlyLocked(*block.Block) {
}

// HandleNewBlockLocked is guarded by CrossNode.
func (n *Node) HandleNewBlockLocked(*block.Block) {
}

// HandleNewEventLocked is guarded by CrossNode.
func (n *Node) HandleNewEventLocked(*roothash.Event) {
}

// HandleRuntimeHostEventLocked is guarded by CrossNode.
func (n *Node) HandleRuntimeHostEventLocked(*host.Event) {
}

func (n *Node) SubmitTx(ctx context.Context, tx []byte) (<-chan *api.SubmitTxResult, *protocol.Error, error) {
	// Make sure consensus is synced.
	select {
	case <-n.commonNode.Consensus.Synced():
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
		return nil, nil, api.ErrNotSynced
	}

	// Submit transaction to the pool and wait for it to get checked.
	result, err := n.commonNode.TxPool.SubmitTx(ctx, tx, &txpool.TransactionMeta{Local: true})
	if err != nil {
		return nil, nil, err
	}
	if !result.IsSuccess() {
		return nil, &result.Error, nil
	}

	ch := make(chan *api.SubmitTxResult, 1)
	n.txCh.In() <- &pendingTx{
		txHash: hash.NewFromBytes(tx),
		ch:     ch,
	}

	return ch, nil, nil
}

func (n *Node) CheckTx(ctx context.Context, tx []byte) (*protocol.CheckTxResult, error) {
	return n.commonNode.TxPool.SubmitTx(ctx, tx, &txpool.TransactionMeta{Local: true, Discard: true})
}

func (n *Node) Query(ctx context.Context, round uint64, method string, args []byte) ([]byte, error) {
	hrt := n.commonNode.GetHostedRuntime()
	if hrt == nil {
		return nil, api.ErrNoHostedRuntime
	}

	// Fetch the active descriptor so we can get the current message limits.
	n.commonNode.CrossNode.Lock()
	dsc := n.commonNode.CurrentDescriptor
	latestRound := n.commonNode.CurrentBlock.Header.Round
	n.commonNode.CrossNode.Unlock()

	if dsc == nil {
		return nil, api.ErrNoHostedRuntime
	}
	maxMessages := dsc.Executor.MaxMessages

	rtInfo, err := hrt.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("client: failed to fetch runtime info: %w", err)
	}

	// TODO: Remove once same block consensus validation is deployed.
	if !rtInfo.Features.SameBlockConsensusValidation {
		var resolvedRound uint64
		queryFn := func(round uint64) ([]byte, error) {
			var annBlk *roothash.AnnotatedBlock
			annBlk, err = n.commonNode.Runtime.History().GetAnnotatedBlock(ctx, round)
			if err != nil {
				return nil, fmt.Errorf("client: failed to fetch annotated block from history: %w", err)
			}
			resolvedRound = annBlk.Block.Header.Round

			// Get consensus light block for state after executing block at given height.
			var lb *consensus.LightBlock
			lb, err = n.commonNode.Consensus.GetLightBlockForState(ctx, annBlk.Height)
			if err != nil {
				return nil, fmt.Errorf("client: failed to get light block at height %d: %w", annBlk.Height, err)
			}
			var epoch beacon.EpochTime
			epoch, err = n.commonNode.Consensus.Beacon().GetEpoch(ctx, annBlk.Height)
			if err != nil {
				return nil, fmt.Errorf("client: failed to get epoch at height %d: %w", annBlk.Height, err)
			}

			return hrt.Query(ctx, annBlk.Block, lb, epoch, maxMessages, method, args)
		}

		var data []byte
		data, err = queryFn(round)
		if errors.Is(err, protocol.ErrVerifierVerificationFailed) {
			// The query failed due to the runtime's consensus verifier failing to verify the given
			// header. We assume that this is because a finalized header is not yet available for the
			// given round.
			switch round {
			case api.RoundLatest, latestRound:
				// Since we are allowed to decide what we see as the latest round, use an earlier one.
				n.logger.Debug("runtime's consensus verifier reports failure, retrying",
					"method", method,
					"target_round", resolvedRound,
				)

				data, err = queryFn(resolvedRound - 1)
			default:
				// A specific round was given so this query is not yet possible.
				n.logger.Debug("runtime's consensus verifier reports failure",
					"method", method,
					"target_round", round,
				)

				return nil, roothash.ErrNotFound
			}
		}
		return data, err
	}

	annBlk, err := n.commonNode.Runtime.History().GetAnnotatedBlock(ctx, round)
	if err != nil {
		return nil, fmt.Errorf("client: failed to fetch annotated block from history: %w", err)
	}

	lb, err := n.commonNode.Consensus.GetLightBlock(ctx, annBlk.Height)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get light block at height %d: %w", annBlk.Height, err)
	}
	epoch, err := n.commonNode.Consensus.Beacon().GetEpoch(ctx, annBlk.Height)
	if err != nil {
		return nil, fmt.Errorf("client: failed to get epoch at height %d: %w", annBlk.Height, err)
	}

	return hrt.Query(ctx, annBlk.Block, lb, epoch, maxMessages, method, args)
}

func (n *Node) checkBlock(ctx context.Context, blk *block.Block, pending map[hash.Hash]*pendingTx) error {
	if blk.Header.IORoot.IsEmpty() {
		return nil
	}

	// If there's no pending transactions, we can skip the check.
	if len(pending) == 0 {
		return nil
	}

	ioRoot := storage.Root{
		Namespace: blk.Header.Namespace,
		Version:   blk.Header.Round,
		Type:      storage.RootTypeIO,
		Hash:      blk.Header.IORoot,
	}

	tree := transaction.NewTree(n.commonNode.Runtime.Storage(), ioRoot)
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
		pTx.ch <- &api.SubmitTxResult{
			Result: &api.SubmitTxMetaResponse{
				Round:      blk.Header.Round,
				BatchOrder: tx.BatchOrder,
				Output:     tx.Output,
			},
		}
		close(pTx.ch)
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
			tx := rtx.(*pendingTx)
			pending[tx.txHash] = tx
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
func NewNode(commonNode *committee.Node) (*Node, error) {
	n := &Node{
		commonNode: commonNode,
		stopCh:     make(chan struct{}),
		quitCh:     make(chan struct{}),
		initCh:     make(chan struct{}),
		txCh:       channels.NewInfiniteChannel(),
		logger:     logging.GetLogger("worker/client/committee").With("runtime_id", commonNode.Runtime.ID()),
	}
	return n, nil
}
