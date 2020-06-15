// Package roothash implements the tendermint backed roothash backend.
package roothash

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/eapache/channels"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/service"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

const crashPointBlockBeforeIndex = "roothash.before_index"

var _ api.Backend = (*tendermintBackend)(nil)

type runtimeBrokers struct {
	sync.Mutex

	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker

	lastBlockHeight int64
	lastBlock       *block.Block
}

type tendermintBackend struct {
	sync.RWMutex

	ctx    context.Context
	logger *logging.Logger

	service         service.TendermintService
	querier         *app.QueryFactory
	lastBlockHeight int64

	allBlockNotifier *pubsub.Broker
	runtimeNotifiers map[common.Namespace]*runtimeBrokers
	genesisBlocks    map[common.Namespace]*block.Block

	closeOnce      sync.Once
	closedCh       chan struct{}
	initCh         chan struct{}
	blockHistoryCh chan api.BlockHistory
}

func (tb *tendermintBackend) GetGenesisBlock(ctx context.Context, id common.Namespace, height int64) (*block.Block, error) {
	// First check if we have the genesis blocks cached. They are immutable so easy
	// to cache to avoid repeated requests to the Tendermint app.
	tb.RLock()
	if blk := tb.genesisBlocks[id]; blk != nil {
		tb.RUnlock()
		return blk, nil
	}
	tb.RUnlock()

	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	blk, err := q.GenesisBlock(ctx, id)
	if err != nil {
		return nil, err
	}

	// Update the genesis block cache.
	tb.Lock()
	tb.genesisBlocks[id] = blk
	tb.Unlock()

	return blk, nil
}

func (tb *tendermintBackend) GetLatestBlock(ctx context.Context, id common.Namespace, height int64) (*block.Block, error) {
	return tb.getLatestBlockAt(ctx, id, height)
}

func (tb *tendermintBackend) getLatestBlockAt(ctx context.Context, id common.Namespace, height int64) (*block.Block, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LatestBlock(ctx, id)
}

func (tb *tendermintBackend) WatchBlocks(id common.Namespace) (<-chan *api.AnnotatedBlock, *pubsub.Subscription, error) {
	notifiers := tb.getRuntimeNotifiers(id)

	sub := notifiers.blockNotifier.SubscribeEx(-1, func(ch channels.Channel) {
		// Replay the latest block if it exists.
		notifiers.Lock()
		defer notifiers.Unlock()
		if notifiers.lastBlock != nil {
			ch.In() <- &api.AnnotatedBlock{
				Height: notifiers.lastBlockHeight,
				Block:  notifiers.lastBlock,
			}
		}
	})
	ch := make(chan *api.AnnotatedBlock)
	sub.Unwrap(ch)

	// Make sure that we only ever emit monotonically increasing blocks. Without
	// special handling this can happen for the first received block due to
	// replaying the latest block (see above).
	invalidRound := uint64(math.MaxUint64)
	lastRound := invalidRound
	monotonicCh := make(chan *api.AnnotatedBlock)
	go func() {
		defer close(monotonicCh)

		for {
			blk, ok := <-ch
			if !ok {
				return
			}
			if lastRound != invalidRound && blk.Block.Header.Round <= lastRound {
				continue
			}
			lastRound = blk.Block.Header.Round
			monotonicCh <- blk
		}
	}()

	return monotonicCh, sub, nil
}

func (tb *tendermintBackend) getBlockFromFinalizedTag(ctx context.Context, rawValue []byte, height int64) (*block.Block, *app.ValueFinalized, error) {
	var value app.ValueFinalized
	if err := cbor.Unmarshal(rawValue, &value); err != nil {
		return nil, nil, fmt.Errorf("roothash: corrupt finalized tag: %w", err)
	}

	block, err := tb.getLatestBlockAt(ctx, value.ID, height)
	if err != nil {
		return nil, nil, fmt.Errorf("roothash: failed to fetch block: %w", err)
	}

	if block.Header.Round != value.Round {
		return nil, nil, fmt.Errorf("roothash: tag/query round mismatch (tag: %d, query: %d)", value.Round, block.Header.Round)
	}

	return block, &value, nil
}

func (tb *tendermintBackend) WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription) {
	sub := tb.allBlockNotifier.Subscribe()
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub
}

func (tb *tendermintBackend) WatchEvents(id common.Namespace) (<-chan *api.Event, *pubsub.Subscription, error) {
	notifiers := tb.getRuntimeNotifiers(id)
	sub := notifiers.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (tb *tendermintBackend) TrackRuntime(ctx context.Context, history api.BlockHistory) error {
	select {
	case tb.blockHistoryCh <- history:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func (tb *tendermintBackend) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (tb *tendermintBackend) GetEvents(ctx context.Context, height int64) ([]api.Event, error) {
	// Get block results at given height.
	var results *tmrpctypes.ResultBlockResults
	results, err := tb.service.GetBlockResults(height)
	if err != nil {
		tb.logger.Error("failed to get tendermint block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := tb.service.GetTransactions(ctx, height)
	if err != nil {
		tb.logger.Error("failed to get tendermint transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Decode events from block results.
	tmEvents := tmapi.ConvertBlockEvents(results.BeginBlockEvents, results.EndBlockEvents)
	for txIdx, txResults := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.

		// Generate hash of transaction.
		evHash := hash.NewFromBytes(txns[txIdx])

		// Append hash to each event.
		for _, tmEv := range txResults.Events {
			var ev tmapi.EventWithHash
			ev.Event = tmEv
			ev.TxHash = evHash
			tmEvents = append(tmEvents, ev)
		}
	}
	return tb.onABCIEvents(ctx, tmEvents, height, false, nil)
}

func (tb *tendermintBackend) Cleanup() {
	tb.closeOnce.Do(func() {
		<-tb.closedCh
	})
}

func (tb *tendermintBackend) getRuntimeNotifiers(id common.Namespace) *runtimeBrokers {
	tb.Lock()
	defer tb.Unlock()

	notifiers := tb.runtimeNotifiers[id]
	if notifiers == nil {
		notifiers = &runtimeBrokers{
			blockNotifier: pubsub.NewBroker(false),
			eventNotifier: pubsub.NewBroker(false),
		}
		tb.runtimeNotifiers[id] = notifiers
	}

	return notifiers
}

func (tb *tendermintBackend) reindexBlocks(bh api.BlockHistory) error {
	var err error
	var lastHeight int64
	if lastHeight, err = bh.LastConsensusHeight(); err != nil {
		tb.logger.Error("failed to get last indexed height",
			"err", err,
		)
		return err
	}

	// Scan all blocks between last indexed height and current height. Note that
	// we can safely snapshot the current height as we have already subscribed
	// to new blocks.
	var currentBlk *tmtypes.Block
	if currentBlk, err = tb.service.GetTendermintBlock(tb.ctx, consensus.HeightLatest); err != nil {
		tb.logger.Error("failed to get latest block",
			"err", err,
		)
		return err
	}

	// There may not be a current block yet if we need to initialize from genesis.
	if currentBlk == nil {
		return nil
	}

	tb.logger.Debug("reindexing blocks",
		"last_indexed_height", lastHeight,
		"current_height", currentBlk.Height,
	)

	// TODO: Take prune strategy into account (e.g., skip heights).
	for height := lastHeight + 1; height <= currentBlk.Height; height++ {
		var results *tmrpctypes.ResultBlockResults
		results, err = tb.service.GetBlockResults(height)
		if err != nil {
			tb.logger.Error("failed to get tendermint block",
				"err", err,
				"height", height,
			)
			return err
		}

		// Index block.
		tmEvents := append(results.BeginBlockEvents, results.EndBlockEvents...)
		for _, txResults := range results.TxsResults {
			tmEvents = append(tmEvents, txResults.Events...)
		}
		for _, tmEv := range tmEvents {
			if tmEv.GetType() != app.EventType {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), app.KeyFinalized) {
					var blk *block.Block
					blk, _, err := tb.getBlockFromFinalizedTag(tb.ctx, pair.GetValue(), height)
					if err != nil {
						tb.logger.Error("failed to get block from tag",
							"err", err,
							"height", height,
						)
						continue
					}

					annBlk := &api.AnnotatedBlock{
						Height: height,
						Block:  blk,
					}
					if err = bh.Commit(annBlk); err != nil {
						tb.logger.Error("failed to commit block to block history",
							"err", err,
							"height", height,
							"round", blk.Header.Round,
						)
						return err
					}
				}
			}
		}
	}

	tb.logger.Debug("block reindex complete")

	return nil
}

func (tb *tendermintBackend) worker(ctx context.Context) { // nolint: gocyclo
	defer close(tb.closedCh)

	// Subscribe to transactions which modify state.
	sub, err := tb.service.Subscribe("roothash-worker", app.QueryApp)
	if err != nil {
		tb.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer tb.service.Unsubscribe("roothash-worker", app.QueryApp) // nolint: errcheck

	close(tb.initCh)

	// Initialize block history keepers.
	blockHistory := make(map[common.Namespace]api.BlockHistory)

	// Process transactions and emit notifications for our subscribers.
	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			tb.logger.Debug("terminating, subscription closed")
			return
		case bh := <-tb.blockHistoryCh:
			// We need to start watching a new block history.
			blockHistory[bh.RuntimeID()] = bh
			// Perform reindex if required.
			if err = tb.reindexBlocks(bh); err != nil {
				tb.logger.Error("failed to reindex blocks",
					"err", err,
					"runtime_id", bh.RuntimeID(),
				)

				panic("roothash: failed to reindex blocks")
			}
			continue
		case <-ctx.Done():
			return
		}

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tb.Lock()
			tb.lastBlockHeight = ev.Block.Header.Height
			tb.Unlock()

			tb.onEventDataNewBlock(ctx, ev, blockHistory)
		case tmtypes.EventDataTx:
			tb.onEventDataTx(ctx, ev, blockHistory)
		default:
		}
	}
}

func (tb *tendermintBackend) onEventDataNewBlock(
	ctx context.Context,
	ev tmtypes.EventDataNewBlock,
	blockHistory map[common.Namespace]api.BlockHistory,
) {
	events := tmapi.ConvertBlockEvents(ev.ResultBeginBlock.GetEvents(), ev.ResultEndBlock.GetEvents())

	_, _ = tb.onABCIEvents(ctx, events, ev.Block.Header.Height, true, blockHistory)
}

func (tb *tendermintBackend) onEventDataTx(
	ctx context.Context,
	tx tmtypes.EventDataTx,
	blockHistory map[common.Namespace]api.BlockHistory,
) {
	evHash := hash.NewFromBytes(tx.Tx)

	var events []tmapi.EventWithHash
	for _, tmEv := range tx.Result.Events {
		var ev tmapi.EventWithHash
		ev.Event = tmEv
		ev.TxHash = evHash
		events = append(events, ev)
	}

	_, _ = tb.onABCIEvents(ctx, events, tx.Height, true, blockHistory)
}

func (tb *tendermintBackend) onABCIEvents(
	ctx context.Context,
	tmEvents []tmapi.EventWithHash,
	height int64,
	doBroadcast bool,
	blockHistory map[common.Namespace]api.BlockHistory,
) ([]api.Event, error) {
	var events []api.Event
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the roothash app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		eh := tmEv.TxHash

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case bytes.Equal(key, app.KeyFinalized):
				// A runtime block has been finalized.
				if !doBroadcast {
					// Ignore finalization event when querying events in GetEvents.
					continue
				}

				blk, value, err := tb.getBlockFromFinalizedTag(tb.ctx, val, height)
				if err != nil {
					tb.logger.Error("worker: failed to get block from tag",
						"err", err,
					)
					continue
				}

				notifiers := tb.getRuntimeNotifiers(value.ID)

				// Ensure latest block is set.
				notifiers.Lock()
				notifiers.lastBlock = blk
				notifiers.lastBlockHeight = height
				notifiers.Unlock()

				annBlk := &api.AnnotatedBlock{
					Height: height,
					Block:  blk,
				}

				// Commit the block to history if needed.
				if bh, ok := blockHistory[value.ID]; ok {
					crash.Here(crashPointBlockBeforeIndex)

					err = bh.Commit(annBlk)
					if err != nil {
						tb.logger.Error("failed to commit block to history keeper",
							"err", err,
							"runtime_id", value.ID,
							"height", height,
							"round", blk.Header.Round,
						)
						// Panic as otherwise the history would become out of sync with
						// what was emitted from the roothash backend. The only reason
						// why something like this could happen is a problem with the
						// history database.
						panic("roothash: failed to index block")
					}
				}

				// Broadcast new block.
				tb.allBlockNotifier.Broadcast(blk)
				notifiers.blockNotifier.Broadcast(annBlk)
			case bytes.Equal(key, app.KeyMergeDiscrepancyDetected):
				// A merge discrepancy has been detected.
				var value app.ValueMergeDiscrepancyDetected
				if err := cbor.Unmarshal(val, &value); err != nil {
					tb.logger.Error("failed to unmarshal merge discrepancy from event",
						"err", err,
					)
					continue
				}

				ev := api.Event{Height: height, TxHash: eh, MergeDiscrepancyDetected: &value.Event}

				if doBroadcast {
					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&ev)
				} else {
					events = append(events, ev)
				}
			case bytes.Equal(key, app.KeyExecutionDiscrepancyDetected):
				// An execution discrepancy has been detected.
				var value app.ValueExecutionDiscrepancyDetected
				if err := cbor.Unmarshal(val, &value); err != nil {
					tb.logger.Error("failed to unmarshal execution discrepancy from event",
						"err", err,
					)
					continue
				}

				ev := api.Event{Height: height, TxHash: eh, ExecutionDiscrepancyDetected: &value.Event}

				if doBroadcast {
					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&ev)
				} else {
					events = append(events, ev)
				}
			case bytes.Equal(key, app.KeyExecutorCommitted):
				// An executor commit has been processed.
				var value app.ValueExecutorCommitted
				if err := cbor.Unmarshal(val, &value); err != nil {
					tb.logger.Error("failed to unmarshal executor committed event",
						"err", err,
					)
					continue
				}

				ev := api.Event{Height: height, TxHash: eh, ExecutorCommitted: &value.Event}

				if doBroadcast {
					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&ev)
				} else {
					events = append(events, ev)
				}
			case bytes.Equal(key, app.KeyMergeCommitted):
				// A merge commit has been processed.
				var value app.ValueMergeCommitted
				if err := cbor.Unmarshal(val, &value); err != nil {
					tb.logger.Error("failed to unmarshal executor committed event",
						"err", err,
					)
					continue
				}

				ev := api.Event{Height: height, TxHash: eh, MergeCommitted: &value.Event}

				if doBroadcast {
					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&ev)
				} else {
					events = append(events, ev)
				}
			default:
				tb.logger.Warn("unknown event type",
					"key", key,
					"value", val,
				)
			}
		}
	}
	return events, nil
}

// New constructs a new tendermint-based root hash backend.
func New(
	ctx context.Context,
	dataDir string,
	service service.TendermintService,
) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New()
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		ctx:              ctx,
		logger:           logging.GetLogger("roothash/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		allBlockNotifier: pubsub.NewBroker(false),
		runtimeNotifiers: make(map[common.Namespace]*runtimeBrokers),
		genesisBlocks:    make(map[common.Namespace]*block.Block),
		closedCh:         make(chan struct{}),
		initCh:           make(chan struct{}),
		blockHistoryCh:   make(chan api.BlockHistory, runtimeRegistry.MaxRuntimeCount),
	}

	go tb.worker(ctx)

	return tb, nil
}

func init() {
	crash.RegisterCrashPoints(
		crashPointBlockBeforeIndex,
	)
}
