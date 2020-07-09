// Package roothash implements the tendermint backed roothash backend.
package roothash

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"sync"

	"github.com/eapache/channels"
	"github.com/hashicorp/go-multierror"
	tmabcitypes "github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
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

func (tb *tendermintBackend) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
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

	var events []*api.Event
	// Decode events from block results.
	blockEvs, err := EventsFromTendermint(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	blockEvs, err = EventsFromTendermint(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		evs, txErr := EventsFromTendermint(txns[txIdx], results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, evs...)
	}

	return events, nil
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
					var value app.ValueFinalized
					if err := cbor.Unmarshal(pair.GetValue(), &value); err != nil {
						tb.logger.Error("failed to unamrshal finalized event",
							"err", err,
							"height", height,
						)
						continue
					}

					blk, err := tb.getLatestBlockAt(tb.ctx, value.ID, height)
					if err != nil {
						tb.logger.Error("failed to fetch latest block",
							"err", err,
							"height", height,
							"runtime_id", value.ID,
						)
						continue
					}
					if blk.Header.Round != value.Round {
						tb.logger.Error("worker: finalized event/query round mismatch",
							"block", blk,
							"event", value,
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
	tmEvents := append([]tmabcitypes.Event{}, ev.ResultBeginBlock.GetEvents()...)
	tmEvents = append(tmEvents, ev.ResultEndBlock.GetEvents()...)
	events, err := EventsFromTendermint(nil, ev.Block.Header.Height, tmEvents)
	if err != nil {
		tb.logger.Error("error processing tendermint roothash events", "err", err)
	}
	tb.processEvents(ctx, events, blockHistory)
}

func (tb *tendermintBackend) onEventDataTx(
	ctx context.Context,
	ev tmtypes.EventDataTx,
	blockHistory map[common.Namespace]api.BlockHistory,
) {
	events, err := EventsFromTendermint(ev.Tx, ev.Height, ev.Result.Events)
	if err != nil {
		tb.logger.Error("error processing tendermint roothash events", "err", err)
	}
	tb.processEvents(ctx, events, blockHistory)
}

func (tb *tendermintBackend) processEvents(ctx context.Context, events []*api.Event, blockHistory map[common.Namespace]api.BlockHistory) {
	for _, ev := range events {
		// Notify non-finalized events.
		if ev.FinalizedEvent == nil {
			notifiers := tb.getRuntimeNotifiers(ev.RuntimeID)
			notifiers.eventNotifier.Broadcast(ev)
			continue
		}

		// Process finalized event.
		blk, err := tb.getLatestBlockAt(ctx, ev.RuntimeID, ev.Height)
		if err != nil {
			tb.logger.Error("worker: failed to fetch latest block",
				"err", err,
				"height", ev.Height,
				"runtime_id", ev.RuntimeID,
			)
			continue
		}
		if blk.Header.Round != ev.FinalizedEvent.Round {
			tb.logger.Error("worker: finalized event/query round mismatch",
				"block", blk,
				"event", ev,
			)
			continue
		}

		notifiers := tb.getRuntimeNotifiers(ev.RuntimeID)
		// Ensure latest block is set.
		notifiers.Lock()
		notifiers.lastBlock = blk
		notifiers.lastBlockHeight = ev.Height
		notifiers.Unlock()

		annBlk := &api.AnnotatedBlock{
			Height: ev.Height,
			Block:  blk,
		}
		// Commit the block to history if needed.
		if bh, ok := blockHistory[ev.RuntimeID]; ok {
			crash.Here(crashPointBlockBeforeIndex)

			err = bh.Commit(annBlk)
			if err != nil {
				tb.logger.Error("failed to commit block to history keeper",
					"err", err,
					"runtime_id", ev.RuntimeID,
					"height", ev.Height,
					"round", blk.Header.Round,
				)
				// Panic as otherwise the history would become out of sync with
				// what was emitted from the roothash backend. The only reason
				// why something like this could happen is a problem with the
				// history database.
				panic("roothash: failed to index block")
			}
		}
		tb.allBlockNotifier.Broadcast(blk)
		notifiers.blockNotifier.Broadcast(annBlk)
	}
}

// EventsFromTendermint extracts staking events from tendermint events.
func EventsFromTendermint(
	tx tmtypes.Tx,
	height int64,
	tmEvents []tmabcitypes.Event,
) ([]*api.Event, error) {
	var txHash hash.Hash
	switch tx {
	case nil:
		txHash.Empty()
	default:
		txHash = hash.NewFromBytes(tx)
	}

	var events []*api.Event
	var errs error
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the roothash app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case bytes.Equal(key, app.KeyFinalized):
				// Finalized event.
				var value app.ValueFinalized
				if err := cbor.Unmarshal(val, &value); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("roothash: corrupt Finalized event: %w", err))
					continue
				}

				ev := &api.Event{RuntimeID: value.ID, Height: height, TxHash: txHash, FinalizedEvent: &api.FinalizedEvent{Round: value.Round}}
				events = append(events, ev)
			case bytes.Equal(key, app.KeyMergeDiscrepancyDetected):
				// A merge discrepancy has been detected.
				var value app.ValueMergeDiscrepancyDetected
				if err := cbor.Unmarshal(val, &value); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("roothash: corrupt MergeDiscrepancy event: %w", err))
					continue
				}

				ev := &api.Event{RuntimeID: value.ID, Height: height, TxHash: txHash, MergeDiscrepancyDetected: &value.Event}
				events = append(events, ev)
			case bytes.Equal(key, app.KeyExecutionDiscrepancyDetected):
				// An execution discrepancy has been detected.
				var value app.ValueExecutionDiscrepancyDetected
				if err := cbor.Unmarshal(val, &value); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("roothash: corrupt ValueExectutionDiscrepancy event: %w", err))
					continue
				}

				ev := &api.Event{RuntimeID: value.ID, Height: height, TxHash: txHash, ExecutionDiscrepancyDetected: &value.Event}
				events = append(events, ev)
			case bytes.Equal(key, app.KeyExecutorCommitted):
				// An executor commit has been processed.
				var value app.ValueExecutorCommitted
				if err := cbor.Unmarshal(val, &value); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("roothash: corrupt ValueExecutorCommitted event: %w", err))
					continue
				}

				ev := &api.Event{RuntimeID: value.ID, Height: height, TxHash: txHash, ExecutorCommitted: &value.Event}
				events = append(events, ev)
			case bytes.Equal(key, app.KeyMergeCommitted):
				// A merge commit has been processed.
				var value app.ValueMergeCommitted
				if err := cbor.Unmarshal(val, &value); err != nil {
					errs = multierror.Append(errs, fmt.Errorf("roothash: corrupt ValueMergeCommitted event: %w", err))
					continue
				}

				ev := &api.Event{RuntimeID: value.ID, Height: height, TxHash: txHash, MergeCommitted: &value.Event}
				events = append(events, ev)
			case bytes.Equal(key, app.KeyRuntimeID):
				// Runtime ID attribute.
				// Not used currently.
			default:
				errs = multierror.Append(errs, fmt.Errorf("roothash: unknown event type: key: %s, val: %s", key, val))
			}
		}
	}
	return events, errs
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
