// Package roothash implements the tendermint backed roothash backend.
package roothash

import (
	"bytes"
	"context"
	"sync"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	"github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	app "github.com/oasislabs/oasis-core/go/consensus/tendermint/apps/roothash"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/service"
	"github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	runtimeRegistry "github.com/oasislabs/oasis-core/go/runtime/registry"
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
	runtimeNotifiers map[signature.PublicKey]*runtimeBrokers
	genesisBlocks    map[signature.PublicKey]*block.Block

	closeOnce      sync.Once
	closedCh       chan struct{}
	initCh         chan struct{}
	blockHistoryCh chan api.BlockHistory
}

func (tb *tendermintBackend) GetGenesisBlock(ctx context.Context, id signature.PublicKey, height int64) (*block.Block, error) {
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

func (tb *tendermintBackend) GetLatestBlock(ctx context.Context, id signature.PublicKey, height int64) (*block.Block, error) {
	return tb.getLatestBlockAt(ctx, id, height)
}

func (tb *tendermintBackend) getLatestBlockAt(ctx context.Context, id signature.PublicKey, height int64) (*block.Block, error) {
	q, err := tb.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LatestBlock(ctx, id)
}

func (tb *tendermintBackend) WatchBlocks(id signature.PublicKey) (<-chan *api.AnnotatedBlock, *pubsub.Subscription, error) {
	notifiers := tb.getRuntimeNotifiers(id)

	sub := notifiers.blockNotifier.SubscribeEx(func(ch *channels.InfiniteChannel) {
		// Replay the latest block if it exists.  This isn't handled by
		// the Broker because the same notifier is used to handle
		// WatchBlocksSince.
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

	return ch, sub, nil
}

func (tb *tendermintBackend) getBlockFromFinalizedTag(ctx context.Context, rawValue []byte, height int64) (*block.Block, *app.ValueFinalized, error) {
	var value app.ValueFinalized
	if err := cbor.Unmarshal(rawValue, &value); err != nil {
		return nil, nil, errors.Wrap(err, "roothash: corrupt finalized tag")
	}

	block, err := tb.getLatestBlockAt(ctx, value.ID, height)
	if err != nil {
		return nil, nil, errors.Wrap(err, "roothash: failed to fetch block")
	}

	if block.Header.Round != value.Round {
		return nil, nil, errors.Errorf("roothash: tag/query round mismatch (tag: %d, query: %d)", value.Round, block.Header.Round)
	}

	return block, &value, nil
}

func (tb *tendermintBackend) WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription) {
	sub := tb.allBlockNotifier.Subscribe()
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub
}

func (tb *tendermintBackend) WatchEvents(id signature.PublicKey) (<-chan *api.Event, *pubsub.Subscription, error) {
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

func (tb *tendermintBackend) Cleanup() {
	tb.closeOnce.Do(func() {
		<-tb.closedCh
	})
}

func (tb *tendermintBackend) getRuntimeNotifiers(id signature.PublicKey) *runtimeBrokers {
	tb.Lock()
	defer tb.Unlock()

	notifiers := tb.runtimeNotifiers[id]
	if notifiers == nil {
		// Fetch the latest block.
		block, _ := tb.GetLatestBlock(tb.ctx, id, consensus.HeightLatest)

		notifiers = &runtimeBrokers{
			blockNotifier: pubsub.NewBroker(false),
			eventNotifier: pubsub.NewBroker(false),
			lastBlock:     block,
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
	if currentBlk, err = tb.service.GetBlock(nil); err != nil {
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
		results, err = tb.service.GetBlockResults(&height)
		if err != nil {
			tb.logger.Error("failed to get tendermint block",
				"err", err,
				"height", height,
			)
			return err
		}

		// Index block.
		tmEvents := append(results.Results.BeginBlock.GetEvents(), results.Results.EndBlock.GetEvents()...)
		for _, txResults := range results.Results.DeliverTx {
			tmEvents = append(tmEvents, txResults.GetEvents()...)
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
	blockHistory := make(map[signature.PublicKey]api.BlockHistory)

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

		// Extract relevant events.
		var height int64
		var tmEvents []types.Event
		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			height = ev.Block.Header.Height
			tmEvents = append([]types.Event{}, ev.ResultBeginBlock.GetEvents()...)
			tmEvents = append(tmEvents, ev.ResultEndBlock.GetEvents()...)
		case tmtypes.EventDataTx:
			height = ev.Height
			tmEvents = ev.Result.GetEvents()
		default:
			continue
		}

		tb.Lock()
		tb.lastBlockHeight = height
		tb.Unlock()

		for _, tmEv := range tmEvents {
			if tmEv.GetType() != app.EventType {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), app.KeyFinalized) {
					blk, value, err := tb.getBlockFromFinalizedTag(tb.ctx, pair.GetValue(), height)
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
				} else if bytes.Equal(pair.GetKey(), app.KeyMergeDiscrepancyDetected) {
					var value app.ValueMergeDiscrepancyDetected
					if err := cbor.Unmarshal(pair.GetValue(), &value); err != nil {
						tb.logger.Error("worker: failed to get discrepancy from tag",
							"err", err,
						)
						continue
					}

					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&api.Event{MergeDiscrepancyDetected: &value.Event})
				} else if bytes.Equal(pair.GetKey(), app.KeyComputeDiscrepancyDetected) {
					var value app.ValueComputeDiscrepancyDetected
					if err := cbor.Unmarshal(pair.GetValue(), &value); err != nil {
						tb.logger.Error("worker: failed to get discrepancy from tag",
							"err", err,
						)
						continue
					}

					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&api.Event{ComputeDiscrepancyDetected: &value.Event})
				}
			}
		}
	}
}

// New constructs a new tendermint-based root hash backend.
func New(
	ctx context.Context,
	dataDir string,
	beac beacon.Backend,
	service service.TendermintService,
) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New(beac)
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		ctx:              ctx,
		logger:           logging.GetLogger("roothash/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		allBlockNotifier: pubsub.NewBroker(false),
		runtimeNotifiers: make(map[signature.PublicKey]*runtimeBrokers),
		genesisBlocks:    make(map[signature.PublicKey]*block.Block),
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
