// Package tendermint implements the tendermint backed roothash backend.
package tendermint

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasislabs/oasis-core/go/beacon/api"
	"github.com/oasislabs/oasis-core/go/common/crash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	"github.com/oasislabs/oasis-core/go/roothash/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	"github.com/oasislabs/oasis-core/go/roothash/api/commitment"
	tmapi "github.com/oasislabs/oasis-core/go/tendermint/api"
	app "github.com/oasislabs/oasis-core/go/tendermint/apps/roothash"
	"github.com/oasislabs/oasis-core/go/tendermint/service"
)

const (
	// BackendName is the name of this implementation.
	BackendName = tmapi.BackendName

	crashPointBlockBeforeIndex = "roothash.before_index"

	// CfgIndexBlocks enables the block indexer.
	CfgIndexBlocks = "roothash.tendermint.index_blocks"
)

var (
	_ api.Backend = (*tendermintBackend)(nil)

	// Flags has the configuration flags.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)
)

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
	pruneNotifier    *pubsub.Broker
	runtimeNotifiers map[signature.MapKey]*runtimeBrokers
	genesisBlocks    map[signature.MapKey]*block.Block
	blockIndex       *blockIndexer

	closeOnce sync.Once
	closedCh  chan struct{}
	initCh    chan struct{}

	roundTimeout time.Duration
}

func (tb *tendermintBackend) Info() api.Info {
	return api.Info{
		ComputeRoundTimeout: tb.roundTimeout,
		MergeRoundTimeout:   tb.roundTimeout,
	}
}

func (tb *tendermintBackend) GetGenesisBlock(ctx context.Context, id signature.PublicKey, height int64) (*block.Block, error) {
	// First check if we have the genesis blocks cached. They are immutable so easy
	// to cache to avoid repeated requests to the Tendermint app.
	tb.RLock()
	if blk := tb.genesisBlocks[id.ToMapKey()]; blk != nil {
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
	tb.genesisBlocks[id.ToMapKey()] = blk
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

func (tb *tendermintBackend) GetBlock(ctx context.Context, id signature.PublicKey, round uint64) (*block.Block, error) {
	if tb.blockIndex == nil {
		return nil, errors.New("roothash: block indexer not enabled for tendermint backend")
	}

	// Make sure we are initialized before querying the index.
	select {
	case <-tb.initCh:
	case <-tb.ctx.Done():
		return nil, tb.ctx.Err()
	}

	height, err := tb.blockIndex.GetBlockHeight(id, round)
	if err != nil {
		return nil, err
	}

	return tb.getLatestBlockAt(ctx, id, height)
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
	if err := value.UnmarshalCBOR(rawValue); err != nil {
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

func (tb *tendermintBackend) WatchPrunedBlocks() (<-chan *api.PrunedBlock, *pubsub.Subscription, error) {
	sub := tb.pruneNotifier.Subscribe()
	ch := make(chan *api.PrunedBlock)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (tb *tendermintBackend) MergeCommit(ctx context.Context, id signature.PublicKey, commits []commitment.MergeCommitment) error {
	tx := app.Tx{
		TxMergeCommit: &app.TxMergeCommit{
			ID:      id,
			Commits: commits,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "roothash: merge commit failed")
	}

	return nil
}

func (tb *tendermintBackend) ComputeCommit(ctx context.Context, id signature.PublicKey, commits []commitment.ComputeCommitment) error {
	tx := app.Tx{
		TxComputeCommit: &app.TxComputeCommit{
			ID:      id,
			Commits: commits,
		},
	}

	if err := tb.service.BroadcastTx(ctx, app.TransactionTag, tx, true); err != nil {
		return errors.Wrap(err, "roothash: compute commit failed")
	}

	return nil
}

func (tb *tendermintBackend) ToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
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
	k := id.ToMapKey()

	tb.Lock()
	defer tb.Unlock()

	notifiers := tb.runtimeNotifiers[k]
	if notifiers == nil {
		// Fetch the latest block.
		block, _ := tb.GetLatestBlock(tb.ctx, id, 0)

		notifiers = &runtimeBrokers{
			blockNotifier: pubsub.NewBroker(false),
			eventNotifier: pubsub.NewBroker(false),
			lastBlock:     block,
		}

		tb.runtimeNotifiers[k] = notifiers
	}

	return notifiers
}

func (tb *tendermintBackend) reindexBlocks() error {
	if tb.blockIndex == nil {
		return nil
	}

	var err error
	var lastHeight int64
	if lastHeight, err = tb.blockIndex.GetLastHeight(); err != nil {
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

	// TODO: Take pruning policy into account (e.g., skip heights).
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
						)
						continue
					}

					err = tb.blockIndex.Index(blk, height)
					if err != nil {
						tb.logger.Error("worker: failed to index block",
							"err", err,
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

	// Subscribe to prune events if a block indexer is configured.
	var pruneCh <-chan int64
	if tb.blockIndex != nil {
		var pruneSub *pubsub.Subscription
		pruneCh, pruneSub, err = tb.service.Pruner().Subscribe()
		if err != nil {
			tb.logger.Error("failed to subscribe to prune events",
				"err", err,
			)
			return
		}
		if pruneSub != nil {
			defer pruneSub.Close()
		}

		// Check if we need to resync any missed blocks.
		if err = tb.reindexBlocks(); err != nil {
			tb.logger.Error("failed to reindex blocks",
				"err", err,
			)
			return
		}
	}

	close(tb.initCh)

	// Process transactions and emit notifications for our subscribers.
	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			tb.logger.Debug("worker: terminating, subsription closed")
			return
		case height := <-pruneCh:
			if tb.blockIndex != nil {
				var blocks []*api.PrunedBlock
				blocks, err = tb.blockIndex.Prune(height)
				if err != nil {
					tb.logger.Error("worker: failed to prune block index",
						"err", err,
					)
				}

				for _, p := range blocks {
					tb.pruneNotifier.Broadcast(p)
				}
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
			tmEvents = append(ev.ResultBeginBlock.GetEvents(), ev.ResultEndBlock.GetEvents()...)
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
					block, value, err := tb.getBlockFromFinalizedTag(tb.ctx, pair.GetValue(), height)
					if err != nil {
						tb.logger.Error("worker: failed to get block from tag",
							"err", err,
						)
						continue
					}

					notifiers := tb.getRuntimeNotifiers(value.ID)

					// Ensure latest block is set.
					notifiers.Lock()
					notifiers.lastBlock = block
					notifiers.lastBlockHeight = height
					notifiers.Unlock()

					// Index the block when an indexer is configured.
					if tb.blockIndex != nil {
						crash.Here(crashPointBlockBeforeIndex)

						err = tb.blockIndex.Index(block, height)
						if err != nil {
							tb.logger.Error("worker: failed to index block",
								"err", err,
								"height", height,
							)
							// Panic as otherwise the index would become out of sync with
							// what was emitted from the roothash backend. The only reason
							// why something like this could happen is a problem with the
							// index database.
							panic("roothash: failed to index block")
						}
					}

					// Broadcast new block.
					tb.allBlockNotifier.Broadcast(block)
					notifiers.blockNotifier.Broadcast(&api.AnnotatedBlock{
						Height: height,
						Block:  block,
					})
				} else if bytes.Equal(pair.GetKey(), app.KeyMergeDiscrepancyDetected) {
					var value app.ValueMergeDiscrepancyDetected
					if err := value.UnmarshalCBOR(pair.GetValue()); err != nil {
						tb.logger.Error("worker: failed to get discrepancy from tag",
							"err", err,
						)
						continue
					}

					notifiers := tb.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&api.Event{MergeDiscrepancyDetected: &value.Event})
				} else if bytes.Equal(pair.GetKey(), app.KeyComputeDiscrepancyDetected) {
					var value app.ValueComputeDiscrepancyDetected
					if err := value.UnmarshalCBOR(pair.GetValue()); err != nil {
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
	timeSource epochtime.Backend,
	beac beacon.Backend,
	service service.TendermintService,
	roundTimeout time.Duration,
) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	a := app.New(timeSource, beac, roundTimeout)
	if err := service.RegisterApplication(a); err != nil {
		return nil, err
	}

	tb := &tendermintBackend{
		ctx:              ctx,
		logger:           logging.GetLogger("roothash/tendermint"),
		service:          service,
		querier:          a.QueryFactory().(*app.QueryFactory),
		allBlockNotifier: pubsub.NewBroker(false),
		pruneNotifier:    pubsub.NewBroker(false),
		runtimeNotifiers: make(map[signature.MapKey]*runtimeBrokers),
		genesisBlocks:    make(map[signature.MapKey]*block.Block),
		closedCh:         make(chan struct{}),
		initCh:           make(chan struct{}),
		roundTimeout:     roundTimeout,
	}

	// Check if we need to index roothash blocks.
	if viper.GetBool(CfgIndexBlocks) {
		var err error
		tb.blockIndex, err = newBlockIndex(dataDir)
		if err != nil {
			return nil, err
		}
	}

	go tb.worker(ctx)

	return tb, nil
}

func init() {
	Flags.Bool(CfgIndexBlocks, false, "Should the roothash blocks be indexed")

	_ = viper.BindPFlags(Flags)

	crash.RegisterCrashPoints(
		crashPointBlockBeforeIndex,
	)
}
