// Package tendermint implements the tendermint backed roothash backend.
package tendermint

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/tendermint/tendermint/abci/types"
	tmrpctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	// BackendName is the name of this implementation.
	BackendName = tmapi.BackendName

	crashPointBlockBeforeIndex = "roothash.before_index"

	cfgIndexBlocks = "roothash.tendermint.index_blocks"
)

var (
	_ api.Backend = (*tendermintBackend)(nil)
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

func (r *tendermintBackend) Info() api.Info {
	return api.Info{
		ComputeRoundTimeout: r.roundTimeout,
		MergeRoundTimeout:   r.roundTimeout,
	}
}

func (r *tendermintBackend) GetGenesisBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	// First check if we have the genesis blocks cached. They are immutable so easy
	// to cache to avoid repeated requests to the Tendermint app.
	r.RLock()
	if blk := r.genesisBlocks[id.ToMapKey()]; blk != nil {
		r.RUnlock()
		return blk, nil
	}
	r.RUnlock()

	query := tmapi.QueryGetByIDRequest{
		ID: id,
	}

	response, err := r.service.Query(app.QueryGetGenesisBlock, query, 0)
	if err != nil {
		return nil, errors.Wrapf(err, "roothash: get genesis block query failed")
	}

	var blk block.Block
	if err := cbor.Unmarshal(response, &blk); err != nil {
		return nil, errors.Wrapf(err, "roothash: get genesis block malformed response")
	}

	// Update the genesis block cache.
	r.Lock()
	r.genesisBlocks[id.ToMapKey()] = &blk
	r.Unlock()

	return &blk, nil
}

func (r *tendermintBackend) GetLatestBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	return r.getLatestBlockAt(id, 0)
}

func (r *tendermintBackend) getLatestBlockAt(id signature.PublicKey, height int64) (*block.Block, error) {
	query := tmapi.QueryGetByIDRequest{
		ID: id,
	}

	response, err := r.service.Query(app.QueryGetLatestBlock, query, height)
	if err != nil {
		return nil, errors.Wrapf(err, "roothash: get block query failed (height: %d)", height)
	}

	var block block.Block
	if err := cbor.Unmarshal(response, &block); err != nil {
		return nil, errors.Wrapf(err, "roothash: get block malformed response (height: %d)", height)
	}

	return &block, nil
}

func (r *tendermintBackend) GetBlock(ctx context.Context, id signature.PublicKey, round uint64) (*block.Block, error) {
	if r.blockIndex == nil {
		return nil, errors.New("roothash: block indexer not enabled for tendermint backend")
	}

	// Make sure we are initialized before querying the index.
	select {
	case <-r.initCh:
	case <-r.ctx.Done():
		return nil, r.ctx.Err()
	}

	height, err := r.blockIndex.GetBlockHeight(id, round)
	if err != nil {
		return nil, err
	}

	return r.getLatestBlockAt(id, height)
}

func (r *tendermintBackend) WatchBlocks(id signature.PublicKey) (<-chan *api.AnnotatedBlock, *pubsub.Subscription, error) {
	notifiers := r.getRuntimeNotifiers(id)

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

func (r *tendermintBackend) getBlockFromFinalizedTag(rawValue []byte, height int64) (*block.Block, *app.ValueFinalized, error) {
	var value app.ValueFinalized
	if err := value.UnmarshalCBOR(rawValue); err != nil {
		return nil, nil, errors.Wrap(err, "roothash: corrupt finalized tag")
	}

	block, err := r.getLatestBlockAt(value.ID, height)
	if err != nil {
		return nil, nil, errors.Wrap(err, "roothash: failed to fetch block")
	}

	if block.Header.Round != value.Round {
		return nil, nil, errors.Errorf("roothash: tag/query round mismatch (tag: %d, query: %d)", value.Round, block.Header.Round)
	}

	return block, &value, nil
}

func (r *tendermintBackend) WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription) {
	sub := r.allBlockNotifier.Subscribe()
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub
}

func (r *tendermintBackend) WatchEvents(id signature.PublicKey) (<-chan *api.Event, *pubsub.Subscription, error) {
	notifiers := r.getRuntimeNotifiers(id)
	sub := notifiers.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *tendermintBackend) WatchPrunedBlocks() (<-chan *api.PrunedBlock, *pubsub.Subscription, error) {
	sub := r.pruneNotifier.Subscribe()
	ch := make(chan *api.PrunedBlock)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *tendermintBackend) MergeCommit(ctx context.Context, id signature.PublicKey, commits []commitment.MergeCommitment) error {
	tx := app.Tx{
		TxMergeCommit: &app.TxMergeCommit{
			ID:      id,
			Commits: commits,
		},
	}

	if err := r.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "roothash: merge commit failed")
	}

	return nil
}

func (r *tendermintBackend) ComputeCommit(ctx context.Context, id signature.PublicKey, commits []commitment.ComputeCommitment) error {
	tx := app.Tx{
		TxComputeCommit: &app.TxComputeCommit{
			ID:      id,
			Commits: commits,
		},
	}

	if err := r.service.BroadcastTx(app.TransactionTag, tx); err != nil {
		return errors.Wrap(err, "roothash: compute commit failed")
	}

	return nil
}

func (r *tendermintBackend) Cleanup() {
	r.closeOnce.Do(func() {
		<-r.closedCh
	})
}

func (r *tendermintBackend) getRuntimeNotifiers(id signature.PublicKey) *runtimeBrokers {
	k := id.ToMapKey()

	r.Lock()
	defer r.Unlock()

	notifiers := r.runtimeNotifiers[k]
	if notifiers == nil {
		// Fetch the latest block.
		block, _ := r.GetLatestBlock(r.ctx, id)

		notifiers = &runtimeBrokers{
			blockNotifier: pubsub.NewBroker(false),
			eventNotifier: pubsub.NewBroker(false),
			lastBlock:     block,
		}

		r.runtimeNotifiers[k] = notifiers
	}

	return notifiers
}

func (r *tendermintBackend) reindexBlocks() error {
	if r.blockIndex == nil {
		return nil
	}

	var err error
	var lastHeight int64
	if lastHeight, err = r.blockIndex.GetLastHeight(); err != nil {
		r.logger.Error("failed to get last indexed height",
			"err", err,
		)
		return err
	}

	// Scan all blocks between last indexed height and current height. Note that
	// we can safely snapshot the current height as we have already subscribed
	// to new blocks.
	var currentBlk *tmtypes.Block
	if currentBlk, err = r.service.GetBlock(nil); err != nil {
		r.logger.Error("failed to get latest block",
			"err", err,
		)
		return err
	}

	// There may not be a current block yet if we need to initialize from genesis.
	if currentBlk == nil {
		return nil
	}

	r.logger.Debug("reindexing blocks",
		"last_indexed_height", lastHeight,
		"current_height", currentBlk.Height,
	)

	// TODO: Take pruning policy into account (e.g., skip heights).
	for height := lastHeight + 1; height <= currentBlk.Height; height++ {
		var results *tmrpctypes.ResultBlockResults
		results, err = r.service.GetBlockResults(&height)
		if err != nil {
			r.logger.Error("failed to get tendermint block",
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
			if tmEv.GetType() != tmapi.EventTypeEkiden {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), app.TagFinalized) {
					var blk *block.Block
					blk, _, err := r.getBlockFromFinalizedTag(pair.GetValue(), height)
					if err != nil {
						r.logger.Error("failed to get block from tag",
							"err", err,
						)
						continue
					}

					err = r.blockIndex.Index(blk, height)
					if err != nil {
						r.logger.Error("worker: failed to index block",
							"err", err,
						)
						return err
					}
				}
			}
		}
	}

	r.logger.Debug("block reindex complete")

	return nil
}

func (r *tendermintBackend) worker(ctx context.Context) { // nolint: gocyclo
	defer close(r.closedCh)

	// Subscribe to transactions which modify state.
	sub, err := r.service.Subscribe("roothash-worker", app.QueryUpdate)
	if err != nil {
		r.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer r.service.Unsubscribe("roothash-worker", app.QueryUpdate) // nolint: errcheck

	// Subscribe to prune events if a block indexer is configured.
	var pruneCh <-chan int64
	if r.blockIndex != nil {
		var pruneSub *pubsub.Subscription
		pruneCh, pruneSub, err = r.service.Pruner().Subscribe()
		if err != nil {
			r.logger.Error("failed to subscribe to prune events",
				"err", err,
			)
			return
		}
		if pruneSub != nil {
			defer pruneSub.Close()
		}

		// Check if we need to resync any missed blocks.
		if err = r.reindexBlocks(); err != nil {
			r.logger.Error("failed to reindex blocks",
				"err", err,
			)
			return
		}
	}

	close(r.initCh)

	// Process transactions and emit notifications for our subscribers.
	for {
		var event interface{}

		select {
		case msg := <-sub.Out():
			event = msg.Data()
		case <-sub.Cancelled():
			r.logger.Debug("worker: terminating, subsription closed")
			return
		case height := <-pruneCh:
			if r.blockIndex != nil {
				var blocks []*api.PrunedBlock
				blocks, err = r.blockIndex.Prune(height)
				if err != nil {
					r.logger.Error("worker: failed to prune block index",
						"err", err,
					)
				}

				for _, p := range blocks {
					r.pruneNotifier.Broadcast(p)
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

		r.Lock()
		r.lastBlockHeight = height
		r.Unlock()

		for _, tmEv := range tmEvents {
			if tmEv.GetType() != tmapi.EventTypeEkiden {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), app.TagFinalized) {
					block, value, err := r.getBlockFromFinalizedTag(pair.GetValue(), height)
					if err != nil {
						r.logger.Error("worker: failed to get block from tag",
							"err", err,
						)
						continue
					}

					notifiers := r.getRuntimeNotifiers(value.ID)

					// Ensure latest block is set.
					notifiers.Lock()
					notifiers.lastBlock = block
					notifiers.lastBlockHeight = height
					notifiers.Unlock()

					// Index the block when an indexer is configured.
					if r.blockIndex != nil {
						crash.Here(crashPointBlockBeforeIndex)

						err = r.blockIndex.Index(block, height)
						if err != nil {
							r.logger.Error("worker: failed to index block",
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
					r.allBlockNotifier.Broadcast(block)
					notifiers.blockNotifier.Broadcast(&api.AnnotatedBlock{
						Height: height,
						Block:  block,
					})
				} else if bytes.Equal(pair.GetKey(), app.TagMergeDiscrepancyDetected) {
					var value app.ValueMergeDiscrepancyDetected
					if err := value.UnmarshalCBOR(pair.GetValue()); err != nil {
						r.logger.Error("worker: failed to get discrepancy from tag",
							"err", err,
						)
						continue
					}

					notifiers := r.getRuntimeNotifiers(value.ID)
					notifiers.eventNotifier.Broadcast(&api.Event{MergeDiscrepancyDetected: &value.Event})
				} else if bytes.Equal(pair.GetKey(), app.TagComputeDiscrepancyDetected) {
					var value app.ValueComputeDiscrepancyDetected
					if err := value.UnmarshalCBOR(pair.GetValue()); err != nil {
						r.logger.Error("worker: failed to get discrepancy from tag",
							"err", err,
						)
						continue
					}

					notifiers := r.getRuntimeNotifiers(value.ID)
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
	app := app.New(ctx, timeSource, beac, roundTimeout)
	if err := service.RegisterApplication(app); err != nil {
		return nil, err
	}

	r := &tendermintBackend{
		ctx:              ctx,
		logger:           logging.GetLogger("roothash/tendermint"),
		service:          service,
		allBlockNotifier: pubsub.NewBroker(false),
		pruneNotifier:    pubsub.NewBroker(false),
		runtimeNotifiers: make(map[signature.MapKey]*runtimeBrokers),
		genesisBlocks:    make(map[signature.MapKey]*block.Block),
		closedCh:         make(chan struct{}),
		initCh:           make(chan struct{}),
		roundTimeout:     roundTimeout,
	}

	// Check if we need to index roothash blocks.
	if viper.GetBool(cfgIndexBlocks) {
		var err error
		r.blockIndex, err = newBlockIndex(dataDir)
		if err != nil {
			return nil, err
		}
	}

	go r.worker(ctx)

	return r, nil
}

// RegisterFlags registers the configuration flags with the provided
// command.
func RegisterFlags(cmd *cobra.Command) {
	if !cmd.Flags().Parsed() {
		cmd.Flags().Bool(cfgIndexBlocks, false, "Should the roothash blocks be indexed")
	}

	for _, v := range []string{
		cfgIndexBlocks,
	} {
		viper.BindPFlag(v, cmd.Flags().Lookup(v)) // nolint: errcheck
	}
}

func init() {
	crash.RegisterCrashPoints(
		crashPointBlockBeforeIndex,
	)
}
