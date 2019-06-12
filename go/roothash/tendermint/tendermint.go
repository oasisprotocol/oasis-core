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
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	app "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "tendermint"

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
	sync.Mutex

	ctx    context.Context
	logger *logging.Logger

	service         service.TendermintService
	lastBlockHeight int64

	allBlockNotifier *pubsub.Broker
	pruneNotifier    *pubsub.Broker
	runtimeNotifiers map[signature.MapKey]*runtimeBrokers
	blockIndex       *blockIndexer

	closeOnce sync.Once
	closedCh  chan struct{}

	roundTimeout time.Duration
}

func (r *tendermintBackend) Info() api.Info {
	return api.Info{
		ComputeRoundTimeout: r.roundTimeout,
		MergeRoundTimeout:   r.roundTimeout,
	}
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

	height, err := r.blockIndex.GetBlockHeight(id, round)
	if err != nil {
		// TODO: Support on-demand reindexing based on neighbouring blocks in
		//       case blocks are not found.
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
	}

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
		var tmEvents []types.Event

		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tmEvents = append(ev.ResultBeginBlock.GetEvents(), ev.ResultEndBlock.GetEvents()...)

			r.Lock()
			r.lastBlockHeight = ev.Block.Header.Height
			r.Unlock()
		case tmtypes.EventDataTx:
			tmEvents = ev.Result.GetEvents()

			r.Lock()
			r.lastBlockHeight = ev.Height
			r.Unlock()
		default:
			continue
		}

		for _, tmEv := range tmEvents {
			if tmEv.GetType() != tmapi.EventTypeEkiden {
				continue
			}

			for _, pair := range tmEv.GetAttributes() {
				if bytes.Equal(pair.GetKey(), app.TagFinalized) {
					block, value, err := r.getBlockFromFinalizedTag(pair.GetValue(), r.lastBlockHeight)
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
					notifiers.lastBlockHeight = r.lastBlockHeight
					notifiers.Unlock()

					// Index the block when an indexer is configured.
					if r.blockIndex != nil {
						err = r.blockIndex.Index(block, r.lastBlockHeight)
						if err != nil {
							r.logger.Error("worker: failed to index block",
								"err", err,
							)
							// TODO: Support on-demand reindexing.
						}
					}

					// Broadcast new block.
					r.allBlockNotifier.Broadcast(block)
					notifiers.blockNotifier.Broadcast(&api.AnnotatedBlock{
						Height: r.lastBlockHeight,
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
	sched scheduler.Backend,
	beac beacon.Backend,
	service service.TendermintService,
	roundTimeout time.Duration,
) (api.Backend, error) {
	// Initialize and register the tendermint service component.
	app := app.New(ctx, timeSource, sched, beac, roundTimeout)
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
		closedCh:         make(chan struct{}),
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
