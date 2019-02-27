// Package tendermint implements the tendermint backed roothash backend.
package tendermint

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmcmn "github.com/tendermint/tendermint/libs/common"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common/cache/lru"
	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	tmroothash "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "tendermint"

	roundHeightMapCacheSize = 10000
)

var (
	_ api.Backend      = (*tendermintBackend)(nil)
	_ api.BlockBackend = (*tendermintBackend)(nil)
)

type runtimeBrokers struct {
	sync.Mutex

	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker

	lastBlockHeight int64
	lastBlock       *block.Block

	roundHeightMapCache *lru.Cache
}

type tendermintBackend struct {
	sync.Mutex

	ctx    context.Context
	logger *logging.Logger

	service         service.TendermintService
	lastBlockHeight int64

	allBlockNotifier *pubsub.Broker
	runtimeNotifiers map[signature.MapKey]*runtimeBrokers

	closeOnce sync.Once
	closedCh  chan struct{}
}

func (r *tendermintBackend) GetLatestBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	return r.getLatestBlockAt(id, 0)
}

func (r *tendermintBackend) getLatestBlockAt(id signature.PublicKey, height int64) (*block.Block, error) {
	query := tmapi.QueryGetLatestBlock{
		ID: id,
	}

	response, err := r.service.Query(tmapi.QueryRootHashGetLatestBlock, query, height)
	if err != nil {
		return nil, errors.Wrapf(err, "roothash: get block query failed (height: %d)", height)
	}

	var block block.Block
	if err := cbor.Unmarshal(response, &block); err != nil {
		return nil, errors.Wrapf(err, "roothash: get block malformed response (height: %d)", height)
	}

	return &block, nil
}

func (r *tendermintBackend) WatchBlocks(id signature.PublicKey) (<-chan *block.Block, *pubsub.Subscription, error) {
	annCh, sub, err := r.WatchAnnotatedBlocks(id)
	if err != nil {
		return nil, nil, err
	}
	ch := api.MapAnnotatedBlockToBlock(annCh)

	return ch, sub, nil
}

func (r *tendermintBackend) WatchBlocksSince(id signature.PublicKey, round block.Round) (<-chan *block.Block, *pubsub.Subscription, error) {
	notifiers := r.getRuntimeNotifiers(id)

	startRound, err := round.ToU64()
	if err != nil {
		return nil, nil, err
	}

	sub := notifiers.blockNotifier.SubscribeEx(func(ch *channels.InfiniteChannel) {
		// NOTE: Due to taking the notifiers lock, block replay blocks any events for
		// this runtime (and others since they share a worker) from being processed.
		notifiers.Lock()
		defer notifiers.Unlock()

		if notifiers.lastBlock != nil {
			lastRound, _ := notifiers.lastBlock.Header.Round.ToU64()

			for round := startRound; round < lastRound; round++ {
				block := r.findBlockForRound(id, round, notifiers)
				if block == nil {
					r.logger.Error("WatchBlocksSince: failed to replay block for round",
						"round", round,
					)
					break
				}

				// NOTE: This doesn't emit the height, but height is always stripped
				//       in this method as there is no WatchAnnotatedBlocksSince.
				ch.In() <- &api.AnnotatedBlock{Block: block}
			}

			ch.In() <- &api.AnnotatedBlock{
				Height: notifiers.lastBlockHeight,
				Block:  notifiers.lastBlock,
			}
		}
	})
	annCh := make(chan *api.AnnotatedBlock)
	sub.Unwrap(annCh)
	ch := api.MapAnnotatedBlockToBlock(annCh)

	return ch, sub, nil
}

func (r *tendermintBackend) WatchAnnotatedBlocks(id signature.PublicKey) (<-chan *api.AnnotatedBlock, *pubsub.Subscription, error) {
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

func (r *tendermintBackend) findBlockForRound(id signature.PublicKey, round uint64, notifiers *runtimeBrokers) *block.Block {
	lastRound, _ := notifiers.lastBlock.Header.Round.ToU64()
	if notifiers.lastBlock == nil || round > lastRound {
		return nil
	} else if round == lastRound {
		return notifiers.lastBlock
	}

	// First we need to map the roothash round number into a Tendermint
	// block. To do this, we first consult the local cache and if the
	// round is not available we do a backwards linear scan.
	cache := notifiers.roundHeightMapCache
	blockHeight, ok := cache.Get(round)
	if ok {
		return r.getBlockFromTmBlock(id, blockHeight.(int64), round, cache)
	}

	// Perform a linear scan to get the block height. This will also
	// populate the cache so we should have all the items available.
	r.Lock()
	currentHeight := r.lastBlockHeight
	r.Unlock()

	for blockHeight := currentHeight; blockHeight > 0; blockHeight-- {
		if block := r.getBlockFromTmBlock(id, blockHeight, round, cache); block != nil {
			return block
		}
	}

	return nil
}

func (r *tendermintBackend) getBlockFromTmBlock(
	id signature.PublicKey,
	height int64,
	round uint64,
	cache *lru.Cache,
) *block.Block {
	// Fetch results for given block to get the tags.
	results, err := r.service.GetBlockResults(height)
	if err != nil {
		r.logger.Error("getBlockFromTmBlock: failed to get block results",
			"block_height", height,
			"err", err,
		)
		return nil
	}

	extractBlock := func(tags []tmcmn.KVPair) *block.Block {
		for _, pair := range tags {
			if bytes.Equal(pair.GetKey(), tmapi.TagRootHashFinalized) {
				block, value, err := r.getBlockFromFinalizedTag(pair.GetValue(), height)
				if err != nil {
					r.logger.Error("getBlockFromTmBlock: failed to get block from tag",
						"err", err,
					)
					continue
				}

				if !id.Equal(value.ID) {
					continue
				}

				_ = cache.Put(value.Round, height)
				if value.Round == round {
					return block
				}
			}
		}

		return nil
	}

	if block := extractBlock(results.Results.BeginBlock.GetTags()); block != nil {
		return block
	}
	for _, tx := range results.Results.DeliverTx {
		if block := extractBlock(tx.GetTags()); block != nil {
			return block
		}
	}
	return extractBlock(results.Results.EndBlock.GetTags())
}

func (r *tendermintBackend) getBlockFromFinalizedTag(rawValue []byte, height int64) (*block.Block, *tmapi.ValueRootHashFinalized, error) {
	var value tmapi.ValueRootHashFinalized
	if err := value.UnmarshalCBOR(rawValue); err != nil {
		return nil, nil, errors.Wrap(err, "roothash: corrupt finalized tag")
	}

	block, err := r.getLatestBlockAt(value.ID, height)
	if err != nil {
		return nil, nil, errors.Wrap(err, "roothash: failed to fetch block")
	}

	if round, _ := block.Header.Round.ToU64(); round != value.Round {
		return nil, nil, errors.Errorf("roothash: tag/query round mismatch (tag: %d, query: %d)", value.Round, round)
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

func (r *tendermintBackend) Commit(ctx context.Context, id signature.PublicKey, commit *api.OpaqueCommitment) error {
	tx := tmapi.TxRootHash{
		TxCommit: &tmapi.TxCommit{
			ID:         id,
			Commitment: *commit,
		},
	}

	if err := r.service.BroadcastTx(tmapi.RootHashTransactionTag, tx); err != nil {
		return errors.Wrap(err, "roothash: commit failed")
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
		var err error
		notifiers.roundHeightMapCache, err = lru.New(
			lru.Capacity(roundHeightMapCacheSize, false),
		)
		if err != nil {
			panic(err)
		}

		r.runtimeNotifiers[k] = notifiers
	}

	return notifiers
}

func (r *tendermintBackend) worker(ctx context.Context) { // nolint: gocyclo
	defer close(r.closedCh)

	// Subscribe to transactions which modify state.
	txChannel := make(chan interface{})

	if err := r.service.Subscribe(r.ctx, "roothash-worker", tmapi.QueryRootHashUpdate, txChannel); err != nil {
		r.logger.Error("failed to subscribe",
			"err", err,
		)
		return
	}
	defer r.service.Unsubscribe(r.ctx, "roothash-worker", tmapi.QueryRootHashUpdate) // nolint: errcheck

	// Process transactions and emit notifications for our subscribers.
	for {
		var event interface{}
		var ok bool

		select {
		case event, ok = <-txChannel:
			if !ok {
				r.logger.Debug("worker: terminating")
				return
			}
		case <-ctx.Done():
			return
		}

		// Extract tags from event.
		var tags []tmcmn.KVPair
		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tags = append(ev.ResultBeginBlock.GetTags(), ev.ResultEndBlock.GetTags()...)

			r.Lock()
			r.lastBlockHeight = ev.Block.Header.Height
			r.Unlock()
		case tmtypes.EventDataTx:
			tags = ev.Result.GetTags()

			r.Lock()
			r.lastBlockHeight = ev.Height
			r.Unlock()
		default:
			continue
		}

		for _, pair := range tags {
			if bytes.Equal(pair.GetKey(), tmapi.TagRootHashFinalized) {
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

				// Insert the round -> block height mapping into the
				// cache.
				_ = notifiers.roundHeightMapCache.Put(value.Round, r.lastBlockHeight)

				// Broadcast new block.
				r.allBlockNotifier.Broadcast(block)
				notifiers.blockNotifier.Broadcast(&api.AnnotatedBlock{
					Height: r.lastBlockHeight,
					Block:  block,
				})
			} else if bytes.Equal(pair.GetKey(), tmapi.TagRootHashDiscrepancyDetected) {
				var value tmapi.ValueRootHashDiscrepancyDetected
				if err := value.UnmarshalCBOR(pair.GetValue()); err != nil {
					r.logger.Error("worker: failed to get discrepancy from tag",
						"err", err,
					)
					continue
				}

				notifiers := r.getRuntimeNotifiers(value.ID)
				notifiers.eventNotifier.Broadcast(&api.Event{DiscrepancyDetected: &value.Event})
			}
		}
	}
}

// New constructs a new tendermint-based root hash backend.
func New(
	ctx context.Context,
	timeSource epochtime.Backend,
	sched scheduler.Backend,
	beac beacon.Backend,
	service service.TendermintService,
	roundTimeout time.Duration,
) (api.Backend, error) {
	// We can only work with a block-based epochtime.
	blockTimeSource, ok := timeSource.(epochtime.BlockBackend)
	if !ok {
		return nil, errors.New("roothash/tendermint: need a block-based epochtime backend")
	}

	// We can only work with a block-based scheduler.
	blockScheduler, ok := sched.(scheduler.BlockBackend)
	if !ok {
		return nil, errors.New("roothash/tendermint: need a block-based scheduler backend")
	}

	// Initialize and register the tendermint service component.
	app := tmroothash.New(ctx, blockTimeSource, blockScheduler, beac, roundTimeout)
	if err := service.RegisterApplication(app); err != nil {
		return nil, err
	}

	r := &tendermintBackend{
		ctx:              ctx,
		logger:           logging.GetLogger("roothash/tendermint"),
		service:          service,
		allBlockNotifier: pubsub.NewBroker(false),
		runtimeNotifiers: make(map[signature.MapKey]*runtimeBrokers),
		closedCh:         make(chan struct{}),
	}

	go r.worker(ctx)

	return r, nil
}
