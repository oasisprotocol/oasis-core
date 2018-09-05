// Package tendermint implements the tendermint backed roothash backend.
package tendermint

import (
	"bytes"
	"sync"

	"github.com/eapache/channels"
	"github.com/pkg/errors"
	tmcmn "github.com/tendermint/tendermint/libs/common"
	tmtypes "github.com/tendermint/tendermint/types"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	tmapi "github.com/oasislabs/ekiden/go/tendermint/api"
	tmroothash "github.com/oasislabs/ekiden/go/tendermint/apps/roothash"
	"github.com/oasislabs/ekiden/go/tendermint/service"
)

// BackendName is the name of this implementation.
const BackendName = "tendermint"

var _ api.Backend = (*tendermintBackend)(nil)

type contractBrokers struct {
	sync.Mutex

	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker

	lastBlock *api.Block
}

type tendermintBackend struct {
	sync.Mutex

	logger *logging.Logger

	service service.TendermintService

	allBlockNotifier  *pubsub.Broker
	contractNotifiers map[signature.MapKey]*contractBrokers
}

func (r *tendermintBackend) GetLatestBlock(ctx context.Context, id signature.PublicKey) (*api.Block, error) {
	query := tmapi.QueryGetLatestBlock{
		ID: id,
	}

	response, err := r.service.Query(tmapi.QueryRootHashGetLatestBlock, query, 0)
	if err != nil {
		return nil, errors.Wrap(err, "roothash: get latest block query failed")
	}

	var block api.Block
	if err := cbor.Unmarshal(response, &block); err != nil {
		return nil, errors.Wrap(err, "roothash: get latest block malformed response")
	}

	return &block, nil
}

func (r *tendermintBackend) WatchBlocks(id signature.PublicKey) (<-chan *api.Block, *pubsub.Subscription, error) {
	notifiers := r.getContractNotifiers(id)

	sub := notifiers.blockNotifier.SubscribeEx(func(ch *channels.InfiniteChannel) {
		// Replay the latest block if it exists.  This isn't handled by
		// the Broker because the same notifier is used to handle
		// WatchBlocksSince.
		notifiers.Lock()
		defer notifiers.Unlock()

		if notifiers.lastBlock != nil {
			ch.In() <- notifiers.lastBlock
		}
	})
	ch := make(chan *api.Block)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *tendermintBackend) WatchBlocksSince(id signature.PublicKey, round api.Round) (<-chan *api.Block, *pubsub.Subscription, error) {
	notifiers := r.getContractNotifiers(id)

	sub := notifiers.blockNotifier.SubscribeEx(func(ch *channels.InfiniteChannel) {
		notifiers.Lock()
		defer notifiers.Unlock()

		if notifiers.lastBlock != nil {
			// TODO: Find blocks (>= round AND < notifiers.lastBlock.Header.Round.ToU64()).

			ch.In() <- notifiers.lastBlock
		}
	})
	ch := make(chan *api.Block)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *tendermintBackend) WatchAllBlocks() (<-chan *api.Block, *pubsub.Subscription) {
	sub := r.allBlockNotifier.Subscribe()
	ch := make(chan *api.Block)
	sub.Unwrap(ch)

	return ch, sub
}

func (r *tendermintBackend) WatchEvents(id signature.PublicKey) (<-chan *api.Event, *pubsub.Subscription, error) {
	notifiers := r.getContractNotifiers(id)
	sub := notifiers.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *tendermintBackend) Commit(ctx context.Context, id signature.PublicKey, commit *api.Commitment) error {
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

func (r *tendermintBackend) getContractNotifiers(id signature.PublicKey) *contractBrokers {
	k := id.ToMapKey()

	r.Lock()
	defer r.Unlock()

	notifiers := r.contractNotifiers[k]
	if notifiers == nil {
		// Fetch the latest block.
		block, _ := r.GetLatestBlock(context.Background(), id)

		notifiers = &contractBrokers{
			blockNotifier: pubsub.NewBroker(false),
			eventNotifier: pubsub.NewBroker(false),
			lastBlock:     block,
		}
		r.contractNotifiers[k] = notifiers
	}

	return notifiers
}

func (r *tendermintBackend) worker() { // nolint: gocyclo
	// Subscribe to transactions which modify state.
	ctx := context.Background()
	txChannel := make(chan interface{})

	if err := r.service.Subscribe(ctx, "roothash-worker", tmapi.QueryRootHashUpdate, txChannel); err != nil {
		panic("worker: failed to subscribe")
	}
	defer r.service.Unsubscribe(ctx, "roothash-worker", tmapi.QueryRootHashUpdate) // nolint: errcheck

	// Process transactions and emit notifications for our subscribers.
PROCESS_LOOP:
	for {
		event, ok := <-txChannel
		if !ok {
			r.logger.Debug("worker: terminating")
			return
		}

		// Extract tags from event.
		var tags []tmcmn.KVPair
		switch ev := event.(type) {
		case tmtypes.EventDataNewBlock:
			tags = append(ev.ResultBeginBlock.GetTags(), ev.ResultEndBlock.GetTags()...)
		case tmtypes.EventDataTx:
			tags = ev.Result.GetTags()
		default:
			continue
		}

		var id signature.PublicKey
		rawID := tmapi.GetTag(tags, tmapi.TagRootHashID)
		if rawID == nil {
			r.logger.Error("worker: missing identifier tag in roothash transaction")
			continue
		}
		if err := id.UnmarshalBinary(rawID); err != nil {
			r.logger.Error("worker: corrupted identifier tag",
				"err", err,
			)
			continue
		}

		notifiers := r.getContractNotifiers(id)

		for _, pair := range tags {
			if bytes.Equal(pair.GetKey(), tmapi.TagRootHashFinalized) {
				// Block finalized.
				var block api.Block
				if err := block.UnmarshalCBOR(pair.GetValue()); err != nil {
					r.logger.Error("worker: corrupted block tag",
						"contract", id,
						"err", err,
					)
					continue PROCESS_LOOP
				}

				// Ensure latest block is set.
				notifiers.Lock()
				if notifiers.lastBlock == nil {
					notifiers.lastBlock = &block
				}
				notifiers.Unlock()

				// Broadcast new block.
				r.allBlockNotifier.Broadcast(&block)
				notifiers.blockNotifier.Broadcast(&block)
			} else if bytes.Equal(pair.GetKey(), tmapi.TagRootHashDiscrepancyDetected) {
				// Discrepancy detected.
				var batchID hash.Hash
				if err := batchID.UnmarshalBinary(pair.GetValue()); err != nil {
					r.logger.Error("worker: corrupted discrepancy detected tag",
						"contract", id,
						"err", err,
					)
					continue PROCESS_LOOP
				}

				notifiers.eventNotifier.Broadcast(&api.Event{DiscrepancyDetected: &batchID})
			} else if bytes.Equal(pair.GetKey(), tmapi.TagRootHashRoundFailed) {
				// Round failed.
				notifiers.eventNotifier.Broadcast(&api.Event{RoundFailed: errors.New(string(pair.GetValue()))})
			}
		}
	}
}

// New constructs a new tendermint-based root hash backend.
func New(
	timeSource epochtime.Backend,
	sched scheduler.Backend,
	storage storage.Backend,
	service service.TendermintService,
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

	// Initialze and register the tendermint service component.
	app := tmroothash.New(blockTimeSource, blockScheduler, storage)
	if err := service.RegisterApplication(app); err != nil {
		return nil, err
	}

	r := &tendermintBackend{
		logger:            logging.GetLogger("roothash/tendermint"),
		service:           service,
		allBlockNotifier:  pubsub.NewBroker(false),
		contractNotifiers: make(map[signature.MapKey]*contractBrokers),
	}

	go r.worker()

	return r, nil
}
