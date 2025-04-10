// Package roothash implements the CometBFT backed roothash backend.
package roothash

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtrpctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

const crashPointBlockBeforeIndex = "roothash.before_index"

type runtimeBrokers struct {
	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker
	ecNotifier    *pubsub.Broker
}

type trackedRuntime struct {
	runtimeID common.Namespace
	height    int64
	round     uint64
}

// ServiceClient is the roothash service client.
type ServiceClient struct {
	tmapi.BaseServiceClient

	mu sync.RWMutex

	ctx    context.Context
	logger *logging.Logger

	backend tmapi.Backend
	querier *app.QueryFactory

	allBlockNotifier *pubsub.Broker
	runtimeNotifiers map[common.Namespace]*runtimeBrokers
	genesisBlocks    map[common.Namespace]*block.Block

	queryCh         chan cmtpubsub.Query
	trackedRuntimes map[common.Namespace]*trackedRuntime
}

// GetGenesisBlock implements api.Backend.
func (sc *ServiceClient) GetGenesisBlock(ctx context.Context, request *api.RuntimeRequest) (*block.Block, error) {
	// First check if we have the genesis blocks cached. They are immutable so easy
	// to cache to avoid repeated requests to the CometBFT app.
	sc.mu.RLock()
	if blk := sc.genesisBlocks[request.RuntimeID]; blk != nil {
		sc.mu.RUnlock()
		return blk, nil
	}
	sc.mu.RUnlock()

	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	blk, err := q.GenesisBlock(ctx, request.RuntimeID)
	if err != nil {
		return nil, err
	}

	// Update the genesis block cache.
	sc.mu.Lock()
	sc.genesisBlocks[request.RuntimeID] = blk
	sc.mu.Unlock()

	return blk, nil
}

// GetLatestBlock implements api.Backend.
func (sc *ServiceClient) GetLatestBlock(ctx context.Context, request *api.RuntimeRequest) (*block.Block, error) {
	return sc.getLatestBlockAt(ctx, request.RuntimeID, request.Height)
}

func (sc *ServiceClient) getLatestBlockAt(ctx context.Context, runtimeID common.Namespace, height int64) (*block.Block, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LatestBlock(ctx, runtimeID)
}

// GetRuntimeState implements api.Backend.
func (sc *ServiceClient) GetRuntimeState(ctx context.Context, request *api.RuntimeRequest) (*api.RuntimeState, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.RuntimeState(ctx, request.RuntimeID)
}

// GetLastRoundResults implements api.Backend.
func (sc *ServiceClient) GetLastRoundResults(ctx context.Context, request *api.RuntimeRequest) (*api.RoundResults, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.LastRoundResults(ctx, request.RuntimeID)
}

func (sc *ServiceClient) GetRoundRoots(ctx context.Context, request *api.RoundRootsRequest) (*api.RoundRoots, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.RoundRoots(ctx, request.RuntimeID, request.Round)
}

func (sc *ServiceClient) GetPastRoundRoots(ctx context.Context, request *api.RuntimeRequest) (map[uint64]api.RoundRoots, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.PastRoundRoots(ctx, request.RuntimeID)
}

// GetIncomingMessageQueueMeta implements api.Backend.
func (sc *ServiceClient) GetIncomingMessageQueueMeta(ctx context.Context, request *api.RuntimeRequest) (*message.IncomingMessageQueueMeta, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.IncomingMessageQueueMeta(ctx, request.RuntimeID)
}

// GetIncomingMessageQueue implements api.Backend.
func (sc *ServiceClient) GetIncomingMessageQueue(ctx context.Context, request *api.InMessageQueueRequest) ([]*message.IncomingMessage, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.IncomingMessageQueue(ctx, request.RuntimeID, request.Offset, request.Limit)
}

// WatchBlocks implements api.Backend.
func (sc *ServiceClient) WatchBlocks(_ context.Context, id common.Namespace) (<-chan *api.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	notifiers := sc.getRuntimeNotifiers(id)
	sub := notifiers.blockNotifier.Subscribe()
	ch := make(chan *api.AnnotatedBlock)
	sub.Unwrap(ch)

	sc.trackRuntime(id)
	return ch, sub, nil
}

func (sc *ServiceClient) WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription) {
	sub := sc.allBlockNotifier.Subscribe()
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub
}

// WatchEvents implements api.Backend.
func (sc *ServiceClient) WatchEvents(_ context.Context, id common.Namespace) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	notifiers := sc.getRuntimeNotifiers(id)
	sub := notifiers.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	sc.trackRuntime(id)
	return ch, sub, nil
}

// WatchExecutorCommitments implements api.Backend.
func (sc *ServiceClient) WatchExecutorCommitments(_ context.Context, id common.Namespace) (<-chan *commitment.ExecutorCommitment, pubsub.ClosableSubscription, error) {
	notifiers := sc.getRuntimeNotifiers(id)
	sub := notifiers.ecNotifier.Subscribe()
	ch := make(chan *commitment.ExecutorCommitment)
	sub.Unwrap(ch)

	sc.trackRuntime(id)
	return ch, sub, nil
}

func (sc *ServiceClient) trackRuntime(id common.Namespace) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if _, ok := sc.trackedRuntimes[id]; ok {
		return
	}

	sc.logger.Debug("tracking new runtime",
		"runtime_id", id,
	)

	sc.trackedRuntimes[id] = &trackedRuntime{
		runtimeID: id,
		round:     api.RoundInvalid,
	}

	// Request subscription to events for this runtime.
	sc.queryCh <- app.QueryForRuntime(id)
}

// StateToGenesis implements api.Backend.
func (sc *ServiceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *ServiceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

// GetEvents implements api.Backend.
func (sc *ServiceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get block results at given height.
	var results *cmtrpctypes.ResultBlockResults
	results, err := sc.backend.GetCometBFTBlockResults(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft block results",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	// Get transactions at given height.
	txns, err := sc.backend.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	var events []*api.Event
	// Decode events from block results (at the beginning of the block).
	blockEvs, err := EventsFromCometBFT(nil, results.Height, results.BeginBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	// Decode events from transaction results.
	for txIdx, txResult := range results.TxsResults {
		// The order of transactions in txns and results.TxsResults is
		// supposed to match, so the same index in both slices refers to the
		// same transaction.
		var tx cmttypes.Tx
		if txns != nil {
			tx = txns[txIdx]
		}
		evs, txErr := EventsFromCometBFT(tx, results.Height, txResult.Events)
		if txErr != nil {
			return nil, txErr
		}
		events = append(events, evs...)
	}

	// Decode events from block results (at the end of the block).
	blockEvs, err = EventsFromCometBFT(nil, results.Height, results.EndBlockEvents)
	if err != nil {
		return nil, err
	}
	events = append(events, blockEvs...)

	return events, nil
}

// Cleanup implements api.Backend.
func (sc *ServiceClient) Cleanup() {
}

func (sc *ServiceClient) getRuntimeNotifiers(id common.Namespace) *runtimeBrokers {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	notifiers := sc.runtimeNotifiers[id]
	if notifiers == nil {
		notifiers = &runtimeBrokers{
			blockNotifier: pubsub.NewBroker(true),
			eventNotifier: pubsub.NewBroker(false),
			ecNotifier:    pubsub.NewBroker(false),
		}
		sc.runtimeNotifiers[id] = notifiers
	}

	return notifiers
}

// ServiceDescriptor implements api.ServiceClient.
func (sc *ServiceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewServiceDescriptor(api.ModuleName, app.EventType, sc.queryCh)
}

// DeliverBlock implements api.ServiceClient.
func (sc *ServiceClient) DeliverBlock(ctx context.Context, blk *cmttypes.Block) error {
	sc.mu.RLock()
	trs := slices.Collect(maps.Values(sc.trackedRuntimes))
	sc.mu.RUnlock()

	for _, tr := range trs {
		// Emit the latest block immediately, unless a finalized event for
		// one of the blocks has already been received. Subsequent blocks
		// will be emitted upon receiving new finalized events.
		if tr.round != api.RoundInvalid {
			continue
		}
		rs, err := sc.GetRuntimeState(ctx, &api.RuntimeRequest{
			RuntimeID: tr.runtimeID,
			Height:    blk.Height,
		})
		if err != nil {
			sc.logger.Warn("failed to get runtime state",
				"err", err,
				"runtime_id", tr.runtimeID,
				"height", blk.Height,
			)
			return fmt.Errorf("roothash: failed to get runtime state: %w", err)
		}
		blk := &api.AnnotatedBlock{
			Height: rs.LastBlockHeight,
			Block:  rs.LastBlock,
		}
		if err := sc.emitBlock(tr, blk); err != nil {
			sc.logger.Warn("failed to emit latest block",
				"err", err,
				"runtime_id", tr.runtimeID,
			)
			return fmt.Errorf("roothash: failed to emit latest block: %w", err)
		}
	}

	return nil
}

// DeliverEvent implements api.ServiceClient.
func (sc *ServiceClient) DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
	events, err := EventsFromCometBFT(tx, height, []cmtabcitypes.Event{*ev})
	if err != nil {
		return fmt.Errorf("roothash: failed to process cometbft events: %w", err)
	}

	for _, ev := range events {
		// Notify non-finalized events.
		if ev.Finalized == nil {
			notifiers := sc.getRuntimeNotifiers(ev.RuntimeID)
			notifiers.eventNotifier.Broadcast(ev)
			continue
		}

		// Only process finalized events for tracked runtimes.
		sc.mu.RLock()
		tr, ok := sc.trackedRuntimes[ev.RuntimeID]
		sc.mu.RUnlock()
		if !ok {
			continue
		}

		// Emit the latest block and any missing blocks.
		blk, err := sc.fetchBlock(ctx, tr.runtimeID, height)
		if err != nil {
			sc.logger.Error("failed to fetch latest block",
				"err", err,
				"height", height,
				"runtime_id", tr.runtimeID,
			)
			return fmt.Errorf("roothash: failed to fetch latest block: %w", err)
		}
		if blk.Block.Header.Round != ev.Finalized.Round {
			sc.logger.Error("block round mismatch",
				"height", height,
				"round", blk.Block.Header.Round,
				"expected_round", ev.Finalized.Round,
			)
			return fmt.Errorf("roothash: block round mismatch")
		}

		if tr.round != api.RoundInvalid && blk.Block.Header.Round > tr.round+1 {
			// Catch up. This may emit the same block multiple times, e.g.,
			// if no new blocks were produced due to slow compute nodes
			// or a suspended runtime.
			for h := tr.height + 1; h < blk.Height; h++ {
				oldBlk, err := sc.fetchBlock(ctx, tr.runtimeID, h)
				if err != nil {
					sc.logger.Error("failed to fetch block",
						"err", err,
						"height", h,
						"runtime_id", tr.runtimeID,
					)
					return fmt.Errorf("roothash: failed to fetch block: %w", err)
				}
				if err := sc.emitBlock(tr, oldBlk); err != nil {
					return fmt.Errorf("roothash: failed to emit block: %w", err)
				}
				if oldBlk.Block.Header.Round+1 == blk.Block.Header.Round {
					break
				}
			}
		}

		if err = sc.emitBlock(tr, blk); err != nil {
			return fmt.Errorf("roothash: failed to emit latest block: %w", err)
		}
	}

	return nil
}

func (sc *ServiceClient) emitBlock(tr *trackedRuntime, blk *api.AnnotatedBlock) error {
	switch {
	case tr.round == api.RoundInvalid:
		// First block.
	case blk.Block.Header.Round <= tr.round:
		// Outdated block can be ignored. This can happen if we also receive
		// a finalize event for the first emitted block, or if we're catching
		// up and no new blocks were generated.
		sc.logger.Warn("skipping outdated block",
			"height", blk.Height,
			"round", blk.Block.Header.Round,
			"last_height", tr.height,
			"last_round", tr.round,
		)
		return nil
	case blk.Block.Header.Round == tr.round+1:
		// Valid block.
	default:
		// Invalid block. Blocks must be emitted sequentially with no skipped
		// rounds.
		sc.logger.Error("unexpected block round",
			"height", blk.Height,
			"round", blk.Block.Header.Round,
			"last_height", tr.height,
			"last_round", tr.round,
		)
		return fmt.Errorf("unexpected block round")
	}

	notifiers := sc.getRuntimeNotifiers(tr.runtimeID)
	notifiers.blockNotifier.Broadcast(blk)
	sc.allBlockNotifier.Broadcast(blk.Block)

	tr.height = blk.Height
	tr.round = blk.Block.Header.Round

	return nil
}

func (sc *ServiceClient) fetchBlock(ctx context.Context, runtimeID common.Namespace, height int64) (*api.AnnotatedBlock, error) {
	blk, err := sc.getLatestBlockAt(ctx, runtimeID, height)
	if err != nil {
		return nil, err
	}
	return &api.AnnotatedBlock{
		Height: height,
		Block:  blk,
	}, nil
}

// DeliverExecutorCommitment implements api.ExecutorCommitmentNotifier.
func (sc *ServiceClient) DeliverExecutorCommitment(runtimeID common.Namespace, ec *commitment.ExecutorCommitment) {
	notifiers := sc.getRuntimeNotifiers(runtimeID)
	notifiers.ecNotifier.Broadcast(ec)
}

// EventsFromCometBFT extracts staking events from CometBFT events.
func EventsFromCometBFT(
	tx cmttypes.Tx,
	height int64,
	tmEvents []cmtabcitypes.Event,
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
EventLoop:
	for _, tmEv := range tmEvents {
		// Ignore events that don't relate to the roothash app.
		if tmEv.GetType() != app.EventType {
			continue
		}

		var (
			runtimeID *common.Namespace
			ev        *api.Event
		)
		for _, pair := range tmEv.GetAttributes() {
			key := pair.GetKey()
			val := pair.GetValue()

			switch {
			case eventsAPI.IsAttributeKind(key, &api.FinalizedEvent{}):
				// Finalized event.
				var e api.FinalizedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt Finalized event: %w", err))
					continue EventLoop
				}

				ev = &api.Event{Finalized: &e}
			case eventsAPI.IsAttributeKind(key, &api.ExecutionDiscrepancyDetectedEvent{}):
				// An execution discrepancy has been detected.
				var e api.ExecutionDiscrepancyDetectedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt ExecutionDiscrepancyDetected event: %w", err))
					continue EventLoop
				}

				ev = &api.Event{ExecutionDiscrepancyDetected: &e}
			case eventsAPI.IsAttributeKind(key, &api.ExecutorCommittedEvent{}):
				// An executor commit has been processed.
				var e api.ExecutorCommittedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt ExecutorCommitted event: %w", err))
					continue EventLoop
				}

				ev = &api.Event{ExecutorCommitted: &e}
			case eventsAPI.IsAttributeKind(key, &api.InMsgProcessedEvent{}):
				// Incoming message processed event.
				var e api.InMsgProcessedEvent
				if err := eventsAPI.DecodeValue(val, &e); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt InMsgProcessed event: %w", err))
					continue EventLoop
				}

				ev = &api.Event{InMsgProcessed: &e}
			case eventsAPI.IsAttributeKind(key, &api.RuntimeIDAttribute{}):
				if runtimeID != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: duplicate runtime ID attribute"))
					continue EventLoop
				}
				rtAttribute := api.RuntimeIDAttribute{}
				if err := eventsAPI.DecodeValue(val, &rtAttribute); err != nil {
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt runtime ID: %w", err))
					continue EventLoop
				}
				runtimeID = &rtAttribute.ID
			default:
				errs = errors.Join(errs, fmt.Errorf("roothash: unknown event type: key: %s, val: %s", key, val))
			}
		}

		if runtimeID == nil {
			errs = errors.Join(errs, fmt.Errorf("roothash: missing runtime ID attribute"))
			continue
		}
		if ev != nil {
			ev.RuntimeID = *runtimeID
			ev.Height = height
			ev.TxHash = txHash
			events = append(events, ev)
		}
	}
	return events, errs
}

// New constructs a new CometBFT-based root hash backend.
func New(ctx context.Context, backend tmapi.Backend, querier *app.QueryFactory) *ServiceClient {
	return &ServiceClient{
		ctx:              ctx,
		logger:           logging.GetLogger("cometbft/roothash"),
		backend:          backend,
		querier:          querier,
		allBlockNotifier: pubsub.NewBroker(false),
		runtimeNotifiers: make(map[common.Namespace]*runtimeBrokers),
		genesisBlocks:    make(map[common.Namespace]*block.Block),
		queryCh:          make(chan cmtpubsub.Query, runtimeRegistry.MaxRuntimeCount),
		trackedRuntimes:  make(map[common.Namespace]*trackedRuntime),
	}
}

func init() {
	crash.RegisterCrashPoints(
		crashPointBlockBeforeIndex,
	)
}
