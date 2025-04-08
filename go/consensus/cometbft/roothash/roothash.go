// Package roothash implements the CometBFT backed roothash backend.
package roothash

import (
	"context"
	"errors"
	"fmt"
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

// ServiceClient is the roothash service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

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

type cmdTrackRuntime struct {
	runtimeID common.Namespace
}

type serviceClient struct {
	tmapi.BaseServiceClient
	sync.RWMutex

	ctx    context.Context
	logger *logging.Logger

	backend tmapi.Backend
	querier *app.QueryFactory

	allBlockNotifier *pubsub.Broker
	runtimeNotifiers map[common.Namespace]*runtimeBrokers
	genesisBlocks    map[common.Namespace]*block.Block

	queryCh        chan cmtpubsub.Query
	cmdCh          chan interface{}
	trackedRuntime map[common.Namespace]*trackedRuntime
}

// Implements api.Backend.
func (sc *serviceClient) GetGenesisBlock(ctx context.Context, request *api.RuntimeRequest) (*block.Block, error) {
	// First check if we have the genesis blocks cached. They are immutable so easy
	// to cache to avoid repeated requests to the CometBFT app.
	sc.RLock()
	if blk := sc.genesisBlocks[request.RuntimeID]; blk != nil {
		sc.RUnlock()
		return blk, nil
	}
	sc.RUnlock()

	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	blk, err := q.GenesisBlock(ctx, request.RuntimeID)
	if err != nil {
		return nil, err
	}

	// Update the genesis block cache.
	sc.Lock()
	sc.genesisBlocks[request.RuntimeID] = blk
	sc.Unlock()

	return blk, nil
}

// Implements api.Backend.
func (sc *serviceClient) GetLatestBlock(ctx context.Context, request *api.RuntimeRequest) (*block.Block, error) {
	return sc.getLatestBlockAt(ctx, request.RuntimeID, request.Height)
}

func (sc *serviceClient) getLatestBlockAt(ctx context.Context, runtimeID common.Namespace, height int64) (*block.Block, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.LatestBlock(ctx, runtimeID)
}

// Implements api.Backend.
func (sc *serviceClient) GetRuntimeState(ctx context.Context, request *api.RuntimeRequest) (*api.RuntimeState, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.RuntimeState(ctx, request.RuntimeID)
}

// Implements api.Backend.
func (sc *serviceClient) GetLastRoundResults(ctx context.Context, request *api.RuntimeRequest) (*api.RoundResults, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.LastRoundResults(ctx, request.RuntimeID)
}

func (sc *serviceClient) GetRoundRoots(ctx context.Context, request *api.RoundRootsRequest) (*api.RoundRoots, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.RoundRoots(ctx, request.RuntimeID, request.Round)
}

func (sc *serviceClient) GetPastRoundRoots(ctx context.Context, request *api.RuntimeRequest) (map[uint64]api.RoundRoots, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.PastRoundRoots(ctx, request.RuntimeID)
}

// Implements api.Backend.
func (sc *serviceClient) GetIncomingMessageQueueMeta(ctx context.Context, request *api.RuntimeRequest) (*message.IncomingMessageQueueMeta, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.IncomingMessageQueueMeta(ctx, request.RuntimeID)
}

// Implements api.Backend.
func (sc *serviceClient) GetIncomingMessageQueue(ctx context.Context, request *api.InMessageQueueRequest) ([]*message.IncomingMessage, error) {
	q, err := sc.querier.QueryAt(ctx, request.Height)
	if err != nil {
		return nil, err
	}

	return q.IncomingMessageQueue(ctx, request.RuntimeID, request.Offset, request.Limit)
}

// Implements api.Backend.
func (sc *serviceClient) WatchBlocks(_ context.Context, id common.Namespace) (<-chan *api.AnnotatedBlock, pubsub.ClosableSubscription, error) {
	notifiers := sc.getRuntimeNotifiers(id)
	sub := notifiers.blockNotifier.Subscribe()
	ch := make(chan *api.AnnotatedBlock)
	sub.Unwrap(ch)

	// Start tracking this runtime if we are not tracking it yet.
	if err := sc.trackRuntime(sc.ctx, id); err != nil {
		sub.Close()
		return nil, nil, err
	}

	return ch, sub, nil
}

func (sc *serviceClient) WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription) {
	sub := sc.allBlockNotifier.Subscribe()
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub
}

// Implements api.Backend.
func (sc *serviceClient) WatchEvents(_ context.Context, id common.Namespace) (<-chan *api.Event, pubsub.ClosableSubscription, error) {
	notifiers := sc.getRuntimeNotifiers(id)
	sub := notifiers.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	// Start tracking this runtime if we are not tracking it yet.
	if err := sc.trackRuntime(sc.ctx, id); err != nil {
		sub.Close()
		return nil, nil, err
	}

	return ch, sub, nil
}

// Implements api.Backend.
func (sc *serviceClient) WatchExecutorCommitments(_ context.Context, id common.Namespace) (<-chan *commitment.ExecutorCommitment, pubsub.ClosableSubscription, error) {
	notifiers := sc.getRuntimeNotifiers(id)
	sub := notifiers.ecNotifier.Subscribe()
	ch := make(chan *commitment.ExecutorCommitment)
	sub.Unwrap(ch)

	// Start tracking this runtime if we are not tracking it yet.
	if err := sc.trackRuntime(sc.ctx, id); err != nil {
		sub.Close()
		return nil, nil, err
	}

	return ch, sub, nil
}

func (sc *serviceClient) trackRuntime(ctx context.Context, id common.Namespace) error {
	cmd := &cmdTrackRuntime{
		runtimeID: id,
	}

	select {
	case sc.cmdCh <- cmd:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

// Implements api.Backend.
func (sc *serviceClient) StateToGenesis(ctx context.Context, height int64) (*api.Genesis, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.Genesis(ctx)
}

func (sc *serviceClient) ConsensusParameters(ctx context.Context, height int64) (*api.ConsensusParameters, error) {
	q, err := sc.querier.QueryAt(ctx, height)
	if err != nil {
		return nil, err
	}

	return q.ConsensusParameters(ctx)
}

func (sc *serviceClient) getEvents(ctx context.Context, height int64, txns [][]byte) ([]*api.Event, error) {
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

// Implements api.Backend.
func (sc *serviceClient) GetEvents(ctx context.Context, height int64) ([]*api.Event, error) {
	// Get transactions at given height.
	txns, err := sc.backend.GetTransactions(ctx, height)
	if err != nil {
		sc.logger.Error("failed to get cometbft transactions",
			"err", err,
			"height", height,
		)
		return nil, err
	}

	return sc.getEvents(ctx, height, txns)
}

// Implements api.Backend.
func (sc *serviceClient) Cleanup() {
}

func (sc *serviceClient) getRuntimeNotifiers(id common.Namespace) *runtimeBrokers {
	sc.Lock()
	defer sc.Unlock()

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

// Implements api.ServiceClient.
func (sc *serviceClient) ServiceDescriptor() tmapi.ServiceDescriptor {
	return tmapi.NewServiceDescriptor(api.ModuleName, app.EventType, sc.queryCh, sc.cmdCh)
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverCommand(ctx context.Context, height int64, cmd interface{}) error {
	switch c := cmd.(type) {
	case *cmdTrackRuntime:
		// Request to track a new runtime.
		if _, ok := sc.trackedRuntime[c.runtimeID]; ok {
			// Ignore duplicate runtime tracking requests.
			return nil
		}

		sc.logger.Debug("tracking new runtime",
			"runtime_id", c.runtimeID,
			"height", height,
		)

		tr := &trackedRuntime{
			runtimeID: c.runtimeID,
			round:     api.RoundInvalid,
		}
		sc.trackedRuntime[c.runtimeID] = tr

		// Request subscription to events for this runtime.
		sc.queryCh <- app.QueryForRuntime(tr.runtimeID)

		// Resolve the correct block finalization height to use for the latest block at the current
		// height as the current height may not correspond to the latest block finalization height.
		rs, err := sc.GetRuntimeState(ctx, &api.RuntimeRequest{
			RuntimeID: tr.runtimeID,
			Height:    height,
		})
		if err != nil {
			sc.logger.Warn("failed to get runtime state",
				"err", err,
				"runtime_id", tr.runtimeID,
				"height", height,
			)
			return fmt.Errorf("roothash: failed to get runtime state: %w", err)
		}
		annBlk := &api.AnnotatedBlock{
			Height: rs.LastBlockHeight,
			Block:  rs.LastBlock,
		}

		// Emit the latest block.
		if err := sc.emitLatestBlock(tr, annBlk); err != nil {
			sc.logger.Warn("failed to emit latest block",
				"err", err,
				"runtime_id", tr.runtimeID,
				"height", height,
			)
			return fmt.Errorf("roothash: failed to emit latest block: %w", err)
		}
	default:
		return fmt.Errorf("roothash: unknown command: %T", cmd)
	}
	return nil
}

// Implements api.ServiceClient.
func (sc *serviceClient) DeliverEvent(ctx context.Context, height int64, tx cmttypes.Tx, ev *cmtabcitypes.Event) error {
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
		tr, ok := sc.trackedRuntime[ev.RuntimeID]
		if !ok {
			continue
		}

		// Fetch the latest block.
		blk, err := sc.getLatestBlockAt(ctx, tr.runtimeID, height)
		if err != nil {
			sc.logger.Error("failed to fetch latest block",
				"err", err,
				"height", height,
				"runtime_id", tr.runtimeID,
			)
			return fmt.Errorf("roothash: failed to fetch latest block: %w", err)
		}
		if blk.Header.Round != ev.Finalized.Round {
			sc.logger.Error("block round mismatch",
				"height", height,
				"round", blk.Header.Round,
				"expected_round", ev.Finalized.Round,
			)
			return fmt.Errorf("roothash: block round mismatch")
		}
		annBlk := &api.AnnotatedBlock{
			Height: height,
			Block:  blk,
		}

		// Emit the latest block.
		if err = sc.emitLatestBlock(tr, annBlk); err != nil {
			return fmt.Errorf("roothash: failed to emit latest block: %w", err)
		}
	}

	return nil
}

func (sc *serviceClient) emitLatestBlock(tr *trackedRuntime, annBlk *api.AnnotatedBlock) error {
	if tr.round != api.RoundInvalid {
		switch {
		case annBlk.Block.Header.Round <= tr.round:
			// This can occur if a block is finalized immediately after we
			// subscribe to runtime events.
			sc.logger.Warn("skipping outdated block",
				"height", annBlk.Height,
				"round", annBlk.Block.Header.Round,
				"last_height", tr.height,
				"last_round", tr.round,
			)
			return nil
		case annBlk.Block.Header.Round == tr.round+1:
			// Blocks should be processed sequentially.
		default:
			// Detected a gap in block rounds. While recovery might be possible
			// by fetching the missing blocks, it's unlikely we can fully recover.
			// For now, enforce strict error handling and address if necessary later.
			sc.logger.Error("unexpected block round",
				"height", annBlk.Height,
				"round", annBlk.Block.Header.Round,
				"last_height", tr.height,
				"last_round", tr.round,
			)
			return fmt.Errorf("unexpected block round")
		}
	}

	notifiers := sc.getRuntimeNotifiers(tr.runtimeID)
	notifiers.blockNotifier.Broadcast(annBlk)
	sc.allBlockNotifier.Broadcast(annBlk.Block)

	tr.height = annBlk.Height
	tr.round = annBlk.Block.Header.Round

	return nil
}

// Implements api.ExecutorCommitmentNotifier.
func (sc *serviceClient) DeliverExecutorCommitment(runtimeID common.Namespace, ec *commitment.ExecutorCommitment) {
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
func New(
	ctx context.Context,
	backend tmapi.Backend,
) (ServiceClient, error) {
	sc := serviceClient{
		ctx:              ctx,
		logger:           logging.GetLogger("cometbft/roothash"),
		backend:          backend,
		allBlockNotifier: pubsub.NewBroker(false),
		runtimeNotifiers: make(map[common.Namespace]*runtimeBrokers),
		genesisBlocks:    make(map[common.Namespace]*block.Block),
		queryCh:          make(chan cmtpubsub.Query, runtimeRegistry.MaxRuntimeCount),
		cmdCh:            make(chan interface{}, runtimeRegistry.MaxRuntimeCount),
		trackedRuntime:   make(map[common.Namespace]*trackedRuntime),
	}

	// Initialize and register the CometBFT service component.
	a := app.New(&sc)
	if err := backend.RegisterApplication(a); err != nil {
		return nil, err
	}
	sc.querier = a.QueryFactory().(*app.QueryFactory)

	return &sc, nil
}

func init() {
	crash.RegisterCrashPoints(
		crashPointBlockBeforeIndex,
	)
}
