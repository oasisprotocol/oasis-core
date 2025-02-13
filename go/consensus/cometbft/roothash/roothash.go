// Package roothash implements the CometBFT backed roothash backend.
package roothash

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	cmtabcitypes "github.com/cometbft/cometbft/abci/types"
	cmtpubsub "github.com/cometbft/cometbft/libs/pubsub"
	cmtrpctypes "github.com/cometbft/cometbft/rpc/core/types"
	cmttypes "github.com/cometbft/cometbft/types"
	"github.com/eapache/channels"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/workerpool"
	eventsAPI "github.com/oasisprotocol/oasis-core/go/consensus/api/events"
	tmapi "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	app "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/roothash"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/message"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
)

const (
	crashPointBlockBeforeIndex = "roothash.before_index"
	batchSize                  = 1000
	// consensuIntervals is number intervals we split initial history reindex,
	// for parallel reindex.
	consensusIntervals = 10
	// readWorkers is number of goroutines that single read worker pool is using.
	// There is one read worker pool per consensus interval, that is responsible
	// for fetching consensus state of a given batch in parallel.
	readWorkers = 1
)

// ServiceClient is the roothash service client interface.
type ServiceClient interface {
	api.Backend
	tmapi.ServiceClient
}

type runtimeBrokers struct {
	sync.Mutex

	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker
	ecNotifier    *pubsub.Broker

	lastBlockHeight int64
	lastBlock       *block.Block
}

type trackedRuntime struct {
	runtimeID common.Namespace

	height       int64
	blockHistory api.BlockHistory
	reindexDone  bool
}

type cmdTrackRuntime struct {
	runtimeID    common.Namespace
	blockHistory api.BlockHistory
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

	pruneHandler *pruneHandler
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

	// Start tracking this runtime if we are not tracking it yet.
	if err := sc.trackRuntime(sc.ctx, id, nil); err != nil {
		sub.Close()
		return nil, nil, err
	}

	return monotonicCh, sub, nil
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
	if err := sc.trackRuntime(sc.ctx, id, nil); err != nil {
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

	return ch, sub, nil
}

// Implements api.Backend.
func (sc *serviceClient) TrackRuntime(ctx context.Context, history api.BlockHistory) error {
	sc.pruneHandler.trackRuntime(history)
	return sc.trackRuntime(ctx, history.RuntimeID(), history)
}

func (sc *serviceClient) trackRuntime(ctx context.Context, id common.Namespace, history api.BlockHistory) error {
	cmd := &cmdTrackRuntime{
		runtimeID:    id,
		blockHistory: history,
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
	results, err := sc.backend.GetBlockResults(ctx, height)
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
			blockNotifier: pubsub.NewBroker(false),
			eventNotifier: pubsub.NewBroker(false),
			ecNotifier:    pubsub.NewBroker(false),
		}
		sc.runtimeNotifiers[id] = notifiers
	}

	return notifiers
}

func (sc *serviceClient) reindexBlocks(ctx context.Context, currentHeight int64, bh api.BlockHistory) (uint64, error) {
	start := time.Now()
	lastRound := api.RoundInvalid
	if currentHeight <= 0 {
		return lastRound, nil
	}

	runtimeID := bh.RuntimeID()
	logger := sc.logger.With("runtime_id", runtimeID)

	var err error
	var lastHeight int64
	if lastHeight, err = bh.LastConsensusHeight(); err != nil {
		sc.logger.Error("failed to get last indexed height",
			"err", err,
		)
		return 0, fmt.Errorf("failed to get last indexed height: %w", err)
	}
	// +1 since we want the last non-seen height.
	lastHeight++

	// Take prune strategy into account.
	lastRetainedHeight, err := sc.backend.GetLastRetainedVersion(sc.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get last retained height: %w", err)
	}
	if lastHeight < lastRetainedHeight {
		logger.Debug("last height pruned, skipping until last retained",
			"last_retained_height", lastRetainedHeight,
			"last_height", lastHeight,
		)
		lastHeight = lastRetainedHeight
	}

	// Take initial genesis height into account.
	genesisDoc, err := sc.backend.GetGenesisDocument(sc.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to get genesis document: %w", err)
	}
	if lastHeight < genesisDoc.Height {
		lastHeight = genesisDoc.Height
	}

	interval := (currentHeight - lastHeight) + 1
	workerInterval := interval/int64(consensusIntervals) + 1 // +1 to distribute modulo
	var wg sync.WaitGroup
	errCh := make(chan error)
	lastRoundCh := make(chan uint64, consensusIntervals)
	readGetBlocksCh := make(chan time.Duration, consensusIntervals)
	readLatestBlockCh := make(chan time.Duration, consensusIntervals)
	readLastRoundsCh := make(chan time.Duration, consensusIntervals)
	writeBatchCh := make(chan time.Duration, consensusIntervals)

	var readGetBlocks, readLatestBlock, readLastRounds, writeBatch time.Duration

	// Scan all blocks between last indexed height and current height.
	logger.Info("history reindex0: reindexing blocks",
		"last_indexed_height", lastHeight,
		"current_height", currentHeight,
		"interval", interval,
		"workerInterval", workerInterval,
	)

	for start := lastHeight; start <= currentHeight; start += workerInterval {
		end := start + workerInterval - 1 // -1 since inclusive range
		if end > currentHeight {
			end = currentHeight
		}

		wg.Add(1)
		go func(workerStart, workerEnd int64) {
			defer wg.Done()
			workerID := fmt.Sprintf("worker-[%d-%d]", workerStart, workerEnd)

			pool := workerpool.New(workerID + "'s worker pool for reads")
			defer pool.Stop()
			pool.Resize(uint(readWorkers))

			var readGetBlocks, readLatestBlock, readLastRounds time.Duration

			// var errCount, emptyCount int64
			var lastRound = api.RoundInvalid

			// var read, write int64
			sc.logger.Info("history reindex0: worker starting worker interval reindex",
				"start", workerStart,
				"end", workerEnd,
			)
			for batchStart := workerStart; batchStart <= workerEnd; batchStart += batchSize {
				batchEnd := batchStart + batchSize - 1
				if batchEnd > workerEnd {
					batchEnd = workerEnd
				}
				readGBlocks, readLBlock, readLRounds, wBatch, last, err := sc.reindexBatch(ctx, runtimeID, bh, batchStart, batchEnd, pool)
				readGetBlocks += readGBlocks
				readLatestBlock += readLBlock
				readLastRounds += readLRounds
				writeBatch += wBatch

				if err != nil {
					errCh <- fmt.Errorf("failed to reindex batch-[%v-%v] of %s: %w",
						batchStart,
						batchEnd,
						workerID,
						err,
					)
					return
				}
				if last != api.RoundInvalid && (lastRound == api.RoundInvalid || last > lastRound) {
					lastRound = last
				}
			}
			lastRoundCh <- lastRound
			readGetBlocksCh <- readGetBlocks
			readLatestBlockCh <- readLatestBlock
			readLastRoundsCh <- readLastRounds
			sc.logger.Info("history reindex0: worker interval reindex completed successfully",
				"start", workerStart,
				"end", workerEnd,
				"lastRound", lastRound)

		}(start, end)

	}
	// Log errors if they happen live
	go func() {
		for err := range errCh {
			sc.logger.Error("history reindex0: error during worker reindexing",
				"err", err,
			)
		}
	}()
	wg.Wait()
	close(errCh)
	close(lastRoundCh)
	close(readGetBlocksCh)
	close(readLatestBlockCh)
	close(readLastRoundsCh)
	close(writeBatchCh)

	for last := range lastRoundCh {
		if last != api.RoundInvalid && (lastRound == api.RoundInvalid || last > lastRound) {
			lastRound = last
		}
	}
	for v := range readGetBlocksCh {
		readGetBlocks += v
	}
	for v := range readLatestBlockCh {
		readLatestBlock += v
	}
	for v := range readLastRoundsCh {
		readLastRounds += v
	}
	for v := range writeBatchCh {
		writeBatch += v
	}
	if lastRound == api.RoundInvalid {
		sc.logger.Debug("no new round reindexed, return latest known round")
		switch blk, err := bh.GetCommittedBlock(sc.ctx, api.RoundLatest); err {
		case api.ErrNotFound:
		case nil:
			lastRound = blk.Header.Round
		default:
			return lastRound, fmt.Errorf("failed to get latest block: %w", err)
		}
	}
	duration := time.Since(start).Seconds()
	speed := interval / int64(duration)
	sc.logger.Info("history reindex0: block reindex complete",
		"last_round", lastRound,
		"duration", duration,
		"interval", interval,
		"speed", speed,
		"batch_size", batchSize,
		"read_worker_pool_size", readWorkers,
		"consensus_intervals", consensusIntervals,
		"read_get_blocks", readGetBlocks.Seconds(),
		"read_latest_block", readLatestBlock.Seconds(),
		"read_last_rounds", readLastRounds.Seconds(),
		"read_total", readGetBlocks.Seconds()+readLatestBlock.Seconds()+readLastRounds.Seconds(),
		"write_batch", writeBatch.Seconds(),
	)
	panic("history reindex0 finished")

	return lastRound, nil
}

func (sc *serviceClient) reindexBatch(
	ctx context.Context,
	runtimeID common.Namespace,
	bh api.BlockHistory,
	start int64,
	end int64,
	pool *workerpool.Pool,
) (time.Duration, time.Duration, time.Duration, time.Duration, uint64, error) {
	sc.logger.Debug("history reindex101: reindexing batch",
		"runtime_id", runtimeID,
		"batch_start", start,
		"batch_end", end,
	)
	var wg sync.WaitGroup

	// TODO ovehead of locking may affect your benchmark!!!
	var mu sync.Mutex
	var readGetBlocks, readLatestBlock, readLastRounds, writeBatch time.Duration
	lastRound := api.RoundInvalid
	var blocks []*api.AnnotatedBlock
	var roundResults []*api.RoundResults
	errorCh := make(chan error, batchSize)

	for height := start; height <= end; height++ {
		wg.Add(1)
		pool.Submit(func() {
			defer wg.Done()

			var results *cmtrpctypes.ResultBlockResults
			begin := time.Now()
			results, err := sc.backend.GetBlockResults(sc.ctx, height)
			readGetBlocksLocal := time.Since(begin)
			if err != nil {
				// XXX: could soft-fail first few heights in case more heights were
				// pruned right after the GetLastRetainedVersion query.
				sc.logger.Error("failed to get cometbft block results",
					"err", err,
					"height", height,
				)
				errorCh <- fmt.Errorf("failed to get cometbft block results: %w", err)
			}

			// Index block.
			tmEvents := results.BeginBlockEvents
			for _, txResults := range results.TxsResults {
				tmEvents = append(tmEvents, txResults.Events...)
			}
			tmEvents = append(tmEvents, results.EndBlockEvents...)
			for _, tmEv := range tmEvents {
				if tmEv.GetType() != app.EventType {
					continue
				}

				var evRtID *common.Namespace
				var ev *api.FinalizedEvent
				for _, pair := range tmEv.GetAttributes() {
					key := pair.GetKey()
					val := pair.GetValue()

					switch {
					case eventsAPI.IsAttributeKind(key, &api.RuntimeIDAttribute{}):
						if evRtID != nil {
							errorCh <- fmt.Errorf("roothash: duplicate runtime ID attribute")
							return
						}

						var rtAttribute api.RuntimeIDAttribute
						if err = eventsAPI.DecodeValue(val, &rtAttribute); err != nil {
							errorCh <- fmt.Errorf("roothash: corrupt runtime ID: %w", err)
							return
						}
						evRtID = &rtAttribute.ID

					case eventsAPI.IsAttributeKind(key, &api.FinalizedEvent{}):
						var e api.FinalizedEvent
						if err = eventsAPI.DecodeValue(val, &e); err != nil {
							sc.logger.Error("failed to unmarshal finalized event",
								"err", err,
								"height", height,
							)
							errorCh <- fmt.Errorf("failed to unmarshal finalized event: %w", err)
							return
						}
						ev = &e
					default:
					}
				}

				// Only process finalized events.
				if ev == nil {
					continue
				}
				// Only process events for the given runtime.
				if !evRtID.Equal(&runtimeID) {
					continue
				}

				readLBlock, readLRound, annBlk, rr, err := sc.fetchFinalizedRound(ctx, height, runtimeID, &ev.Round)
				if err != nil {
					errorCh <- fmt.Errorf("failed to fetch roothash finalized round: %w", err)
					return
				}
				mu.Lock()
				readLatestBlock += readLBlock
				readLastRounds += readLRound
				readGetBlocks += readGetBlocksLocal
				blocks = append(blocks, annBlk)
				roundResults = append(roundResults, rr)
				lastRound = ev.Round
				mu.Unlock()
			}
		})
	}

	// Either all tasks finished or worker pool was closed.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
		close(errorCh)
	}()

	go func() {
		for err := range errorCh {
			sc.logger.Error("history reindex0: error during batching",
				"err", err,
			)
		}
	}()
	select {
	case <-pool.Quit():
	case <-done:
	}

	begin := time.Now()
	err := bh.CommitBatch(blocks, roundResults)
	writeBatch = time.Since(begin)
	if err != nil {
		sc.logger.Error("failed to commit batch to history keeper",
			"err", err,
			"runtime_id", runtimeID,
			"batch_start", start,
			"batch_end", end,
		)
		return 0, 0, 0, 0, 0, err
	}

	return readGetBlocks, readLatestBlock, readLastRounds, writeBatch, lastRound, nil
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
		etr := sc.trackedRuntime[c.runtimeID]
		if etr != nil {
			// Ignore duplicate runtime tracking requests unless this updates the block history.
			if etr.blockHistory != nil || c.blockHistory == nil {
				break
			}
		} else {
			sc.logger.Debug("tracking new runtime",
				"runtime_id", c.runtimeID,
				"height", height,
			)
		}

		// We need to start watching a new block history.
		tr := &trackedRuntime{
			runtimeID:    c.runtimeID,
			blockHistory: c.blockHistory,
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
			sc.logger.Warn("failed to get runtime state for latest block",
				"err",
				"runtime_id", tr.runtimeID,
				"height", height,
			)
			return nil
		}

		// Emit latest block.
		if err := sc.processFinalizedEvent(ctx, rs.LastBlockHeight, tr.runtimeID, nil); err != nil {
			sc.logger.Warn("failed to emit latest block",
				"err", err,
				"runtime_id", tr.runtimeID,
				"height", height,
			)
		}
		// Make sure we reindex again when receiving the first event.
		tr.reindexDone = false
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
		if sc.trackedRuntime[ev.RuntimeID] == nil {
			continue
		}
		if err = sc.processFinalizedEvent(ctx, height, ev.RuntimeID, &ev.Finalized.Round); err != nil { //nolint:gosec
			return fmt.Errorf("roothash: failed to process finalized event: %w", err)
		}
	}

	return nil
}

// Implements api.ExecutorCommitmentNotifier.
func (sc *serviceClient) DeliverExecutorCommitment(runtimeID common.Namespace, ec *commitment.ExecutorCommitment) {
	notifiers := sc.getRuntimeNotifiers(runtimeID)
	notifiers.ecNotifier.Broadcast(ec)
}

func (sc *serviceClient) processFinalizedEvent(
	ctx context.Context,
	height int64,
	runtimeID common.Namespace,
	round *uint64,
) (err error) {
	tr := sc.trackedRuntime[runtimeID]
	if tr == nil {
		sc.logger.Error("runtime not tracked",
			"runtime_id", runtimeID,
			"tracked_runtimes", sc.trackedRuntime,
		)
		return fmt.Errorf("roothash: runtime not tracked: %s", runtimeID)
	}
	defer func() {
		// If there was an error, flag the tracked runtime for reindex.
		if err == nil {
			return
		}

		tr.reindexDone = false
	}()

	if height <= tr.height {
		return nil
	}

	// Process finalized event.
	_, _, annBlk, roundResults, err := sc.fetchFinalizedRound(ctx, height, runtimeID, round)
	if err != nil {
		return fmt.Errorf("failed to fetch roothash finalized round: %w", err)
	}

	// Commit the block to history if needed.
	if tr.blockHistory != nil {
		crash.Here(crashPointBlockBeforeIndex)

		// Perform reindex if required.
		lastRound := api.RoundInvalid
		if !tr.reindexDone {
			// Note that we need to reindex up to the previous height as the current height is
			// already being processed right now.
			if lastRound, err = sc.reindexBlocks(ctx, height-1, tr.blockHistory); err != nil {
				sc.logger.Error("failed to reindex blocks",
					"err", err,
					"runtime_id", runtimeID,
				)
				return fmt.Errorf("failed to reindex blocks: %w", err)
			}
			tr.reindexDone = true
		}

		// Only commit the block in case it was not already committed during reindex. Note that even
		// in case we only reindex up to height-1 this can still happen on the first emitted block
		// since that height is not guaranteed to be the one that contains a round finalized event.
		if lastRound == api.RoundInvalid || annBlk.Block.Header.Round > lastRound {
			sc.logger.Debug("commit block",
				"runtime_id", runtimeID,
				"height", height,
				"round", annBlk.Block.Header.Round,
			)

			err = tr.blockHistory.Commit(annBlk, roundResults, true)
			if err != nil {
				sc.logger.Error("failed to commit block to history keeper",
					"err", err,
					"runtime_id", runtimeID,
					"height", height,
					"round", annBlk.Block.Header.Round,
				)
				return fmt.Errorf("failed to commit block to history keeper: %w", err)
			}
		}
	}

	notifiers := sc.getRuntimeNotifiers(runtimeID)
	// Ensure latest block is set.
	notifiers.Lock()
	notifiers.lastBlock = annBlk.Block
	notifiers.lastBlockHeight = height
	notifiers.Unlock()

	sc.allBlockNotifier.Broadcast(annBlk.Block)
	notifiers.blockNotifier.Broadcast(annBlk)
	tr.height = height

	return nil
}

func (sc *serviceClient) fetchFinalizedRound(
	ctx context.Context,
	height int64,
	runtimeID common.Namespace,
	round *uint64,
) (time.Duration, time.Duration, *api.AnnotatedBlock, *api.RoundResults, error) {
	var readLatestBlock, readLastRounds time.Duration
	start := time.Now()
	blk, err := sc.getLatestBlockAt(ctx, runtimeID, height)
	readLatestBlock = time.Since(start)
	if err != nil {
		sc.logger.Error("failed to fetch latest block",
			"err", err,
			"height", height,
			"runtime_id", runtimeID,
		)
		return 0, 0, nil, nil, fmt.Errorf("roothash: failed to fetch latest block: %w", err)
	}
	if round != nil && blk.Header.Round != *round {
		sc.logger.Error("finalized event/query round mismatch",
			"block_round", blk.Header.Round,
			"event_round", *round,
		)
		return 0, 0, nil, nil, fmt.Errorf("roothash: finalized event/query round mismatch")
	}
	start = time.Now()

	roundResults, err := sc.GetLastRoundResults(ctx, &api.RuntimeRequest{
		RuntimeID: runtimeID,
		Height:    height,
	})
	readLastRounds = time.Since(start)
	if err != nil {
		sc.logger.Error("failed to fetch round results",
			"err", err,
			"height", height,
			"runtime_id", runtimeID,
		)
		return 0, 0, nil, nil, fmt.Errorf("roothash: failed to fetch round results: %w", err)
	}

	annBlk := &api.AnnotatedBlock{
		Height: height,
		Block:  blk,
	}
	return readLatestBlock, readLastRounds, annBlk, roundResults, nil
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
					errs = errors.Join(errs, fmt.Errorf("roothash: corrupt ExecutorComitted event: %w", err))
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

type pruneHandler struct {
	sync.Mutex

	logger *logging.Logger

	trackedRuntimes []api.BlockHistory
}

func (ph *pruneHandler) trackRuntime(bh api.BlockHistory) {
	ph.Lock()
	defer ph.Unlock()

	ph.trackedRuntimes = append(ph.trackedRuntimes, bh)
}

// Implements api.StatePruneHandler.
func (ph *pruneHandler) Prune(version uint64) error {
	ph.Lock()
	defer ph.Unlock()

	for _, bh := range ph.trackedRuntimes {
		lastHeight, err := bh.LastConsensusHeight()
		if err != nil {
			ph.logger.Warn("failed to fetch last consensus height for tracked runtime",
				"err", err,
				"runtime_id", bh.RuntimeID(),
			)
			// We can't be sure if it is ok to prune this version, so prevent pruning to be safe.
			return fmt.Errorf("failed to fetch last consensus height for tracked runtime: %w", err)
		}

		if version > uint64(lastHeight) {
			return fmt.Errorf("version %d not yet indexed for %s", version, bh.RuntimeID())
		}
	}
	return nil
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

	// Register a consensus state prune handler to make sure that we don't prune blocks that haven't
	// yet been indexed by the roothash backend.
	sc.pruneHandler = &pruneHandler{
		logger: logging.GetLogger("cometbft/roothash/prunehandler"),
	}
	backend.Pruner().RegisterHandler(sc.pruneHandler)

	return &sc, nil
}

func init() {
	crash.RegisterCrashPoints(
		crashPointBlockBeforeIndex,
	)
}
