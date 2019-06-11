// Package memory provides the in-memory (centralized) root hash implementation.
package memory

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/eapache/channels"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

const (
	// BackendName is the name of this implementation.
	BackendName = "memory"

	infiniteTimeout = time.Duration(math.MaxInt64)
)

var (
	errRuntimeExists = errors.New("roothash/memory: runtime already exists")
	errNoSuchRuntime = errors.New("roothash/memory: no such runtime")
	errNoSuchBlocks  = errors.New("roothash/memory: no such block(s) exist for runtime")
	errNoRound       = errors.New("roothash/memory: no round in progress")

	_ api.Backend              = (*memoryRootHash)(nil)
	_ (api.MetricsMonitorable) = (*memoryRootHash)(nil)
)

type computeCommitCmd struct {
	commitments []commitment.ComputeCommitment
	errCh       chan error
}

type mergeCommitCmd struct {
	commitments []commitment.MergeCommitment
	errCh       chan error
}

type runtimeState struct {
	sync.RWMutex

	logger   *logging.Logger
	registry registry.Backend

	runtime *registry.Runtime
	round   *round
	timer   *time.Timer
	blocks  []*block.Block

	cmdCh         chan interface{}
	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker

	rootHash *memoryRootHash
}

func (s *runtimeState) getLatestBlock() (*block.Block, error) {
	s.RLock()
	defer s.RUnlock()

	return s.getLatestBlockImpl()
}

func (s *runtimeState) getLatestBlockImpl() (*block.Block, error) {
	nBlocks := len(s.blocks)
	if nBlocks == 0 {
		return nil, errNoSuchBlocks
	}

	return s.blocks[nBlocks-1], nil
}

func (s *runtimeState) onNewCommittees(ctx context.Context, committees []*scheduler.Committee) {
	var computeCommittee, mergeCommittee *scheduler.Committee
	for _, c := range committees {
		switch c.Kind {
		case scheduler.KindCompute:
			computeCommittee = c
		case scheduler.KindMerge:
			mergeCommittee = c
		default:
			// Skip other types of committees.
		}
	}
	if computeCommittee == nil || mergeCommittee == nil {
		panic("roothash/memory: missing committees")
	}

	// If the committee is the "same", ignore this.
	//
	// TODO: Use a better check to allow for things like rescheduling.
	if s.round != nil && s.round.mergePool.Committee.ValidFor == mergeCommittee.ValidFor {
		s.logger.Debug("worker: duplicate committee or reschedule, ignoring",
			"epoch", mergeCommittee.ValidFor,
		)
		return
	}

	// Transition the round.
	blk, err := s.getLatestBlockImpl()
	if err != nil {
		panic(err) // Will never happen, but just in case.
	}

	blockNr := blk.Header.Round

	s.logger.Debug("worker: new committee, transitioning round",
		"epoch", mergeCommittee.ValidFor,
		"round", blockNr,
	)

	if !s.timer.Stop() {
		<-s.timer.C
	}
	s.timer.Reset(infiniteTimeout)

	// Retrieve nodes for their runtime-specific information.
	nodes, err := s.rootHash.registry.GetNodes(ctx)
	if err != nil {
		panic(err)
	}

	// TODO: Support multiple compute committees (#1775).
	computeNodeInfo := make(map[signature.MapKey]commitment.NodeInfo)
	for idx, committeeNode := range computeCommittee.Members {
		computeNodeInfo[committeeNode.PublicKey.ToMapKey()] = commitment.NodeInfo{
			CommitteeNode: idx,
		}
	}

	mergeNodeInfo := make(map[signature.MapKey]commitment.NodeInfo)
	for idx, committeeNode := range mergeCommittee.Members {
		mergeNodeInfo[committeeNode.PublicKey.ToMapKey()] = commitment.NodeInfo{
			CommitteeNode: idx,
		}
	}

	for _, node := range nodes {
		ni, ok := computeNodeInfo[node.ID.ToMapKey()]
		if !ok {
			continue
		}
		for _, r := range node.Runtimes {
			if !r.ID.Equal(s.runtime.ID) {
				continue
			}
			ni.Runtime = r
			break
		}
	}

	// Update the runtime.
	rtID := s.runtime.ID
	if s.runtime, err = s.registry.GetRuntime(ctx, s.runtime.ID); err != nil {
		s.logger.Error("worker: new committee, failed to update runtime",
			"err", err,
			"runtime", rtID,
		)
		panic(err)
	}

	s.round = newRound(
		ctx,
		computeCommittee,
		computeNodeInfo,
		mergeCommittee,
		mergeNodeInfo,
		blk,
		s.runtime,
	)

	// Emit an empty epoch transition block in the new round. This is required so that
	// the clients can be sure what state is final when an epoch transition occurs.
	s.emitEmptyBlock(blk, block.EpochTransition)
}

func (s *runtimeState) emitEmptyBlock(blk *block.Block, hdrType block.HeaderType) {
	blk = block.NewEmptyBlock(blk, uint64(time.Now().Unix()), hdrType)
	s.rootHash.allBlockNotifier.Broadcast(blk)

	s.Lock()
	defer s.Unlock()

	s.blockNotifier.Broadcast(blk)
	s.blocks = append(s.blocks, blk)
}

func (s *runtimeState) updateTimer(now time.Time, forced bool) {
	if !forced && !s.timer.Stop() {
		<-s.timer.C
	}

	nextTimeout := s.round.getNextTimeout()
	if nextTimeout.IsZero() {
		// Disarm timer.
		s.logger.Debug("worker: disarming round timeout")
		s.timer.Reset(infiniteTimeout)
	} else {
		// (Re-)arm timer.
		s.logger.Debug("worker: (re-)arming round timeout")
		s.timer.Reset(nextTimeout.Sub(now))
	}
}

func (s *runtimeState) tryFinalizeCompute(pool *commitment.Pool, forced bool) {
	now := time.Now()
	defer s.updateTimer(now, forced)

	latestBlock, _ := s.getLatestBlockImpl()
	blockNr := latestBlock.Header.Round
	committeeID := pool.GetCommitteeID()

	// TODO: Separate timeout for compute/merge.
	_, err := pool.TryFinalize(now, s.rootHash.roundTimeout, forced)
	switch err {
	case nil:
		// No error -- there is no discrepancy. But only the merge committee
		// can make progress even if we have all compute commitments.

		// TODO: Check if we need to punish the merge committee.

		s.logger.Warn("worker: no compute discrepancy, but only merge committee can make progress",
			"round", blockNr,
			"committee_id", committeeID,
		)

		if !forced {
			// If this was not a timeout, we give the merge committee some
			// more time to merge, otherwise we fail the round.
			return
		}
	case commitment.ErrStillWaiting:
		// Need more commits.
		return
	case commitment.ErrDiscrepancyDetected:
		s.logger.Warn("worker: compute discrepancy detected",
			"round", blockNr,
			"committee_id", committeeID,
		)

		s.eventNotifier.Broadcast(&api.Event{
			ComputeDiscrepancyDetected: &api.ComputeDiscrepancyDetectedEvent{
				CommitteeID: committeeID,
			},
		})
		return
	default:
	}

	// Something else went wrong, emit empty error block. Note that we need
	// to abort everything even if only one committee failed to finalize as
	// there is otherwise no way to make progress as merge committees will
	// refuse to merge if there are discrepancies.
	s.logger.Error("worker: round failed during compute finalization",
		"round", blockNr,
		"err", err,
	)

	s.emitEmptyBlock(latestBlock, block.RoundFailed)
}

func (s *runtimeState) tryFinalizeMerge(forced bool) { // nolint: gocyclo
	now := time.Now()
	defer s.updateTimer(now, forced)

	latestBlock, _ := s.getLatestBlockImpl()
	blockNr := latestBlock.Header.Round

	header, err := s.round.mergePool.TryFinalize(now, s.rootHash.roundTimeout, forced)
	switch err {
	case nil:
		// Add the new block to the block chain.
		s.logger.Debug("worker: finalized round",
			"round", blockNr,
		)

		// Generate the final block.
		blk := new(block.Block)
		blk.Header = *header
		blk.Header.Timestamp = uint64(now.Unix())

		s.rootHash.allBlockNotifier.Broadcast(blk)
		s.blockNotifier.Broadcast(blk)

		s.Lock()
		defer s.Unlock()

		s.blocks = append(s.blocks, blk)
		return
	case commitment.ErrStillWaiting:
		// Need more commits.
		s.logger.Debug("worker: insufficient commitments for finality, waiting",
			"round", blockNr,
		)

		return
	case commitment.ErrDiscrepancyDetected:
		s.logger.Warn("worker: merge discrepancy detected",
			"round", blockNr,
		)

		s.eventNotifier.Broadcast(&api.Event{
			MergeDiscrepancyDetected: &api.MergeDiscrepancyDetectedEvent{},
		})
		return
	default:
	}

	// Something else went wrong, emit empty error block.
	s.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	s.emitEmptyBlock(latestBlock, block.RoundFailed)
}

func (s *runtimeState) worker(ctx context.Context, sched scheduler.Backend) { // nolint: gocyclo
	defer s.rootHash.closedWg.Done()

	schedCh, sub := sched.WatchCommittees()
	defer sub.Close()

	s.timer = time.NewTimer(infiniteTimeout)
	defer func() {
		if !s.timer.Stop() {
			<-s.timer.C
		}
		s.timer = nil
	}()

OUTER:
	for {
		select {
		case committee, ok := <-schedCh:
			if !ok {
				s.logger.Debug("worker: terminating, scheduler disappeared")
				return
			}

			// Ignore unrelated committees.
			if !committee.RuntimeID.Equal(s.runtime.ID) {
				continue
			}
			if committee.Kind != scheduler.KindCompute {
				continue
			}

			committees, err := sched.GetCommittees(ctx, s.runtime.ID)
			if err != nil {
				s.logger.Error("worker: failed to get committees",
					"err", err,
				)
				continue
			}
			s.onNewCommittees(ctx, committees)
		case c, ok := <-s.cmdCh:
			if !ok {
				return
			}

			var errCh chan error
			switch cmd := c.(type) {
			case *mergeCommitCmd:
				errCh = cmd.errCh
			case *computeCommitCmd:
				errCh = cmd.errCh
			default:
				panic("worker: unsupported command type")
			}

			if s.round == nil {
				s.logger.Error("worker: commit recevied when no round in progress",
					"err", errNoRound,
				)
				errCh <- errNoRound
				continue
			}

			latestBlock, err := s.getLatestBlockImpl()
			if err != nil {
				s.logger.Error("worker: BUG: Failed to get latest block",
					"err", err,
				)
				errCh <- err
				continue
			}
			blockNr := latestBlock.Header.Round

			// If the round was finalized, transition.
			if s.round.currentBlock != latestBlock {
				s.logger.Debug("worker: round was finalized, transitioning round",
					"round", blockNr,
				)

				s.round.transition(latestBlock)
			}

			// Add the commitments.
			switch cmd := c.(type) {
			case *mergeCommitCmd:
				// Merge commits.
				for _, commit := range cmd.commitments {
					if err = s.round.addMergeCommitment(&commit); err != nil {
						s.logger.Error("worker: failed to add merge commitment to round",
							"err", err,
							"round", blockNr,
						)
						errCh <- err
						continue OUTER
					}
				}

				// Propagate the commit success to the committer.
				errCh <- nil

				s.tryFinalizeMerge(false)
			case *computeCommitCmd:
				// Compute commits.
				pools := make(map[*commitment.Pool]bool)
				for _, commit := range cmd.commitments {
					var pool *commitment.Pool
					if pool, err = s.round.addComputeCommitment(&commit); err != nil {
						s.logger.Error("worker: failed to add compute commitment to round",
							"err", err,
							"round", blockNr,
						)
						errCh <- err
						continue OUTER
					}

					pools[pool] = true
				}

				// Propagate the commit success to the committer.
				errCh <- nil

				for pool := range pools {
					s.tryFinalizeCompute(pool, false)
				}
			}
		case <-s.timer.C:
			now := time.Now()
			s.logger.Warn("worker: round timeout expired, forcing finalization")

			if s.round.mergePool.IsTimeout(now) {
				s.tryFinalizeMerge(true)
			}
			for _, pool := range s.round.computePool.GetTimeoutCommittees(now) {
				s.tryFinalizeCompute(pool, true)
			}
		}
	}
}

type memoryRootHash struct {
	sync.Mutex

	logger    *logging.Logger
	scheduler scheduler.Backend
	registry  registry.Backend

	runtimes map[signature.MapKey]*runtimeState

	// If a runtime with one of these IDs would be initialized,
	// start with the given block as the genesis block. For other
	// runtimes, generate an "empty" genesis block.
	genesisBlocks map[signature.MapKey]*block.Block

	allBlockNotifier *pubsub.Broker
	pruneNotifier    *pubsub.Broker

	closedCh  chan struct{}
	closedWg  sync.WaitGroup
	closeOnce sync.Once

	roundTimeout time.Duration
}

func (r *memoryRootHash) Info() api.Info {
	return api.Info{
		ComputeRoundTimeout: r.roundTimeout,
		MergeRoundTimeout:   r.roundTimeout,
	}
}

func (r *memoryRootHash) GetLatestBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return nil, err
	}

	return s.getLatestBlock()
}

func (r *memoryRootHash) GetBlock(ctx context.Context, id signature.PublicKey, round uint64) (*block.Block, error) {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return nil, err
	}

	s.Lock()
	defer s.Unlock()

	blk := s.blocks[round]
	if blk == nil {
		return nil, api.ErrNotFound
	}

	if blk.Header.Round != round {
		panic("roothash: inconsistent state")
	}

	return blk, nil
}

func (r *memoryRootHash) WatchBlocks(id signature.PublicKey) (<-chan *block.Block, *pubsub.Subscription, error) {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return nil, nil, err
	}

	sub := s.blockNotifier.SubscribeEx(func(ch *channels.InfiniteChannel) {
		// Replay the latest block if it exists.  This isn't handled by
		// the Broker because the same notifier is used to handle
		// WatchBlocksSince.
		if block, err := s.getLatestBlock(); err == nil {
			ch.In() <- block
		}
	})
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *memoryRootHash) WatchEvents(id signature.PublicKey) (<-chan *api.Event, *pubsub.Subscription, error) {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return nil, nil, err
	}

	sub := s.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *memoryRootHash) MergeCommit(ctx context.Context, id signature.PublicKey, commits []commitment.MergeCommitment) error {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return err
	}

	cmd := &mergeCommitCmd{
		commitments: commits,
		errCh:       make(chan error, 1),
	}
	s.cmdCh <- cmd

	select {
	case <-ctx.Done():
		return context.Canceled
	case err = <-cmd.errCh:
	}

	return err
}

func (r *memoryRootHash) ComputeCommit(ctx context.Context, id signature.PublicKey, commits []commitment.ComputeCommitment) error {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return err
	}

	cmd := &computeCommitCmd{
		commitments: commits,
		errCh:       make(chan error, 1),
	}
	s.cmdCh <- cmd

	select {
	case <-ctx.Done():
		return context.Canceled
	case err = <-cmd.errCh:
	}

	return err
}

func (r *memoryRootHash) WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription) {
	sub := r.allBlockNotifier.Subscribe()
	ch := make(chan *block.Block)
	sub.Unwrap(ch)

	return ch, sub
}

func (r *memoryRootHash) WatchPrunedBlocks() (<-chan *api.PrunedBlock, *pubsub.Subscription, error) {
	sub := r.pruneNotifier.Subscribe()
	ch := make(chan *api.PrunedBlock)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *memoryRootHash) Cleanup() {
	r.closeOnce.Do(func() {
		<-r.closedCh // Need to ensure no Add() in progress for the Wait().
		r.closedWg.Wait()
	})
}

func (r *memoryRootHash) getRuntimeState(id signature.PublicKey) (*runtimeState, error) {
	k := id.ToMapKey()

	r.Lock()
	defer r.Unlock()

	s, ok := r.runtimes[k]
	if !ok {
		return nil, errNoSuchRuntime
	}

	return s, nil
}

func (r *memoryRootHash) onRuntimeRegistration(ctx context.Context, runtime *registry.Runtime) error {
	k := runtime.ID.ToMapKey()

	if !runtime.IsCompute() {
		r.logger.Warn("worker: ignoring non-compute runtime",
			"runtime", runtime.ID,
		)
		return nil
	}

	r.Lock()
	defer r.Unlock()

	if _, ok := r.runtimes[k]; ok {
		return errRuntimeExists
	}

	// Create genesis block.
	genesisBlock := r.genesisBlocks[k]
	if genesisBlock == nil {
		now := time.Now().Unix()
		genesisBlock = block.NewGenesisBlock(runtime.ID, uint64(now))
	}

	s := &runtimeState{
		logger:        r.logger.With("runtime_id", runtime.ID),
		registry:      r.registry,
		runtime:       runtime,
		blocks:        append([]*block.Block{}, genesisBlock),
		cmdCh:         make(chan interface{}), // XXX: Use an unbound channel?
		blockNotifier: pubsub.NewBroker(false),
		eventNotifier: pubsub.NewBroker(false),
		rootHash:      r,
	}

	r.closedWg.Add(1)
	go s.worker(ctx, r.scheduler)

	r.runtimes[k] = s

	r.logger.Debug("worker: runtime registered",
		"runtime_id", runtime.ID,
	)

	return nil
}

func (r *memoryRootHash) worker(ctx context.Context) {
	defer func() {
		close(r.closedCh)
		for _, v := range r.runtimes {
			close(v.cmdCh)
		}
	}()

	regCh, regSub := r.registry.WatchRuntimes()
	defer regSub.Close()

	for {
		select {
		case runtime, ok := <-regCh:
			if !ok {
				return
			}

			_ = r.onRuntimeRegistration(ctx, runtime)
		case <-ctx.Done():
			return
		}
	}
}

// New constructs a new in-memory (centralized) root hash backend.
func New(
	ctx context.Context,
	scheduler scheduler.Backend,
	registry registry.Backend,
	genesisBlocks map[signature.MapKey]*block.Block,
	roundTimeout time.Duration,
) api.Backend {
	r := &memoryRootHash{
		logger:           logging.GetLogger("roothash/memory"),
		scheduler:        scheduler,
		registry:         registry,
		runtimes:         make(map[signature.MapKey]*runtimeState),
		genesisBlocks:    genesisBlocks,
		allBlockNotifier: pubsub.NewBroker(false),
		pruneNotifier:    pubsub.NewBroker(false),
		closedCh:         make(chan struct{}),
		roundTimeout:     roundTimeout,
	}
	go r.worker(ctx)

	return r
}
