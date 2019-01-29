// Package memory provides the in-memory (centralized) root hash implementation.
package memory

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
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

type commitCmd struct {
	commitment *commitment.Commitment
	errCh      chan error
}

type runtimeState struct {
	sync.RWMutex

	logger   *logging.Logger
	storage  storage.Backend
	registry registry.Backend

	runtime *registry.Runtime
	round   *round
	timer   *time.Timer
	blocks  []*block.Block

	cmdCh         chan *commitCmd
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

func (s *runtimeState) onNewCommittee(committee *scheduler.Committee) {
	// If the committee is the "same", ignore this.
	//
	// TODO: Use a better check to allow for things like rescheduling.
	if s.round != nil && s.round.roundState.committee.ValidFor == committee.ValidFor {
		s.logger.Debug("worker: duplicate committee or reschedule, ignoring",
			"epoch", committee.ValidFor,
		)
		return
	}

	// Transition the round.
	blk, err := s.getLatestBlockImpl()
	if err != nil {
		panic(err) // Will never happen, but just in case.
	}

	blockNr, _ := blk.Header.Round.ToU64()

	s.logger.Debug("worker: new committee, transitioning round",
		"epoch", committee.ValidFor,
		"round", blockNr,
	)

	if !s.timer.Stop() {
		<-s.timer.C
	}
	s.timer.Reset(infiniteTimeout)

	s.round = newRound(s.storage, s.runtime, committee, blk)

	// Emit an empty epoch transition block in the new round. This is required so that
	// the clients can be sure what state is final when an epoch transition occurs.
	s.emitEmptyBlock(blk, block.EpochTransition)

	// Update the runtime.
	rtID := s.runtime.ID
	if s.runtime, err = s.registry.GetRuntime(context.Background(), s.runtime.ID); err != nil {
		s.logger.Error("worker: new committee, failed to update runtime",
			"err", err,
			"runtime", rtID,
		)
		panic(err)
	}
}

func (s *runtimeState) emitEmptyBlock(blk *block.Block, hdrType block.HeaderType) {
	blk = block.NewEmptyBlock(blk, uint64(time.Now().Unix()), hdrType)
	s.round.populateFinalizedBlock(blk)
	s.rootHash.allBlockNotifier.Broadcast(blk)

	s.Lock()
	defer s.Unlock()

	s.blockNotifier.Broadcast(blk)
	s.blocks = append(s.blocks, blk)
}

func (s *runtimeState) tryFinalize(forced bool) { // nolint: gocyclo
	var rearmTimer bool
	defer func() {
		// Note: Unlike the Rust code, this pushes back the timer
		// each time forward progress is made.

		if !forced && !s.timer.Stop() {
			<-s.timer.C
		}

		switch rearmTimer {
		case true: // (Re-)arm timer.
			s.logger.Debug("worker: (re-)arming round timeout")
			s.timer.Reset(s.rootHash.roundTimeout)
		case false: // Disarm timer.
			s.logger.Debug("worker: disarming round timeout")
			s.timer.Reset(infiniteTimeout)
		}
	}()

	latestBlock, _ := s.getLatestBlockImpl()
	blockNr, _ := latestBlock.Header.Round.ToU64()

	state := s.round.roundState.state

	blk, err := s.round.tryFinalize()
	switch err {
	case nil:
		// Add the new block to the block chain.
		s.logger.Debug("worker: finalized round",
			"round", blockNr,
		)

		s.rootHash.allBlockNotifier.Broadcast(blk)

		s.Lock()
		defer s.Unlock()

		s.blockNotifier.Broadcast(blk)
		s.blocks = append(s.blocks, blk)
		return
	case errStillWaiting:
		if forced {
			if state == stateDiscrepancyWaitingCommitments {
				// This was a forced finalization call due to timeout,
				// and the round was in the discrepancy state.  Give up.
				//
				// I'm 99% sure the Rust code can livelock since it
				// doesn't handle this.
				s.logger.Error("worker: failed to finalize discrepancy committee on timeout",
					"round", blockNr,
					"num_commitments", len(s.round.roundState.commitments),
				)
				break
			}

			// This is the fast path and the round timer expired.
			//
			// Transition to the discrepancy state so the backup workers
			// process the round, assuming that it is possible to do so.
			s.logger.Error("worker: failed to finalize committee on timeout",
				"round", blockNr,
				"num_commitments", len(s.round.roundState.commitments),
			)
			err = s.round.forceBackupTransition()
			break
		}

		s.logger.Debug("worker: insufficient commitments for finality, waiting",
			"round", blockNr,
			"num_commitments", len(s.round.roundState.commitments),
		)

		rearmTimer = true
		return
	default:
	}

	if dErr, ok := (err).(errDiscrepancyDetected); ok {
		inputHash := hash.Hash(dErr)

		s.logger.Warn("worker: discrepancy detected",
			"round", blockNr,
			"input_hash", inputHash,
		)

		s.eventNotifier.Broadcast(&api.Event{
			DiscrepancyDetected: &api.DiscrepancyDetectedEvent{
				BatchHash:   &inputHash,
				BlockHeader: &latestBlock.Header,
			},
		})

		// Re-arm the timer.  The rust code waits till the first discrepancy
		// commit to do this, but there is 0 guarantee that said commit will
		// come.
		rearmTimer = true
		return
	}

	// Something else went wrong, emit empty error block.
	s.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	s.emitEmptyBlock(latestBlock, block.RoundFailed)
}

func (s *runtimeState) worker(sched scheduler.Backend) { // nolint: gocyclo
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
			if committee.Kind != scheduler.Compute {
				continue
			}
			s.onNewCommittee(committee)
		case cmd, ok := <-s.cmdCh:
			if !ok {
				return
			}
			if s.round == nil {
				s.logger.Error("worker: commit recevied when no round in progress",
					"err", errNoRound,
				)
				cmd.errCh <- errNoRound
				continue
			}

			latestBlock, err := s.getLatestBlockImpl()
			if err != nil {
				s.logger.Error("worker: BUG: Failed to get latest block",
					"err", err,
				)
				cmd.errCh <- err
				continue
			}
			blockNr, _ := latestBlock.Header.Round.ToU64()

			// If the round was finalized, transition.
			if s.round.roundState.currentBlock != latestBlock {
				s.logger.Debug("worker: round was finalized, transitioning round",
					"round", blockNr,
				)

				s.round = newRound(s.storage, s.runtime, s.round.roundState.committee, latestBlock)
			}

			// Add the commitment.
			if err = s.round.addCommitment(cmd.commitment); err != nil {
				s.logger.Error("worker: failed to add commitment to round",
					"err", err,
					"round", blockNr,
				)
				cmd.errCh <- err
				continue
			}

			// Propagate the commit success to the committer.
			cmd.errCh <- nil

			s.tryFinalize(false)
		case <-s.timer.C:
			s.logger.Warn("worker: round timeout expired, forcing finalization")
			s.round.didTimeout = true
			s.tryFinalize(true)
		}
	}
}

type memoryRootHash struct {
	sync.Mutex

	logger    *logging.Logger
	scheduler scheduler.Backend
	storage   storage.Backend
	registry  registry.Backend

	runtimes map[signature.MapKey]*runtimeState

	// If a runtime with one of these IDs would be initialized,
	// start with the given block as the genesis block. For other
	// runtimes, generate an "empty" genesis block.
	genesisBlocks map[signature.MapKey]*block.Block

	allBlockNotifier *pubsub.Broker

	closeCh   chan struct{}
	closedCh  chan struct{}
	closedWg  sync.WaitGroup
	closeOnce sync.Once

	roundTimeout time.Duration
}

func (r *memoryRootHash) GetLatestBlock(ctx context.Context, id signature.PublicKey) (*block.Block, error) {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return nil, err
	}

	return s.getLatestBlock()
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

func (r *memoryRootHash) WatchBlocksSince(id signature.PublicKey, round block.Round) (<-chan *block.Block, *pubsub.Subscription, error) {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return nil, nil, err
	}

	startBlock, err := round.ToU64()
	if err != nil {
		return nil, nil, err
	}

	var replayOk bool
	sub := s.blockNotifier.SubscribeEx(func(ch *channels.InfiniteChannel) {
		s.Lock()
		defer s.Unlock()

		// Replay from startBlock up to current.
		for _, block := range s.blocks {
			nr, _ := block.Header.Round.ToU64()
			if nr >= startBlock {
				replayOk = true
				ch.In() <- block
			}
		}
	})
	if !replayOk {
		sub.Close()
		return nil, nil, errNoSuchBlocks
	}

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

func (r *memoryRootHash) Commit(ctx context.Context, id signature.PublicKey, commit *api.OpaqueCommitment) error {
	s, err := r.getRuntimeState(id)
	if err != nil {
		return err
	}

	var c commitment.Commitment
	if err = c.FromOpaqueCommitment(commit); err != nil {
		return err
	}

	cmd := &commitCmd{
		commitment: &c,
		errCh:      make(chan error, 1),
	}
	s.cmdCh <- cmd

	select {
	case <-ctx.Done():
		return errors.New("roothash/memory: canceled by context")
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

func (r *memoryRootHash) Cleanup() {
	r.closeOnce.Do(func() {
		close(r.closeCh)
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

func (r *memoryRootHash) onRuntimeRegistration(runtime *registry.Runtime) error {
	k := runtime.ID.ToMapKey()

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
		storage:       r.storage,
		registry:      r.registry,
		runtime:       runtime,
		blocks:        append([]*block.Block{}, genesisBlock),
		cmdCh:         make(chan *commitCmd), // XXX: Use an unbound channel?
		blockNotifier: pubsub.NewBroker(false),
		eventNotifier: pubsub.NewBroker(false),
		rootHash:      r,
	}

	r.closedWg.Add(1)
	go s.worker(r.scheduler)

	r.runtimes[k] = s

	r.logger.Debug("worker: runtime registered",
		"runtime_id", runtime.ID,
	)

	return nil
}

func (r *memoryRootHash) worker() {
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

			_ = r.onRuntimeRegistration(runtime)
		case <-r.closeCh:
			return
		}
	}
}

// New constructs a new in-memory (centralized) root hash backend.
func New(
	scheduler scheduler.Backend,
	storage storage.Backend,
	registry registry.Backend,
	genesisBlocks map[signature.MapKey]*block.Block,
	roundTimeout time.Duration,
) api.Backend {
	r := &memoryRootHash{
		logger:           logging.GetLogger("roothash/memory"),
		scheduler:        scheduler,
		storage:          storage,
		registry:         registry,
		runtimes:         make(map[signature.MapKey]*runtimeState),
		genesisBlocks:    genesisBlocks,
		allBlockNotifier: pubsub.NewBroker(false),
		closeCh:          make(chan struct{}),
		closedCh:         make(chan struct{}),
		roundTimeout:     roundTimeout,
	}
	go r.worker()

	return r
}
