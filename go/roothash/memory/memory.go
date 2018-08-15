// Package memory provides the in-memory (centralized) root hash implementation.
package memory

import (
	"errors"
	"math"
	"sync"
	"time"

	"github.com/eapache/channels"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

const (
	roundTimeout    = 10 * time.Second
	infiniteTimeout = time.Duration(math.MaxInt64)
)

var (
	errContractExists = errors.New("roothash/memory: contract already exists")
	errNoSuchContract = errors.New("roothash/memory: no such contract")
	errNoSuchBlocks   = errors.New("roothash/memory: no such block(s) exist for contract")
	errNoRound        = errors.New("roothash/memory: no round in progress")
)

type commitCmd struct {
	commitment *commitment
	errCh      chan error
}

type contractState struct {
	sync.RWMutex

	logger  *logging.Logger
	storage storage.Backend

	contract *contract.Contract
	round    *round
	timer    *time.Timer
	blocks   []*api.Block

	cmdCh         chan *commitCmd
	blockNotifier *pubsub.Broker
	eventNotifier *pubsub.Broker
}

func (s *contractState) getLatestBlock() (*api.Block, error) {
	s.RLock()
	defer s.RUnlock()

	return s.getLatestBlockImpl()
}

func (s *contractState) getLatestBlockImpl() (*api.Block, error) {
	nBlocks := len(s.blocks)
	if nBlocks == 0 {
		return nil, errNoSuchBlocks
	}

	return s.blocks[nBlocks-1], nil
}

func (s *contractState) onNewCommittee(committee *scheduler.Committee) {
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
	block, err := s.getLatestBlockImpl()
	if err != nil {
		panic(err) // Will never happen, but just in case.
	}

	blockNr, _ := block.Header.Round.ToU64()

	s.logger.Debug("worker: new committee, transitioning round",
		"epoch", committee.ValidFor,
		"round", blockNr,
	)

	s.round = newRound(s.storage, s.contract, committee, block)
}

func (s *contractState) tryFinalize(forced bool) { // nolint: gocyclo
	var rearmTimer bool
	defer func() {
		// Note: Unlike the Rust code, this pushes back the timer
		// each time forward progress is made.

		if !s.timer.Stop() {
			<-s.timer.C
		}

		switch rearmTimer {
		case true: // (Re-)arm timer.
			s.logger.Debug("worker: (re-)arming round timeout")
			s.timer.Reset(roundTimeout)
		case false: // Disarm timer.
			s.logger.Debug("worker: disarming round timeout")
			s.timer.Reset(infiniteTimeout)
		}
	}()

	latestBlock, _ := s.getLatestBlockImpl()
	blockNr, _ := latestBlock.Header.Round.ToU64()

	state := s.round.roundState.state

	block, err := s.round.tryFinalize()
	switch err {
	case nil:
		// Add the new block to the block chain.
		s.logger.Debug("worker: finalized round",
			"round", blockNr,
		)

		s.Lock()
		defer s.Unlock()

		s.blockNotifier.Broadcast(block)
		s.blocks = append(s.blocks, block)
		return
	case errStillWaiting:
		if forced {
			if state == stateDiscrepancyWaitingCommitments {
				// This was a forced finalization call due to timeout,
				// and the round was in the discrepancy state.  Give up.
				//
				// I'm 99% sure the Rust code can livelock since it
				// doesn't handle this.
				s.logger.Error("worker: failed to finalize discrepancy comittee on timeout",
					"round", blockNr,
				)
				break
			}

			// XXX: This is the fast path and the round timer expired.
			// This should probably transition to the backups, but the
			// Rust code doesn't appear to do this either.
		}

		s.logger.Debug("worker: insufficient commitments for finality, waiting",
			"round", blockNr,
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
			DiscrepancyDetected: &inputHash,
		})

		// Re-arm the timer.  The rust code waits till the first discrepancy
		// commit to do this, but there is 0 guarantee that said commit will
		// come.
		rearmTimer = true
		return
	}

	// Something else went wrong.
	s.logger.Error("worker: round failed",
		"round", blockNr,
		"err", err,
	)

	s.round.reset()

	s.eventNotifier.Broadcast(&api.Event{
		RoundFailed: err,
	})
}

func (s *contractState) worker(sched scheduler.Backend) { // nolint: gocyclo
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
			if !committee.Contract.ID.Equal(s.contract.ID) {
				continue
			}
			if committee.Kind != scheduler.Compute {
				continue
			}
			s.onNewCommittee(committee)
		case cmd := <-s.cmdCh:
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

				s.round = newRound(s.storage, s.contract, s.round.roundState.committee, latestBlock)
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

	contracts map[signature.MapKey]*contractState
}

func (r *memoryRootHash) GetLatestBlock(ctx context.Context, id signature.PublicKey) (*api.Block, error) {
	s, err := r.getContractState(id)
	if err != nil {
		return nil, err
	}

	return s.getLatestBlock()
}

func (r *memoryRootHash) WatchBlocks(id signature.PublicKey) (<-chan *api.Block, *pubsub.Subscription, error) {
	s, err := r.getContractState(id)
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
	ch := make(chan *api.Block)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *memoryRootHash) WatchBlocksSince(id signature.PublicKey, round api.Round) (<-chan *api.Block, *pubsub.Subscription, error) {
	s, err := r.getContractState(id)
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

	ch := make(chan *api.Block)
	sub.Unwrap(ch)

	return nil, sub, nil
}

func (r *memoryRootHash) WatchEvents(id signature.PublicKey) (<-chan *api.Event, *pubsub.Subscription, error) {
	s, err := r.getContractState(id)
	if err != nil {
		return nil, nil, err
	}

	sub := s.eventNotifier.Subscribe()
	ch := make(chan *api.Event)
	sub.Unwrap(ch)

	return ch, sub, nil
}

func (r *memoryRootHash) Commit(ctx context.Context, id signature.PublicKey, commit *api.Commitment) error {
	s, err := r.getContractState(id)
	if err != nil {
		return err
	}

	var c commitment
	if err = c.fromCommitment(commit); err != nil {
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

func (r *memoryRootHash) getContractState(id signature.PublicKey) (*contractState, error) {
	k := id.ToMapKey()

	r.Lock()
	defer r.Unlock()

	s, ok := r.contracts[k]
	if !ok {
		return nil, errNoSuchContract
	}

	return s, nil
}

func (r *memoryRootHash) onContractRegistration(contract *contract.Contract) error {
	k := contract.ID.ToMapKey()

	r.Lock()
	defer r.Unlock()

	if _, ok := r.contracts[k]; ok {
		return errContractExists
	}

	s := &contractState{
		logger:        r.logger.With("contract_id", contract.ID),
		storage:       r.storage,
		contract:      contract,
		blocks:        append([]*api.Block{}, newGenesisBlock(contract.ID)),
		cmdCh:         make(chan *commitCmd), // XXX: Use an unbound channel?
		blockNotifier: pubsub.NewBroker(false),
		eventNotifier: pubsub.NewBroker(false),
	}

	go s.worker(r.scheduler)

	r.contracts[k] = s

	return nil
}

func (r *memoryRootHash) worker(registry registry.Backend) {
	ch, sub := registry.WatchContracts()
	defer sub.Close()

	for {
		contract, ok := <-ch
		if !ok {
			break
		}

		err := r.onContractRegistration(contract)
		if err != nil {
			r.logger.Error("worker: contract registration failed",
				"err", err,
				"contract_id", contract.ID,
			)
			continue
		}

		r.logger.Debug("worker: contract registered",
			"contract_id", contract.ID,
		)
	}
}

// New constructs a new in-memory (centralized) root hash backend.
func New(scheduler scheduler.Backend, storage storage.Backend, registry registry.Backend) api.Backend {
	r := &memoryRootHash{
		logger:    logging.GetLogger("roothash/memory"),
		scheduler: scheduler,
		storage:   storage,
		contracts: make(map[signature.MapKey]*contractState),
	}
	go r.worker(registry)

	return r
}

func newGenesisBlock(id signature.PublicKey) *api.Block {
	var blk api.Block

	blk.Header.Version = 0
	_ = blk.Header.Namespace.UnmarshalBinary(id[:])
	blk.Header.InputHash.Empty()
	blk.Header.OutputHash.Empty()
	blk.Header.StateRoot.Empty()

	return &blk
}
