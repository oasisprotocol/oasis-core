package memory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

type errDiscrepancyDetected hash.Hash

func (e errDiscrepancyDetected) Error() string {
	return fmt.Sprintf("roothash/memory: discrepancy detected: %v", hash.Hash(e))
}

type state uint

const (
	stateWaitingCommitments state = iota
	stateDiscrepancyWaitingCommitments
)

type round struct {
	ctx          context.Context
	pool         *commitment.Pool
	currentBlock *block.Block
	state        state
	didTimeout   bool
}

func (r *round) ensureValidWorker(n *scheduler.CommitteeNode) error {
	var ok bool
	switch r.state {
	case stateWaitingCommitments:
		ok = n.Role == scheduler.Worker || n.Role == scheduler.Leader
	case stateDiscrepancyWaitingCommitments:
		ok = n.Role == scheduler.BackupWorker
	}
	if !ok {
		return errors.New("roothash/memory: node has incorrect role for current state")
	}

	return nil
}

func (r *round) reset() {
	r.pool.ResetCommitments()
	r.state = stateWaitingCommitments
}

func (r *round) addCommitment(commitment *commitment.ComputeCommitment) error {
	return r.pool.AddComputeCommitment(r.currentBlock, commitment)
}

func (r *round) populateFinalizedBlock(block *block.Block) {
	block.Header.GroupHash.From(r.pool.Committee.Members)
	var blockCommitments []*api.OpaqueCommitment
	for _, node := range r.pool.Committee.Members {
		id := node.PublicKey.ToMapKey()
		c, ok := r.pool.Commitments[id]
		if !ok {
			continue
		}
		commit := c.(commitment.OpenComputeCommitment)
		blockCommitments = append(blockCommitments, commit.ToOpaqueCommitment())
	}
	block.Header.CommitmentsHash.From(blockCommitments)
}

func (r *round) tryFinalize() (*block.Block, error) {
	var err error

	// Ensure that the required number of commitments are present.
	if err = r.checkCommitments(); err != nil {
		return nil, err
	}

	r.didTimeout = false

	// Attempt to finalize, based on the state.
	var finalizeFn func() (*block.Header, error)
	switch r.state {
	case stateWaitingCommitments:
		finalizeFn = r.tryFinalizeFast
	case stateDiscrepancyWaitingCommitments:
		finalizeFn = r.tryFinalizeDiscrepancy
	}

	header, err := finalizeFn()
	if err != nil {
		return nil, err
	}

	// Generate the final block.
	block := new(block.Block)
	block.Header = *header
	block.Header.Timestamp = uint64(time.Now().Unix())
	r.populateFinalizedBlock(block)

	return block, nil
}

func (r *round) forceBackupTransition() error {
	if r.state != stateWaitingCommitments {
		panic("roothash/memory: unexpected state for backup transition")
	}

	// Find the Leader's batch hash based on the existing commitments.
	for _, n := range r.pool.Committee.Members {
		if n.Role != scheduler.Leader {
			continue
		}

		c, ok := r.pool.Commitments[n.PublicKey.ToMapKey()]
		if !ok {
			break
		}

		commit := c.(commitment.OpenComputeCommitment)
		r.state = stateDiscrepancyWaitingCommitments
		return errDiscrepancyDetected(commit.Body.Header.IORoot)
	}

	return fmt.Errorf("roothash/memory: no I/O root available for backup transition")
}

func (r *round) tryFinalizeFast() (*block.Header, error) {
	leaderHeader, err := r.pool.DetectComputeDiscrepancy()
	if err != nil {
		// Activate the backup workers.
		return nil, r.forceBackupTransition()
	}

	return leaderHeader, nil
}

func (r *round) tryFinalizeDiscrepancy() (*block.Header, error) {
	return r.pool.ResolveComputeDiscrepancy()
}

func (r *round) checkCommitments() error {
	return r.pool.CheckEnoughComputeCommitments(r.state == stateWaitingCommitments, r.didTimeout)
}

func newRound(
	ctx context.Context,
	committee *scheduler.Committee,
	nodeInfo map[signature.MapKey]commitment.NodeInfo,
	block *block.Block,
	runtime *registry.Runtime,
) *round {
	if committee.Kind != scheduler.Compute {
		panic("roothash/memory: non-compute committee passed to round ctor")
	}

	r := &round{
		ctx:          ctx,
		currentBlock: block,
		pool: &commitment.Pool{
			Runtime:   runtime,
			Committee: committee,
			NodeInfo:  nodeInfo,
		},
	}
	r.pool.NodeVerifyPolicy = r.ensureValidWorker
	// TODO: Actually check that the storage receipt was signed by a storage node.
	r.pool.StorageVerifyPolicy = func(signature.PublicKey) error { return nil }
	r.reset()

	return r
}
