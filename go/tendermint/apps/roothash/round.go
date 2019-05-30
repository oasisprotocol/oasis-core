package roothash

import (
	"errors"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	_ cbor.Marshaler   = (*round)(nil)
	_ cbor.Unmarshaler = (*round)(nil)
)

type errDiscrepancyDetected hash.Hash

func (e errDiscrepancyDetected) Error() string {
	return fmt.Sprintf("tendermint/roothash: discrepancy detected: %v", hash.Hash(e))
}

type state uint

const (
	stateWaitingCommitments state = iota
	stateDiscrepancyWaitingCommitments
	stateFinalized
)

type round struct {
	Pool         *commitment.Pool `codec:"pool"`
	CurrentBlock *block.Block     `codec:"current_block"`
	State        state            `codec:"state"`
	DidTimeout   bool             `codec:"did_timeout"`
}

func (r *round) ensureValidWorker(n *scheduler.CommitteeNode) error {
	var ok bool
	switch r.State {
	case stateWaitingCommitments:
		ok = n.Role == scheduler.Worker || n.Role == scheduler.Leader
	case stateDiscrepancyWaitingCommitments:
		ok = n.Role == scheduler.BackupWorker
	case stateFinalized:
		return errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	if !ok {
		return errors.New("tendermint/roothash: node has incorrect role for current state")
	}

	return nil
}

func (r *round) reset() {
	r.Pool.ResetCommitments()
	r.State = stateWaitingCommitments
}

func (r *round) addCommitment(commitment *commitment.ComputeCommitment) error {
	// Need to set these here as they are not serialized.
	r.Pool.NodeVerifyPolicy = r.ensureValidWorker
	// TODO: Actually check that the storage receipt was signed by a storage node.
	r.Pool.StorageVerifyPolicy = func(signature.PublicKey) error { return nil }

	return r.Pool.AddComputeCommitment(r.CurrentBlock, commitment)
}

func (r *round) populateFinalizedBlock(block *block.Block) {
	block.Header.GroupHash.From(r.Pool.Committee.Members)
	var blockCommitments []*api.OpaqueCommitment
	for _, node := range r.Pool.Committee.Members {
		id := node.PublicKey.ToMapKey()
		c, ok := r.Pool.Commitments[id]
		if !ok {
			continue
		}
		commit := c.(commitment.OpenComputeCommitment)
		blockCommitments = append(blockCommitments, commit.ToOpaqueCommitment())
	}
	block.Header.CommitmentsHash.From(blockCommitments)
}

func (r *round) tryFinalize(ctx *abci.Context) (*block.Block, error) {
	var err error

	// Caller is responsible for enforcing this.
	if r.State == stateFinalized {
		panic("tendermint/roothash: tryFinalize when already finalized")
	}

	// Ensure that the required number of commitments are present.
	if err = r.checkCommitments(); err != nil {
		return nil, err
	}

	r.DidTimeout = false

	// Attempt to finalize, based on the state.
	var finalizeFn func() (*block.Header, error)
	switch r.State {
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
	block.Header.Timestamp = uint64(ctx.Now().Unix())
	r.populateFinalizedBlock(block)

	r.State = stateFinalized
	r.Pool.ResetCommitments()

	return block, nil
}

func (r *round) forceBackupTransition() error {
	if r.State != stateWaitingCommitments {
		panic("tendermint/roothash: unexpected state for backup transition")
	}

	// Find the Leader's batch hash based on the existing commitments.
	for _, n := range r.Pool.Committee.Members {
		if n.Role != scheduler.Leader {
			continue
		}

		c, ok := r.Pool.Commitments[n.PublicKey.ToMapKey()]
		if !ok {
			break
		}

		commit := c.(commitment.OpenComputeCommitment)
		r.State = stateDiscrepancyWaitingCommitments
		return errDiscrepancyDetected(commit.Body.Header.IORoot)
	}

	return fmt.Errorf("tendermint/roothash: no I/O root available for backup transition")
}

func (r *round) tryFinalizeFast() (*block.Header, error) {
	leaderHeader, err := r.Pool.DetectComputeDiscrepancy()
	if err != nil {
		// Activate the backup workers.
		return nil, r.forceBackupTransition()
	}

	return leaderHeader, nil
}

func (r *round) tryFinalizeDiscrepancy() (*block.Header, error) {
	return r.Pool.ResolveComputeDiscrepancy()
}

func (r *round) checkCommitments() error {
	return r.Pool.CheckEnoughComputeCommitments(r.State == stateWaitingCommitments, r.DidTimeout)
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *round) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (r *round) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

func newRound(
	committee *scheduler.Committee,
	nodeInfo map[signature.MapKey]commitment.NodeInfo,
	block *block.Block,
	runtime *registry.Runtime,
) *round {
	if committee.Kind != scheduler.Compute {
		panic("tendermint/roothash: non-compute committee passed to round ctor")
	}

	r := &round{
		CurrentBlock: block,
		Pool: &commitment.Pool{
			Runtime:   runtime,
			Committee: committee,
			NodeInfo:  nodeInfo,
		},
	}
	r.reset()

	return r
}
