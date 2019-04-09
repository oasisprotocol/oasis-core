package roothash

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	errStillWaiting      = errors.New("tendermint/roothash: still waiting for commits")
	errInsufficientVotes = errors.New("tendermint/roothash: insufficient votes to finalize discrepancy resolution round")
	errRakSigInvalid     = errors.New("tendermint/roothash: batch RAK signature invalid")

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

type nodeInfo struct {
	CommitteeNode *scheduler.CommitteeNode `codec:"committee_node"`
	Runtime       *node.Runtime            `codec:"runtime"`
}

type roundState struct {
	Committee        *scheduler.Committee                            `codec:"committee"`
	ComputationGroup map[signature.MapKey]nodeInfo                   `codec:"computation_group"`
	Commitments      map[signature.MapKey]*commitment.OpenCommitment `codec:"commitments"`
	CurrentBlock     *block.Block                                    `codec:"current_block"`
	State            state                                           `codec:"state"`
}

func (s *roundState) ensureValidWorker(id signature.MapKey) (scheduler.Role, error) {
	ni, ok := s.ComputationGroup[id]
	if !ok {
		return scheduler.Invalid, errors.New("tendermint/roothash: node not part of computation group")
	}

	switch s.State {
	case stateWaitingCommitments:
		ok = ni.CommitteeNode.Role == scheduler.Worker || ni.CommitteeNode.Role == scheduler.Leader
	case stateDiscrepancyWaitingCommitments:
		ok = ni.CommitteeNode.Role == scheduler.BackupWorker
	case stateFinalized:
		return scheduler.Invalid, errors.New("tendermint/roothash: round is already finalized, can't commit")
	}
	if !ok {
		return scheduler.Invalid, errors.New("tendermint/roothash: node has incorrect role for current state")
	}

	return ni.CommitteeNode.Role, nil
}

func (s *roundState) reset() {
	if s.Commitments == nil || len(s.Commitments) > 0 {
		s.Commitments = make(map[signature.MapKey]*commitment.OpenCommitment)
	}
	s.State = stateWaitingCommitments
}

type round struct {
	RoundState *roundState `codec:"round_state"`
	DidTimeout bool        `codec:"did_timeout"`
}

func (r *round) addCommitment(ctx context.Context, commitment *commitment.Commitment, runtime *registry.Runtime) error {
	id := commitment.Signature.PublicKey.ToMapKey()

	// Check node identity/role.
	role, err := r.RoundState.ensureValidWorker(id)
	if err != nil {
		return err
	}

	// Check the commitment signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return err
	}
	message := openCom.Message
	header := &message.Header
	if runtime.TEEHardware != node.TEEHardwareInvalid {
		rak := r.RoundState.ComputationGroup[id].Runtime.Capabilities.TEE.RAK
		batchSigMessage := block.BatchSigMessage{
			InputHash:  header.InputHash,
			OutputHash: header.OutputHash,
			StateRoot:  header.StateRoot,
		}
		batchSigMessage.PreviousBlock.FromFull(r.RoundState.CurrentBlock)
		if !rak.Verify(api.RakSigContext, cbor.Marshal(batchSigMessage), message.RakSig[:]) {
			return errRakSigInvalid
		}
	}

	// Ensure the node did not already submit a commitment.
	if _, ok := r.RoundState.Commitments[id]; ok {
		return errors.New("tendermint/roothash: node already sent commitment")
	}

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&r.RoundState.CurrentBlock.Header) {
		return errors.New("tendermint/roothash: submitted header is not based on previous block")
	}

	// Check if the block is based on the same committee.
	committeeHash := r.RoundState.Committee.EncodedMembersHash()
	if !header.GroupHash.Equal(&committeeHash) {
		return errors.New("tendermint/roothash: submitted header is not for the current committee")
	}

	// Check if the header refers to hashes in storage.
	if role == scheduler.Leader || role == scheduler.BackupWorker {
		if err := r.ensureHashesInStorage(ctx, header); err != nil {
			return err
		}
	}

	r.RoundState.Commitments[id] = openCom

	return nil
}

func (r *round) populateFinalizedBlock(block *block.Block) {
	block.Header.GroupHash.From(r.RoundState.Committee.Members)
	var blockCommitments []*api.OpaqueCommitment
	for _, node := range r.RoundState.Committee.Members {
		id := node.PublicKey.ToMapKey()
		commit, ok := r.RoundState.Commitments[id]
		if !ok {
			continue
		}
		blockCommitments = append(blockCommitments, commit.ToOpaqueCommitment())
	}
	block.Header.CommitmentsHash.From(blockCommitments)
}

func (r *round) tryFinalize(ctx *abci.Context, runtime *registry.Runtime) (*block.Block, error) {
	var err error

	// Caller is responsible for enforcing this.
	if r.RoundState.State == stateFinalized {
		panic("tendermint/roothash: tryFinalize when already finalized")
	}

	// Ensure that the required number of commitments are present.
	if err = r.checkCommitments(runtime); err != nil {
		return nil, err
	}

	r.DidTimeout = false

	// Attempt to finalize, based on the state.
	var finalizeFn func() (*block.Header, error)
	switch r.RoundState.State {
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

	r.RoundState.State = stateFinalized
	r.RoundState.Commitments = make(map[signature.MapKey]*commitment.OpenCommitment)

	return block, nil
}

func (r *round) forceBackupTransition() error {
	if r.RoundState.State != stateWaitingCommitments {
		panic("tendermint/roothash: unexpected state for backup transition")
	}

	// Find the Leader's batch hash based on the existing commitments.
	for id, ni := range r.RoundState.ComputationGroup {
		if ni.CommitteeNode.Role != scheduler.Leader {
			continue
		}

		commit, ok := r.RoundState.Commitments[id]
		if !ok {
			break
		}

		r.RoundState.State = stateDiscrepancyWaitingCommitments
		return errDiscrepancyDetected(commit.Message.Header.InputHash)
	}

	return fmt.Errorf("tendermint/roothash: no input hash available for backup transition")
}

func (r *round) tryFinalizeFast() (*block.Header, error) {
	var header, leaderHeader *block.Header
	var discrepancyDetected bool

	for id, ni := range r.RoundState.ComputationGroup {
		if ni.CommitteeNode.Role != scheduler.Worker && ni.CommitteeNode.Role != scheduler.Leader {
			continue
		}

		commit, ok := r.RoundState.Commitments[id]
		if !ok {
			continue
		}

		if header == nil {
			header = &commit.Message.Header
		}
		if ni.CommitteeNode.Role == scheduler.Leader {
			leaderHeader = &commit.Message.Header
		}
		if !header.MostlyEqual(&commit.Message.Header) {
			discrepancyDetected = true
		}
	}

	if leaderHeader == nil || discrepancyDetected {
		// Activate the backup workers.
		return nil, r.forceBackupTransition()
	}

	return leaderHeader, nil
}

func (r *round) tryFinalizeDiscrepancy() (*block.Header, error) {
	type voteEnt struct {
		header *block.Header
		tally  int
	}

	votes := make(map[hash.Hash]*voteEnt)
	var backupNodes int
	for id, ni := range r.RoundState.ComputationGroup {
		if ni.CommitteeNode.Role != scheduler.BackupWorker {
			continue
		}
		backupNodes++

		commit, ok := r.RoundState.Commitments[id]
		if !ok {
			continue
		}

		k := commit.Message.Header.EncodedHash()
		if ent, ok := votes[k]; !ok {
			votes[k] = &voteEnt{
				header: &commit.Message.Header,
				tally:  1,
			}
		} else {
			ent.tally++
		}
	}

	minVotes := (backupNodes / 2) + 1
	for _, ent := range votes {
		if ent.tally >= minVotes {
			return ent.header, nil
		}
	}

	return nil, errInsufficientVotes
}

func (r *round) ensureHashesInStorage(ctx context.Context, header *block.Header) error {
	// TODO: Ensure that the public key that signs the storage receipt
	// is the expected one.
	return header.VerifyStorageReceiptSignature()
}

func (r *round) checkCommitments(runtime *registry.Runtime) error {
	wantPrimary := r.RoundState.State == stateWaitingCommitments

	var commits, required int
	for id, ni := range r.RoundState.ComputationGroup {
		var check bool
		switch wantPrimary {
		case true:
			check = ni.CommitteeNode.Role == scheduler.Worker || ni.CommitteeNode.Role == scheduler.Leader
		case false:
			check = ni.CommitteeNode.Role == scheduler.BackupWorker
		}
		if !check {
			continue
		}

		required++
		if _, ok := r.RoundState.Commitments[id]; ok {
			commits++
		}
	}

	// While a timer is running, all nodes are required to answer.
	//
	// After the timeout has elapsed, a limited number of stragglers
	// are allowed.
	if r.DidTimeout {
		required -= int(runtime.ReplicaAllowedStragglers)
	}

	if commits < required {
		return errStillWaiting
	}

	return nil
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (r *round) MarshalCBOR() []byte {
	return cbor.Marshal(r)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (r *round) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, r)
}

func newRound(committee *scheduler.Committee, computationGroup map[signature.MapKey]nodeInfo, block *block.Block) *round {
	if committee.Kind != scheduler.Compute {
		panic("tendermint/roothash: non-compute committee passed to round ctor")
	}

	state := &roundState{
		Committee:        committee,
		ComputationGroup: computationGroup,
		CurrentBlock:     block,
	}
	state.reset()

	return &round{
		RoundState: state,
	}
}
