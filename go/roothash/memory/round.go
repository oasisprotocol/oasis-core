package memory

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
)

var (
	errStillWaiting      = errors.New("roothash/memory: still waiting for commits")
	errInsufficientVotes = errors.New("roothash/memory: insufficient votes to finalize discrepancy resolution round")
	errRakSigInvalid     = errors.New("roothash/memory: batch RAK signature invalid")
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

type nodeInfo struct {
	committeeNode *scheduler.CommitteeNode
	runtime       *node.Runtime
}

type roundState struct {
	runtime          *registry.Runtime
	committee        *scheduler.Committee
	computationGroup map[signature.MapKey]nodeInfo
	commitments      map[signature.MapKey]*commitment.OpenCommitment
	currentBlock     *block.Block
	state            state
}

func (s *roundState) ensureValidWorker(id signature.MapKey) (scheduler.Role, error) {
	ni, ok := s.computationGroup[id]
	if !ok {
		return scheduler.Invalid, errors.New("roothash/memory: node not part of computation group")
	}

	switch s.state {
	case stateWaitingCommitments:
		ok = ni.committeeNode.Role == scheduler.Worker || ni.committeeNode.Role == scheduler.Leader
	case stateDiscrepancyWaitingCommitments:
		ok = ni.committeeNode.Role == scheduler.BackupWorker
	}
	if !ok {
		return scheduler.Invalid, errors.New("roothash/memory: node has incorrect role for current state")
	}

	return ni.committeeNode.Role, nil
}

func (s *roundState) reset() {
	s.commitments = make(map[signature.MapKey]*commitment.OpenCommitment)
	s.state = stateWaitingCommitments
}

type round struct {
	ctx        context.Context
	roundState *roundState
	didTimeout bool
}

func (r *round) addCommitment(commitment *commitment.Commitment) error {
	id := commitment.Signature.PublicKey.ToMapKey()

	// Check node identity/role.
	role, err := r.roundState.ensureValidWorker(id)
	if err != nil {
		return err
	}

	// Check the commitment signature and RAK signature and de-serialize into header.
	openCom, err := commitment.Open()
	if err != nil {
		return err
	}
	message := openCom.Message
	header := &message.Header
	if r.roundState.runtime.TEEHardware != node.TEEHardwareInvalid {
		rak := r.roundState.computationGroup[id].runtime.Capabilities.TEE.RAK
		batchSigMessage := block.BatchSigMessage{
			InputHash:  header.InputHash,
			OutputHash: header.OutputHash,
			TagsHash:   header.TagHash,
			StateRoot:  header.StateRoot,
		}
		batchSigMessage.PreviousBlock.FromFull(r.roundState.currentBlock)
		if !rak.Verify(api.RakSigContext, cbor.Marshal(batchSigMessage), message.RakSig[:]) {
			return errRakSigInvalid
		}
	}

	// Ensure the node did not already submit a commitment.
	if _, ok := r.roundState.commitments[id]; ok {
		return errors.New("roothash/memory: node already sent commitment")
	}

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&r.roundState.currentBlock.Header) {
		return errors.New("roothash/memory: submitted header is not based on previous block")
	}

	// Check if the block is based on the same committee.
	committeeHash := r.roundState.committee.EncodedMembersHash()
	if !header.GroupHash.Equal(&committeeHash) {
		return errors.New("tendermint/roothash: submitted header is not for the current committee")
	}

	// Check if the header refers to hashes in storage.
	if role == scheduler.Leader || role == scheduler.BackupWorker {
		if err := r.ensureHashesInStorage(header); err != nil {
			return err
		}
	}

	r.roundState.commitments[id] = openCom

	return nil
}

func (r *round) populateFinalizedBlock(block *block.Block) {
	block.Header.GroupHash.From(r.roundState.committee.Members)
	var blockCommitments []*api.OpaqueCommitment
	for _, node := range r.roundState.committee.Members {
		id := node.PublicKey.ToMapKey()
		commit, ok := r.roundState.commitments[id]
		if !ok {
			continue
		}
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
	switch r.roundState.state {
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
	if r.roundState.state != stateWaitingCommitments {
		panic("roothash/memory: unexpected state for backup transition")
	}

	// Find the Leader's batch hash based on the existing commitments.
	for id, ni := range r.roundState.computationGroup {
		if ni.committeeNode.Role != scheduler.Leader {
			continue
		}

		commit, ok := r.roundState.commitments[id]
		if !ok {
			break
		}

		r.roundState.state = stateDiscrepancyWaitingCommitments
		return errDiscrepancyDetected(commit.Message.Header.InputHash)
	}

	return fmt.Errorf("roothash/memory: no input hash available for backup transition")
}

func (r *round) tryFinalizeFast() (*block.Header, error) {
	var header, leaderHeader *block.Header
	var discrepancyDetected bool

	for id, ni := range r.roundState.computationGroup {
		if ni.committeeNode.Role != scheduler.Worker && ni.committeeNode.Role != scheduler.Leader {
			continue
		}

		commit, ok := r.roundState.commitments[id]
		if !ok {
			continue
		}

		if header == nil {
			header = &commit.Message.Header
		}
		if ni.committeeNode.Role == scheduler.Leader {
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
	for id, ni := range r.roundState.computationGroup {
		if ni.committeeNode.Role != scheduler.BackupWorker {
			continue
		}
		backupNodes++

		commit, ok := r.roundState.commitments[id]
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

func (r *round) ensureHashesInStorage(header *block.Header) error {
	// TODO: Ensure that the public key that signs the storage receipt
	// is the expected one.
	return header.VerifyStorageReceiptSignature()
}

func (r *round) checkCommitments() error {
	wantPrimary := r.roundState.state == stateWaitingCommitments

	var commits, required int
	for id, ni := range r.roundState.computationGroup {
		var check bool
		switch wantPrimary {
		case true:
			check = ni.committeeNode.Role == scheduler.Worker || ni.committeeNode.Role == scheduler.Leader
		case false:
			check = ni.committeeNode.Role == scheduler.BackupWorker
		}
		if !check {
			continue
		}

		required++
		if _, ok := r.roundState.commitments[id]; ok {
			commits++
		}
	}

	// While a timer is running, all nodes are required to answer.
	//
	// After the timeout has elapsed, a limited number of stragglers
	// are allowed.
	if r.didTimeout {
		required -= int(r.roundState.runtime.ReplicaAllowedStragglers)
	}

	if commits < required {
		return errStillWaiting
	}

	return nil
}

func newRound(ctx context.Context, runtime *registry.Runtime, committee *scheduler.Committee, computationGroup map[signature.MapKey]nodeInfo, block *block.Block) *round {
	if committee.Kind != scheduler.Compute {
		panic("roothash/memory: non-compute committee passed to round ctor")
	}

	state := &roundState{
		runtime:          runtime,
		committee:        committee,
		computationGroup: computationGroup,
		currentBlock:     block,
	}
	state.reset()

	return &round{
		ctx:        ctx,
		roundState: state,
	}
}
