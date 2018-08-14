package memory

import (
	"errors"
	"fmt"

	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/contract"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/roothash/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

var (
	commitmentSignatureContext = []byte("EkCommit")

	errStillWaiting      = errors.New("roothash/memory: still waiting for commits")
	errInsufficientVotes = errors.New("roothash/memory: insufficient votes to finalize discrepancy resolution round")

	_ api.Backend      = (*memoryRootHash)(nil)
	_ cbor.Marshaler   = (*commitment)(nil)
	_ cbor.Unmarshaler = (*commitment)(nil)
)

type errDiscrepancyDetected hash.Hash

func (e errDiscrepancyDetected) Error() string {
	return fmt.Sprintf("roothash/memory: discrepancy detected: %v", hash.Hash(e))
}

type commitment struct {
	Raw       []byte
	Signature *signature.Signature

	header *api.Header
}

func (c *commitment) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, c)
}

func (c *commitment) MarshalCBOR() []byte {
	return cbor.Marshal(c)
}

func (c *commitment) fromCommitment(commit *api.Commitment) error {
	return c.UnmarshalCBOR(commit.Data)
}

func (c *commitment) toCommitment() *api.Commitment {
	return &api.Commitment{Data: c.MarshalCBOR()}
}

func (c *commitment) open() error {
	if !c.Signature.Verify(commitmentSignatureContext, c.Raw) {
		return errors.New("roothash/memory: commitment has invalid signature")
	}

	header := new(api.Header)
	if err := header.UnmarshalCBOR(c.Raw); err != nil {
		return err
	}
	c.header = header

	return nil
}

type state uint

const (
	stateWaitingCommitments state = iota
	stateDiscrepancyWaitingCommitments
)

type roundState struct {
	contract         *contract.Contract
	committee        *scheduler.Committee
	computationGroup map[signature.MapKey]*scheduler.CommitteeNode
	commitments      map[signature.MapKey]*commitment
	currentBlock     *api.Block
	state            state
}

func (s *roundState) ensureValidWorker(id signature.MapKey) error {
	node, ok := s.computationGroup[id]
	if !ok {
		return errors.New("roothash/memory: node not part of computation group")
	}

	switch s.state {
	case stateWaitingCommitments:
		ok = node.Role == scheduler.Worker
	case stateDiscrepancyWaitingCommitments:
		ok = node.Role == scheduler.BackupWorker
	}
	if !ok {
		return errors.New("roothash/memory: node has incorrect role for current state")
	}

	return nil
}

func (s *roundState) reset() {
	s.commitments = make(map[signature.MapKey]*commitment)
	s.state = stateWaitingCommitments
}

type round struct {
	roundState *roundState
	storage    storage.Backend
	didTimeout bool
}

func (r *round) reset() {
	r.roundState.reset()
	r.didTimeout = false
}

func (r *round) addCommitment(commitment *commitment) error {
	id := commitment.Signature.PublicKey.ToMapKey()

	// Check node identity/role.
	if err := r.roundState.ensureValidWorker(id); err != nil {
		return err
	}

	// Check the commitment signature and de-serialize into header.
	if err := commitment.open(); err != nil {
		return err
	}
	header := commitment.header

	// Ensure the node did not already submit a commitment.
	if _, ok := r.roundState.commitments[id]; ok {
		return errors.New("roothash/memory: node already sent commitment")
	}

	// Check if the block is based on the previous block.
	if !header.IsParentOf(&r.roundState.currentBlock.Header) {
		return errors.New("roothash/memory: submitted header is not based on previous block")
	}

	// Check if the header refers to hashes in storage.
	if err := r.ensureHashesInStorage(header); err != nil {
		return err
	}

	r.roundState.commitments[id] = commitment

	return nil
}

func (r *round) tryFinalize() (*api.Block, error) {
	var err error

	// Ensure that the required number of commitments are present.
	if err = r.checkCommitments(); err != nil {
		return nil, err
	}

	r.didTimeout = false

	// Attempt to finalize, based on the state.
	var finalizeFn func() (*api.Header, error)
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
	block := r.roundState.currentBlock.NewParentOf(header)
	block.ComputationGroup = r.roundState.committee.Members
	for _, node := range r.roundState.committee.Members {
		id := node.PublicKey.ToMapKey()
		commit, ok := r.roundState.commitments[id]
		if !ok {
			continue
		}
		block.Commitments = append(block.Commitments, commit.toCommitment())
	}
	block.Update()

	return block, nil
}

func (r *round) tryFinalizeFast() (*api.Header, error) {
	var header *api.Header
	var discrepancyDetected bool

	for id, node := range r.roundState.computationGroup {
		if node.Role != scheduler.Worker && node.Role != scheduler.Leader {
			continue
		}

		commit, ok := r.roundState.commitments[id]
		if !ok {
			continue
		}

		if header == nil {
			header = commit.header
		}
		if !header.Equal(commit.header) {
			discrepancyDetected = true
		}
	}

	if discrepancyDetected {
		// Activate the backup workers.
		r.roundState.state = stateDiscrepancyWaitingCommitments
		return nil, errDiscrepancyDetected(header.InputHash)
	}

	return header, nil
}

func (r *round) tryFinalizeDiscrepancy() (*api.Header, error) {
	type voteEnt struct {
		header *api.Header
		tally  int
	}

	votes := make(map[hash.Hash]*voteEnt)
	var backupNodes int
	for id, node := range r.roundState.computationGroup {
		if node.Role != scheduler.BackupWorker {
			continue
		}
		backupNodes++

		commit, ok := r.roundState.commitments[id]
		if !ok {
			continue
		}

		k := commit.header.EncodedHash()
		if ent, ok := votes[k]; !ok {
			votes[k] = &voteEnt{
				header: commit.header,
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

func (r *round) ensureHashesInStorage(header *api.Header) error {
	for _, h := range []struct {
		hash  hash.Hash
		descr string
	}{
		{header.InputHash, "inputs"},
		{header.OutputHash, "outputs"},
		{header.StateRoot, "state root"}, // TODO: Check against the log.
	} {
		if h.hash.IsEmpty() {
			continue
		}

		var key storage.Key
		copy(key[:], h.hash[:])
		if _, err := r.storage.Get(context.Background(), key); err != nil {
			return fmt.Errorf("roothash/memory: failed to retreive %v: %v", h.descr, err)
		}
	}

	return nil
}

func (r *round) checkCommitments() error {
	wantPrimary := r.roundState.state == stateWaitingCommitments

	var commits, required int
	for id, node := range r.roundState.computationGroup {
		var check bool
		switch wantPrimary {
		case true:
			check = node.Role == scheduler.Worker || node.Role == scheduler.Leader
		case false:
			check = node.Role == scheduler.BackupWorker
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
		required -= int(r.roundState.contract.ReplicaAllowedStragglers)
	}

	if commits < required {
		return errStillWaiting
	}

	return nil
}

func newRound(storage storage.Backend, contract *contract.Contract, committee *scheduler.Committee, block *api.Block) *round {
	if committee.Kind != scheduler.Compute {
		panic("roothash/memory: non-compute committee passed to round ctor")
	}

	computationGroup := make(map[signature.MapKey]*scheduler.CommitteeNode)
	for _, node := range committee.Members {
		computationGroup[node.PublicKey.ToMapKey()] = node
	}

	state := &roundState{
		contract:         contract,
		committee:        committee,
		computationGroup: computationGroup,
		currentBlock:     block,
	}
	state.reset()

	return &round{
		roundState: state,
		storage:    storage,
	}
}
