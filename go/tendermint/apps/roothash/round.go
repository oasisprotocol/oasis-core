package roothash

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
	"github.com/oasislabs/ekiden/go/tendermint/abci"
)

var (
	commitmentSignatureContext = []byte("EkCommit")

	errStillWaiting      = errors.New("tendermint/roothash: still waiting for commits")
	errInsufficientVotes = errors.New("tendermint/roothash: insufficient votes to finalize discrepancy resolution round")

	_ cbor.Marshaler   = (*commitment)(nil)
	_ cbor.Unmarshaler = (*commitment)(nil)
	_ cbor.Marshaler   = (*round)(nil)
	_ cbor.Unmarshaler = (*round)(nil)
)

type errDiscrepancyDetected hash.Hash

func (e errDiscrepancyDetected) Error() string {
	return fmt.Sprintf("tendermint/roothash: discrepancy detected: %v", hash.Hash(e))
}

type commitment struct {
	signature.Signed

	Header *api.Header `codec:"header"`
}

func (c *commitment) fromCommitment(commit *api.Commitment) error {
	return c.UnmarshalCBOR(commit.Data)
}

func (c *commitment) toCommitment() *api.Commitment {
	return &api.Commitment{Data: c.MarshalCBOR()}
}

func (c *commitment) open() error {
	var header api.Header
	if err := c.Signed.Open(commitmentSignatureContext, &header); err != nil {
		return errors.New("tendermint/roothash: commitment has invalid signature")
	}
	c.Header = &header

	return nil
}

type state uint

const (
	stateWaitingCommitments state = iota
	stateDiscrepancyWaitingCommitments
)

type roundState struct {
	Committee        *scheduler.Committee                          `codec:"committee"`
	ComputationGroup map[signature.MapKey]*scheduler.CommitteeNode `codec:"computation_group"`
	Commitments      map[signature.MapKey]*commitment              `codec:"commitments"`
	CurrentBlock     *api.Block                                    `codec:"current_block"`
	State            state                                         `codec:"state"`
}

func (s *roundState) ensureValidWorker(id signature.MapKey) error {
	node, ok := s.ComputationGroup[id]
	if !ok {
		return errors.New("tendermint/roothash: node not part of computation group")
	}

	switch s.State {
	case stateWaitingCommitments:
		ok = node.Role == scheduler.Worker || node.Role == scheduler.Leader
	case stateDiscrepancyWaitingCommitments:
		ok = node.Role == scheduler.BackupWorker
	}
	if !ok {
		return errors.New("tendermint/roothash: node has incorrect role for current state")
	}

	return nil
}

func (s *roundState) reset() {
	s.Commitments = make(map[signature.MapKey]*commitment)
	s.State = stateWaitingCommitments
}

type round struct {
	RoundState *roundState `codec:"round_state"`
	DidTimeout bool        `codec:"did_timeout"`
}

func (r *round) reset() {
	r.RoundState.reset()
	r.DidTimeout = false
}

func (r *round) addCommitment(store storage.Backend, commitment *commitment) error {
	id := commitment.Signature.PublicKey.ToMapKey()

	// Check node identity/role.
	if err := r.RoundState.ensureValidWorker(id); err != nil {
		return err
	}

	// Check the commitment signature and de-serialize into header.
	if err := commitment.open(); err != nil {
		return err
	}
	header := commitment.Header

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
	if err := r.ensureHashesInStorage(store, header); err != nil {
		return err
	}

	r.RoundState.Commitments[id] = commitment

	return nil
}

func (r *round) tryFinalize(ctx *abci.Context, contract *contract.Contract) (*api.Block, error) {
	var err error

	// Ensure that the required number of commitments are present.
	if err = r.checkCommitments(contract); err != nil {
		return nil, err
	}

	r.DidTimeout = false

	// Attempt to finalize, based on the state.
	var finalizeFn func() (*api.Header, error)
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
	block := new(api.Block)
	block.Header = *header
	block.Header.Timestamp = uint64(ctx.Now().Unix())
	block.ComputationGroup = r.RoundState.Committee.Members
	for _, node := range r.RoundState.Committee.Members {
		id := node.PublicKey.ToMapKey()
		commit, ok := r.RoundState.Commitments[id]
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

	for id, node := range r.RoundState.ComputationGroup {
		if node.Role != scheduler.Worker && node.Role != scheduler.Leader {
			continue
		}

		commit, ok := r.RoundState.Commitments[id]
		if !ok {
			continue
		}

		if header == nil {
			header = commit.Header
		}
		if !header.Equal(commit.Header) {
			discrepancyDetected = true
		}
	}

	if discrepancyDetected {
		// Activate the backup workers.
		r.RoundState.State = stateDiscrepancyWaitingCommitments
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
	for id, node := range r.RoundState.ComputationGroup {
		if node.Role != scheduler.BackupWorker {
			continue
		}
		backupNodes++

		commit, ok := r.RoundState.Commitments[id]
		if !ok {
			continue
		}

		k := commit.Header.EncodedHash()
		if ent, ok := votes[k]; !ok {
			votes[k] = &voteEnt{
				header: commit.Header,
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

func (r *round) ensureHashesInStorage(store storage.Backend, header *api.Header) error {
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
		if _, err := store.Get(context.Background(), key); err != nil {
			return fmt.Errorf("tendermint/roothash: failed to retreive %v: %v", h.descr, err)
		}
	}

	return nil
}

func (r *round) checkCommitments(contract *contract.Contract) error {
	wantPrimary := r.RoundState.State == stateWaitingCommitments

	var commits, required int
	for id, node := range r.RoundState.ComputationGroup {
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
		if _, ok := r.RoundState.Commitments[id]; ok {
			commits++
		}
	}

	// While a timer is running, all nodes are required to answer.
	//
	// After the timeout has elapsed, a limited number of stragglers
	// are allowed.
	if r.DidTimeout {
		required -= int(contract.ReplicaAllowedStragglers)
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

func newRound(committee *scheduler.Committee, block *api.Block) *round {
	if committee.Kind != scheduler.Compute {
		panic("tendermint/roothash: non-compute committee passed to round ctor")
	}

	computationGroup := make(map[signature.MapKey]*scheduler.CommitteeNode)
	for _, node := range committee.Members {
		computationGroup[node.PublicKey.ToMapKey()] = node
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
