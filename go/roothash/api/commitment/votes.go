package commitment

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

// SchedulerCommitment is a structure for storing scheduler commitment and its votes.
type SchedulerCommitment struct {
	// Commitment is a verified scheduler's Commitment for which votes are being collected.
	Commitment *ExecutorCommitment `json:"commitment,omitempty"`

	// Votes is a map that collects Votes from nodes in the form of commitment hashes.
	//
	// A nil vote indicates a failure.
	Votes map[signature.PublicKey]*hash.Hash `json:"votes,omitempty"`
}

// Add converts the provided executor commitment into a vote and adds it to the votes map.
//
// It returns an error if the node has already submitted a vote.
func (sc *SchedulerCommitment) Add(ec *ExecutorCommitment) error {
	// Allow only one vote.
	if _, ok := sc.Votes[ec.NodeID]; ok {
		return ErrAlreadyCommitted
	}

	// Convert commitment to a vote.
	var vote *hash.Hash
	if !ec.IsIndicatingFailure() {
		v := ec.ToVote()
		vote = &v
	}

	// Store vote.
	if sc.Votes == nil {
		sc.Votes = make(map[signature.PublicKey]*hash.Hash)
	}
	sc.Votes[ec.NodeID] = vote

	// Store scheduler's commitment.
	if ec.NodeID.Equal(ec.Header.SchedulerID) {
		sc.Commitment = ec
	}

	return nil
}
