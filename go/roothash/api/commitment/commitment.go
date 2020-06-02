package commitment

import (
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
)

// OpenCommitment is a verified roothash commitment.
type OpenCommitment interface {
	// MostlyEqual returns true if the commitment is mostly equal to another
	// specified commitment as per discrepancy detection criteria.
	//
	// The caller MUST guarantee that the passed commitment is of the same
	// type.
	MostlyEqual(OpenCommitment) bool

	// ToVote returns a hash that represents a vote for this commitment as
	// per discrepancy resolution criteria.
	ToVote() hash.Hash

	// ToDDResult returns a commitment-specific result after discrepancy
	// detection.
	ToDDResult() interface{}
}
