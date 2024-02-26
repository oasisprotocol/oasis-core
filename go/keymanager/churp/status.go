package churp

import (
	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

const (
	// HandoffsDisabled is a handoff interval that disables handoffs.
	HandoffsDisabled = beacon.EpochInvalid
)

const (
	// EccNistP384 represents the NIST P-384 elliptic curve group.
	EccNistP384 uint8 = iota
)

// ConsensusParameters are the key manager CHURP consensus parameters.
type ConsensusParameters struct {
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`
}

// Identity uniquely identifies a CHURP instance.
type Identity struct {
	// ID is a unique CHURP identifier within the key manager runtime.
	ID uint8 `json:"id"`

	// RuntimeID is the identifier of the key manager runtime.
	RuntimeID common.Namespace `json:"runtime_id"`
}

// Status represents the current state of a CHURP instance.
type Status struct {
	Identity

	// GroupID is the identifier of a group used for verifiable secret sharing
	// and key derivation.
	GroupID uint8 `json:"group_id"`

	// Threshold is the minimum number of distinct shares required
	// to reconstruct a key.
	Threshold uint8 `json:"threshold"`

	// Round counts the number of handoffs done so far.
	//
	// The first round is a special round called the dealer round, in which
	// nodes do not reshare shares but construct the secret and shares instead.
	Round uint64 `json:"round"`

	// NextHandoff defines the epoch in which the next handoff will occur.
	//
	// If an insufficient number of applications is received, the next handoff
	// will be delayed by one epoch.
	NextHandoff beacon.EpochTime `json:"next_handoff"`

	// HandoffInterval is the time interval in epochs between handoffs.
	//
	// A zero value disables handoffs.
	HandoffInterval beacon.EpochTime `json:"handoff_interval"`

	// Policy is a signed SGX access control policy.
	Policy SignedPolicySGX `json:"policy"`

	// Committee is a vector of nodes holding a share of the secret
	// in the current round.
	//
	// A client needs to obtain at least a threshold number of key shares
	// from the nodes in this vector to construct the key.
	Committee []signature.PublicKey `json:"committee,omitempty"`

	// Applications is a map of nodes that wish to form the new committee.
	//
	// Candidates are expected to generate a random bivariate polynomial,
	// construct a verification matrix, compute its checksum, and submit
	// an application one epoch in advance of the next scheduled handoff.
	// Subsequently, upon the arrival of the handoff epoch, nodes must execute
	// the handoff protocol and confirm the reconstruction of its share.
	Applications map[signature.PublicKey]Application `json:"applications,omitempty"`

	// Checksum is the hash of the merged verification matrix.
	//
	// The first candidate to confirm share reconstruction is the source
	// of truth for the checksum. All other candidates need to confirm
	// with the same checksum; otherwise, the applications will be annulled,
	// and the nodes will need to apply for the new committee again.
	Checksum *hash.Hash `json:"checksum,omitempty"`
}

// HandoffsDisabled returns true if and only if handoffs are disabled.
func (s *Status) HandoffsDisabled() bool {
	return s.HandoffInterval == HandoffsDisabled
}

// Application represents a node's application to form a new committee.
type Application struct {
	// Checksum is the hash of the random verification matrix.
	//
	// In all handoffs, except in the dealer phase, the verification matrix
	// needs to be zero-hole.
	Checksum hash.Hash `json:"checksum"`

	// Reconstructed is true if and only if the node verified all matrices
	// and successfully reconstructed its share during the handoff.
	Reconstructed bool `json:"reconstructed"`
}
