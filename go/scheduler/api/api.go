// Package api defines the committee scheduler API.
package api

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/pubsub"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
)

// Role is the role a given node plays in a committee.
type Role uint8

// TODO: Rename these to include the Role prefix.
const (
	// Invalid is an invalid role (should never appear on the wire).
	Invalid Role = 0

	// Worker indicates the node is a worker.
	Worker Role = 1

	// BackupWorker indicates the node is a backup worker.
	BackupWorker Role = 2

	// Leader indicates the node is a group leader.
	Leader Role = 3
)

// RewardFactorEpochElectionAny is the factor for a reward
// distributed per epoch to entities that have any node considered
// in any election.
var RewardFactorEpochElectionAny *quantity.Quantity

// String returns a string representation of a Role.
func (r Role) String() string {
	switch r {
	case Invalid:
		return "invalid"
	case Worker:
		return "worker"
	case BackupWorker:
		return "backup worker"
	case Leader:
		return "leader"
	default:
		return fmt.Sprintf("[unknown role: %d]", r)
	}
}

// CommitteeNode is a node participating in a committee.
type CommitteeNode struct {
	// Role is the node's role in a committee.
	Role Role `json:"role"`

	// PublicKey is the node's public key.
	PublicKey signature.PublicKey `json:"public_key"`
}

// CommitteeKind is the functionality a committee exists to provide.
type CommitteeKind uint8

const (
	// KindCompute is a compute committee.
	KindCompute CommitteeKind = 0

	// KindStorage is a storage committee.
	KindStorage CommitteeKind = 1

	// KindTransactionScheduler is a transaction scheduler committee.
	KindTransactionScheduler CommitteeKind = 2

	// KindMerge is a merge committee.
	KindMerge CommitteeKind = 3

	// MaxCommitteeKind is a dummy value used for iterating all committee kinds.
	MaxCommitteeKind = 4
)

// NeedsLeader returns if committee kind needs leader role.
func (k CommitteeKind) NeedsLeader() bool {
	switch k {
	case KindCompute:
		return false
	case KindMerge:
		return false
	case KindStorage:
		return false
	default:
		return true
	}
}

// String returns a string representation of a CommitteeKind.
func (k CommitteeKind) String() string {
	switch k {
	case KindCompute:
		return "compute"
	case KindStorage:
		return "storage"
	case KindTransactionScheduler:
		return "txn_scheduler"
	case KindMerge:
		return "merge"
	default:
		return fmt.Sprintf("[unknown kind: %d]", k)
	}
}

// Committee is a per-runtime (instance) committee.
type Committee struct {
	// Kind is the functionality a committee exists to provide.
	Kind CommitteeKind `json:"kind"`

	// Members is the committee members.
	Members []*CommitteeNode `json:"members"`

	// RuntimeID is the runtime ID that this committee is for.
	RuntimeID signature.PublicKey `json:"runtime_id"`

	// ValidFor is the epoch for which the committee is valid.
	ValidFor epochtime.EpochTime `json:"valid_for"`
}

// String returns a string representation of a Committee.
func (c Committee) String() string {
	members := make([]string, len(c.Members))
	for i, m := range c.Members {
		members[i] = fmt.Sprintf("%+v", m)
	}
	return fmt.Sprintf("&{Kind:%v Members:[%v] RuntimeID:%v ValidFor:%v}", c.Kind, strings.Join(members, " "), c.RuntimeID, c.ValidFor)
}

// EncodedMembersHash returns the encoded cryptographic hash of the committee members.
func (c *Committee) EncodedMembersHash() hash.Hash {
	var hh hash.Hash

	hh.From(c.Members)

	return hh
}

// Validator is a consensus validator.
type Validator struct {
	// ID is the validator consensus (NOT oasis) identifier.
	ID signature.PublicKey `json:"id"`

	// VotingPower is the validator's consensus voting power.
	VotingPower int64 `json:"voting_power"`
}

// Backend is a scheduler implementation.
type Backend interface {
	// GetValidators returns the vector of consensus validators for
	// a given epoch.
	GetValidators(context.Context, int64) ([]*Validator, error)

	// GetCommittees returns the vector of committees for a given
	// runtime ID, at the specified block height, and optional callback
	// for querying the beacon for a given epoch/block height.
	//
	// Iff the callback is nil, `beacon.GetBlockBeacon` will be used.
	GetCommittees(context.Context, signature.PublicKey, int64) ([]*Committee, error)

	// WatchCommittees returns a channel that produces a stream of
	// Committee.
	//
	// Upon subscription, all committees for the current epoch will
	// be sent immediately.
	WatchCommittees() (<-chan *Committee, *pubsub.Subscription)

	// ToGenesis returns the genesis state at specified block height.
	ToGenesis(context.Context, int64) (*Genesis, error)

	// Cleanup cleans up the scheduler backend.
	Cleanup()
}

// Genesis is the committee scheduler genesis state.
type Genesis struct {
	// Parameters are the scheduler consensus parameters.
	Parameters ConsensusParameters `json:"params"`
}

// ConsensusParameters are the scheduler consensus parameters.
type ConsensusParameters struct {
	// MinValidators is the minimum number of validators that MUST be
	// present in elected validator sets.
	MinValidators int `json:"min_validators"`

	// MaxValidators is the maximum number of validators that MAY be
	// present in elected validator sets.
	MaxValidators int `json:"max_validators"`

	// MaxValidatorsPerEntity is the maximum number of validators that
	// may be elected per entity in a single validator set.
	MaxValidatorsPerEntity int `json:"max_validators_per_entity"`

	// DebugBypassStake is true iff the scheduler should bypass all of
	// the staking related checks and operations.
	DebugBypassStake bool `json:"debug_bypass_stake"`

	// DebugStaticValidators is true iff the scheduler should use
	// a static validator set instead of electing anything.
	DebugStaticValidators bool `json:"debug_static_validators"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck() error {
	return nil
}

func init() {
	RewardFactorEpochElectionAny = quantity.NewQuantity()
	err := RewardFactorEpochElectionAny.FromBigInt(big.NewInt(1))
	if err != nil {
		panic(err)
	}
}
