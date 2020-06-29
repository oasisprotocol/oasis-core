// Package api defines the committee scheduler API.
package api

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
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
	// KindInvalid is an invalid committee.
	KindInvalid CommitteeKind = 0

	// KindComputeExecutor is an executor committee.
	KindComputeExecutor CommitteeKind = 1

	// KindComputeTxnScheduler is a transaction scheduler committee.
	KindComputeTxnScheduler CommitteeKind = 2

	// KindComputeMerge is a merge committee.
	KindComputeMerge CommitteeKind = 3

	// KindStorage is a storage committee.
	KindStorage CommitteeKind = 4

	// MaxCommitteeKind is a dummy value used for iterating all committee kinds.
	MaxCommitteeKind = 5
)

// NeedsLeader returns if committee kind needs leader role.
func (k CommitteeKind) NeedsLeader() (bool, error) {
	switch k {
	case KindComputeExecutor:
		return false, nil
	case KindComputeTxnScheduler:
		return true, nil
	case KindComputeMerge:
		return false, nil
	case KindStorage:
		return false, nil
	default:
		return false, fmt.Errorf("scheduler/NeedsLeader: unsupported committee kind %s", k)
	}
}

// String returns a string representation of a CommitteeKind.
func (k CommitteeKind) String() string {
	switch k {
	case KindInvalid:
		return "invalid"
	case KindComputeExecutor:
		return "executor"
	case KindComputeTxnScheduler:
		return "txn_scheduler"
	case KindComputeMerge:
		return "merge"
	case KindStorage:
		return "storage"
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
	RuntimeID common.Namespace `json:"runtime_id"`

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
	return hash.NewFrom(c.Members)
}

// BaseUnitsPerVotingPower is the ratio of base units staked to validator power.
var BaseUnitsPerVotingPower quantity.Quantity

// VotingPowerFromStake computes that by dividing by BaseUnitsPerVotingPower.
//
// NOTE: It's not that we're implementation-hiding the conversion though.
// It's just that otherwise if we accidentally skip the `IsInt64`, it would
// still appear to work, and that would be a bad thing to have in a routine
// that's written multiple times.
func VotingPowerFromStake(t *quantity.Quantity) (int64, error) {
	powerQ := t.Clone()
	if err := powerQ.Quo(&BaseUnitsPerVotingPower); err != nil {
		return 0, fmt.Errorf("quo %v / %v: %w", t, &BaseUnitsPerVotingPower, err)
	}
	if powerQ.IsZero() {
		// In some cases, especially in tests, staking is enabled but
		// registration thresholds are zero.
		// However, if they actually register with zero, give them one free vote
		// power so that Tendermint doesn't treat it as a removal.
		return 1, nil
	}
	powerBI := powerQ.ToBigInt()
	if !powerBI.IsInt64() {
		return 0, fmt.Errorf("%v is too many base units to convert to power", powerQ)
	}
	return powerBI.Int64(), nil
}

// Validator is a consensus validator.
type Validator struct {
	// ID is the validator Oasis node identifier.
	ID signature.PublicKey `json:"id"`

	// VotingPower is the validator's consensus voting power.
	VotingPower int64 `json:"voting_power"`
}

// Backend is a scheduler implementation.
type Backend interface {
	// GetValidators returns the vector of consensus validators for
	// a given epoch.
	GetValidators(ctx context.Context, height int64) ([]*Validator, error)

	// GetCommittees returns the vector of committees for a given
	// runtime ID, at the specified block height, and optional callback
	// for querying the beacon for a given epoch/block height.
	//
	// Iff the callback is nil, `beacon.GetBlockBeacon` will be used.
	GetCommittees(ctx context.Context, request *GetCommitteesRequest) ([]*Committee, error)

	// WatchCommittees returns a channel that produces a stream of
	// Committee.
	//
	// Upon subscription, all committees for the current epoch will
	// be sent immediately.
	WatchCommittees(ctx context.Context) (<-chan *Committee, pubsub.ClosableSubscription, error)

	// StateToGenesis returns the genesis state at specified block height.
	StateToGenesis(ctx context.Context, height int64) (*Genesis, error)

	// Cleanup cleans up the scheduler backend.
	Cleanup()
}

// GetCommitteesRequest is a GetCommittees request.
type GetCommitteesRequest struct {
	Height    int64            `json:"height"`
	RuntimeID common.Namespace `json:"runtime_id"`
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

	// RewardFactorEpochElectionAny is the factor for a reward
	// distributed per epoch to entities that have any node considered
	// in any election.
	RewardFactorEpochElectionAny quantity.Quantity `json:"reward_factor_epoch_election_any"`
}

// SanityCheck does basic sanity checking on the genesis state.
func (g *Genesis) SanityCheck(stakingTotalSupply *quantity.Quantity) error {
	unsafeFlags := g.Parameters.DebugBypassStake || g.Parameters.DebugStaticValidators
	if unsafeFlags && !flags.DebugDontBlameOasis() {
		return fmt.Errorf("scheduler: sanity check failed: one or more unsafe debug flags set")
	}

	if !g.Parameters.DebugBypassStake {
		supplyPower, err := VotingPowerFromStake(stakingTotalSupply)
		if err != nil {
			return fmt.Errorf("scheduler: sanity check failed: total supply would break voting power computation: %w", err)
		}
		// I've been advised not to import implementation details.
		// Instead, here's our own number that satisfies all current implementations' limits.
		maxTotalVotingPower := int64(math.MaxInt64) / 8
		if supplyPower > maxTotalVotingPower {
			return fmt.Errorf("init chain: total supply power %d exceeds Tendermint voting power limit %d", supplyPower, maxTotalVotingPower)
		}
	}

	return nil
}

func init() {
	// 16 allows for up to 1.8e19 base units to be staked.
	if err := BaseUnitsPerVotingPower.FromUint64(16); err != nil {
		panic(err)
	}
}
