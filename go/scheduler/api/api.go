// Package api defines the committee scheduler API.
package api

import (
	"context"
	"fmt"
	"strings"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/pubsub"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// ModuleName is a unique module name for the scheduler module.
const ModuleName = "scheduler"

// Role is the role a given node plays in a committee.
type Role uint8

const (
	// RoleInvalid is an invalid role (should never appear on the wire).
	RoleInvalid Role = 0
	// RoleWorker indicates the node is a worker.
	RoleWorker Role = 1
	// RoleBackupWorker indicates the node is a backup worker.
	RoleBackupWorker Role = 2

	RoleInvalidName      = "invalid"
	RoleWorkerName       = "worker"
	RoleBackupWorkerName = "backup-worker"
)

// String returns a string representation of a Role.
func (r Role) String() string {
	switch r {
	case RoleInvalid:
		return RoleInvalidName
	case RoleWorker:
		return RoleWorkerName
	case RoleBackupWorker:
		return RoleBackupWorkerName
	default:
		return fmt.Sprintf("[unknown role: %d]", r)
	}
}

// MarshalText encodes a Role into text form.
func (r Role) MarshalText() ([]byte, error) {
	switch r {
	case RoleInvalid:
		return []byte(RoleInvalidName), nil
	case RoleWorker:
		return []byte(RoleWorkerName), nil
	case RoleBackupWorker:
		return []byte(RoleBackupWorkerName), nil
	default:
		return nil, fmt.Errorf("invalid role: %d", r)
	}
}

// UnmarshalText decodes a text slice into a Role.
func (r *Role) UnmarshalText(text []byte) error {
	switch string(text) {
	case RoleWorkerName:
		*r = RoleWorker
	case RoleBackupWorkerName:
		*r = RoleBackupWorker
	default:
		return fmt.Errorf("invalid role: %s", string(text))
	}
	return nil
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

	// MaxCommitteeKind is a dummy value used for iterating all committee kinds.
	MaxCommitteeKind = 2

	KindInvalidName         = "invalid"
	KindComputeExecutorName = "executor"
)

// MarshalText encodes a CommitteeKind into text form.
func (k CommitteeKind) MarshalText() ([]byte, error) {
	switch k {
	case KindInvalid:
		return []byte(KindInvalidName), nil
	case KindComputeExecutor:
		return []byte(KindComputeExecutorName), nil
	default:
		return nil, fmt.Errorf("invalid role: %d", k)
	}
}

// UnmarshalText decodes a text slice into a CommitteeKind.
func (k *CommitteeKind) UnmarshalText(text []byte) error {
	switch string(text) {
	case KindComputeExecutorName:
		*k = KindComputeExecutor
	default:
		return fmt.Errorf("invalid role: %s", string(text))
	}
	return nil
}

// String returns a string representation of a CommitteeKind.
func (k CommitteeKind) String() string {
	switch k {
	case KindInvalid:
		return KindInvalidName
	case KindComputeExecutor:
		return KindComputeExecutorName
	default:
		return fmt.Sprintf("[unknown kind: %d]", k)
	}
}

// Committee is a per-runtime (instance) committee.
type Committee struct {
	// Kind is the functionality a committee exists to provide.
	Kind CommitteeKind `json:"kind"`

	// Members is a collection of committee members.
	//
	// The order of committee members is consistent, with workers always preceding backup workers.
	Members []*CommitteeNode `json:"members"`

	// RuntimeID is the runtime ID that this committee is for.
	RuntimeID common.Namespace `json:"runtime_id"`

	// ValidFor is the epoch for which the committee is valid.
	ValidFor beacon.EpochTime `json:"valid_for"`
}

// IsMember returns true iff the given node is a member of the committee.
func (c *Committee) IsMember(id signature.PublicKey) bool {
	for _, n := range c.Members {
		if n.PublicKey == id {
			return true
		}
	}
	return false
}

// IsWorker returns true iff the given node is a worker in the committee.
func (c *Committee) IsWorker(id signature.PublicKey) bool {
	for _, n := range c.Members {
		if n.Role != RoleWorker {
			// Workers are listed before backup workers.
			return false
		}
		if n.PublicKey == id {
			return true
		}
	}
	return false
}

// IsBackupWorker returns true iff the given node is a backup worker in the committee.
func (c *Committee) IsBackupWorker(id signature.PublicKey) bool {
	for i := len(c.Members) - 1; i >= 0; i-- {
		n := c.Members[i]
		if n.Role != RoleBackupWorker {
			// Backup workers are listed after workers.
			return false
		}
		if n.PublicKey == id {
			return true
		}
	}

	return false
}

// Scheduler returns the scheduler with the given rank in the committee's scheduling order
// for the given round.
//
// If no scheduler with the given rank is found, it returns false.
func (c *Committee) Scheduler(round uint64, rank uint64) (*CommitteeNode, bool) {
	idx, ok := c.SchedulerIdx(round, rank)
	if !ok {
		return nil, false
	}
	return c.Members[idx], true
}

// SchedulerIdx returns the index of the scheduler with the given rank in the committee's
// scheduling order for the given round.
//
// If no scheduler with the given rank is found, it returns false.
func (c *Committee) SchedulerIdx(round uint64, rank uint64) (int, bool) {
	var total uint64

	for _, n := range c.Members {
		if n.Role != RoleWorker {
			// Workers are listed before backup workers.
			break
		}
		total++
	}

	if rank >= total {
		return 0, false
	}

	idx := (rank + total - round%total) % total

	return int(idx), true
}

// SchedulerRank returns the position (index) of a node with the given public key in the committee's
// scheduling order for the given round. A lower rank indicates higher scheduling priority.
//
// If the node is not a worker in the committee and, therefore, not allowed to schedule transactions
// for the given round, it returns false.
func (c *Committee) SchedulerRank(round uint64, id signature.PublicKey) (uint64, bool) {
	var (
		total    uint64
		idx      uint64
		isWorker bool
	)

	for _, n := range c.Members {
		if n.Role != RoleWorker {
			// Workers are listed before backup workers.
			break
		}
		if n.PublicKey == id {
			isWorker = true
			idx = total
		}
		total++
	}

	if !isWorker {
		return 0, false
	}

	rank := (round + idx) % total

	return rank, true
}

// String returns a string representation of a Committee.
func (c *Committee) String() string {
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

// VotingPowerDistribution is the voting power distribution type.
type VotingPowerDistribution uint8

const (
	// VotingPowerDistributionLinear is the distribution where power is
	// linearly proportional to the stake.
	VotingPowerDistributionLinear = 0
	// VotingPowerDistributionSqrt is the distribution where power is
	// proportional to the square root of the stake.
	VotingPowerDistributionSqrt = 1
)

// VotingPowerFromStake computes the voting power from given stake based on
// the given distribution.
//
// NOTE: It's not that we're implementation-hiding the conversion though.
// It's just that otherwise if we accidentally skip the `IsInt64`, it would
// still appear to work, and that would be a bad thing to have in a routine
// that's written multiple times.
func VotingPowerFromStake(t *quantity.Quantity, distribution VotingPowerDistribution) (int64, error) {
	powerQ := t.Clone()

	if distribution == VotingPowerDistributionLinear {
		// The reason for this scaling is to ensure the voting power doesn't
		// overflow as it is limited to 63 bits.
		// With a non-linear distribution (e.g. sqrt) such scaling may not be
		// needed as sqrt(10**19) (max total supply in base units) is well
		// under the limit.
		if err := powerQ.Quo(&BaseUnitsPerVotingPower); err != nil {
			return 0, fmt.Errorf("quo %v / %v: %w", t, &BaseUnitsPerVotingPower, err)
		}
	}

	if powerQ.IsZero() {
		// In some cases, especially in tests, staking is enabled but
		// registration thresholds are zero.
		// However, if they actually register with zero, give them one free
		// vote power so that CometBFT doesn't treat it as a removal.
		return 1, nil
	}

	powerBI := powerQ.ToBigInt()

	if distribution == VotingPowerDistributionSqrt {
		powerBI = powerBI.Sqrt(powerBI)
	}

	if !powerBI.IsInt64() {
		return 0, fmt.Errorf("%v is too many base units to convert to power", powerQ)
	}

	return powerBI.Int64(), nil
}

// Validator is a consensus validator.
type Validator struct {
	// ID is the validator Oasis node identifier.
	ID signature.PublicKey `json:"id"`

	// EntityID is the validator entity identifier.
	EntityID signature.PublicKey `json:"entity_id"`

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

	// ConsensusParameters returns the scheduler consensus parameters.
	ConsensusParameters(ctx context.Context, height int64) (*ConsensusParameters, error)

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
	DebugBypassStake bool `json:"debug_bypass_stake,omitempty"`

	// RewardFactorEpochElectionAny is the factor for a reward
	// distributed per epoch to entities that have any node considered
	// in any election.
	RewardFactorEpochElectionAny quantity.Quantity `json:"reward_factor_epoch_election_any"`

	// DebugForceElect is the map of nodes that will always be elected
	// to a given role for a runtime.
	DebugForceElect map[common.Namespace]map[signature.PublicKey]*ForceElectCommitteeRole `json:"debug_force_elect,omitempty"`

	// DebugAllowWeakAlpha allows VRF based elections based on proofs
	// generated by an alpha value considered weak.
	DebugAllowWeakAlpha bool `json:"debug_allow_weak_alpha,omitempty"`

	// VotingPowerDistribution is the voting power distribution.
	VotingPowerDistribution VotingPowerDistribution `json:"voting_power_distribution,omitempty"`
}

// ConsensusParameterChanges are allowed scheduler consensus parameter changes.
type ConsensusParameterChanges struct {
	// MinValidators is the new minimum number of validators.
	MinValidators *int `json:"min_validators"`

	// MaxValidators is the new maximum number of validators.
	MaxValidators *int `json:"max_validators"`

	// VotingPowerDistribution is the new voting power distribution.
	VotingPowerDistribution *VotingPowerDistribution `json:"voting_power_distribution,omitempty"`
}

// Apply applies changes to the given consensus parameters.
func (c *ConsensusParameterChanges) Apply(params *ConsensusParameters) error {
	if c.MinValidators != nil {
		params.MinValidators = *c.MinValidators
	}
	if c.MaxValidators != nil {
		params.MaxValidators = *c.MaxValidators
	}
	if c.VotingPowerDistribution != nil {
		params.VotingPowerDistribution = *c.VotingPowerDistribution
	}
	return nil
}

// ForceElectCommitteeRole is the committee kind/role that a force-elected
// node is elected as.
type ForceElectCommitteeRole struct {
	// Kind is the kind of committee to force-elect the node into.
	Kind CommitteeKind `json:"kind,omitempty"`
	// Roles are the roles that the given node is force elected as.
	Roles []Role `json:"roles,omitempty"`
	// Index is the position of the given node in the committee's worker group if it has
	// the worker role.
	Index uint64 `json:"index,omitempty"`
}

// HasRole returns true whether the force election configuration specifies a given role.
func (fe *ForceElectCommitteeRole) HasRole(role Role) bool {
	for _, r := range fe.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// ElectedEvent is the elected committee kind event.
type ElectedEvent struct {
	// Kinds are the elected committee kinds.
	Kinds []CommitteeKind `json:"kinds,omitempty"`
}

// EventKind returns a string representation of this event's kind.
func (ev *ElectedEvent) EventKind() string {
	return "elected"
}

func init() {
	// 16 allows for up to 1.8e19 base units to be staked.
	if err := BaseUnitsPerVotingPower.FromUint64(16); err != nil {
		panic(err)
	}
}
