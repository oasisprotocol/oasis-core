package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	// ErrUnsupportedRuntimeKind is the error returned when the parsed runtime
	// kind is malformed or unknown.
	ErrUnsupportedRuntimeKind = errors.New("runtime: unsupported runtime kind")

	// ErrUnsupportedRuntimeGovernanceModel is the error returned when the
	// parsed runtime governance model is malformed or unknown.
	ErrUnsupportedRuntimeGovernanceModel = errors.New("runtime: unsupported governance model")
)

// RuntimeKind represents the runtime functionality.
type RuntimeKind uint32

const (
	// KindInvalid is an invalid runtime and should never be explicitly set.
	KindInvalid RuntimeKind = 0

	// KindCompute is a generic compute runtime.
	KindCompute RuntimeKind = 1

	// KindKeyManager is a key manager runtime.
	KindKeyManager RuntimeKind = 2

	kindInvalid    = "invalid"
	kindCompute    = "compute"
	kindKeyManager = "keymanager"
)

// String returns a string representation of a runtime kind.
func (k RuntimeKind) String() string {
	switch k {
	case KindInvalid:
		return kindInvalid
	case KindCompute:
		return kindCompute
	case KindKeyManager:
		return kindKeyManager
	default:
		return "[unsupported runtime kind]"
	}
}

// FromString deserializes a string into a RuntimeKind.
func (k *RuntimeKind) FromString(str string) error {
	switch strings.ToLower(str) {
	case kindCompute:
		*k = KindCompute
	case kindKeyManager:
		*k = KindKeyManager
	default:
		return ErrUnsupportedRuntimeKind
	}

	return nil
}

// ExecutorParameters are parameters for the executor committee.
type ExecutorParameters struct {
	// GroupSize is the size of the committee.
	GroupSize uint16 `json:"group_size"`

	// GroupBackupSize is the size of the discrepancy resolution group.
	GroupBackupSize uint16 `json:"group_backup_size"`

	// AllowedStragglers is the number of allowed stragglers.
	AllowedStragglers uint16 `json:"allowed_stragglers"`

	// RoundTimeout is the round timeout in consensus blocks.
	RoundTimeout int64 `json:"round_timeout"`

	// MaxMessages is the maximum number of messages that can be emitted by the runtime in a
	// single round.
	MaxMessages uint32 `json:"max_messages"`

	// MinLiveRoundsPercent is the minimum percentage of rounds in an epoch that a node must
	// participate in positively in order to be considered live. Nodes not satisfying this may be
	// penalized.
	MinLiveRoundsPercent uint8 `json:"min_live_rounds_percent,omitempty"`

	// MinLiveRoundsForEvaluation is the minimum number of live rounds in an epoch for the liveness
	// calculations to be considered for evaluation.
	MinLiveRoundsForEvaluation uint64 `json:"min_live_rounds_eval,omitempty"`

	// MaxLivenessFailures is the maximum number of liveness failures that are tolerated before
	// suspending and/or slashing the node. Zero means unlimited.
	MaxLivenessFailures uint8 `json:"max_liveness_fails,omitempty"`
}

// ValidateBasic performs basic executor parameter validity checks.
func (e *ExecutorParameters) ValidateBasic() error {
	if e.GroupSize == 0 {
		return fmt.Errorf("executor primary group too small")
	}
	if e.AllowedStragglers > e.GroupSize || (e.GroupBackupSize > 0 && e.AllowedStragglers > e.GroupBackupSize) {
		return fmt.Errorf("number of allowed stragglers too large")
	}

	if e.RoundTimeout <= 0 {
		return fmt.Errorf("round timeout too small")
	}

	if e.MinLiveRoundsPercent > 100 {
		return fmt.Errorf("minimum live rounds percentage cannot be greater than 100")
	}

	return nil
}

// TxnSchedulerParameters are parameters for the runtime transaction scheduler.
type TxnSchedulerParameters struct {
	// BatchFlushTimeout denotes, if using the "simple" algorithm, how long to
	// wait for a scheduled batch.
	BatchFlushTimeout time.Duration `json:"batch_flush_timeout"`

	// MaxBatchSize denotes what is the max size of a scheduled batch.
	MaxBatchSize uint64 `json:"max_batch_size"`

	// MaxBatchSizeBytes denote what is the max size of a scheduled batch in bytes.
	MaxBatchSizeBytes uint64 `json:"max_batch_size_bytes"`

	// MaxInMessages specifies the maximum size of the incoming message queue.
	MaxInMessages uint32 `json:"max_in_messages,omitempty"`

	// ProposerTimeout denotes the timeout (in consensus blocks) for scheduler
	// to propose a batch.
	ProposerTimeout int64 `json:"propose_batch_timeout"`
}

// ValidateBasic performs basic transaction scheduler parameter validity checks.
func (t *TxnSchedulerParameters) ValidateBasic() error {
	// Ensure txnscheduler parameters have sensible values.
	if t.BatchFlushTimeout < 50*time.Millisecond {
		return fmt.Errorf("transaction scheduler batch flush timeout parameter too small")
	}
	if t.MaxBatchSize < 1 {
		return fmt.Errorf("transaction scheduler max batch size parameter too small")
	}
	if t.MaxBatchSizeBytes < 1024 {
		return fmt.Errorf("transaction scheduler max batch bytes size parameter too small")
	}
	if t.ProposerTimeout < 2 {
		return fmt.Errorf("transaction scheduler proposer timeout parameter too small")
	}

	return nil
}

// StorageParameters are parameters for the storage committee.
type StorageParameters struct {
	// CheckpointInterval is the expected runtime state checkpoint interval (in rounds).
	CheckpointInterval uint64 `json:"checkpoint_interval"`

	// CheckpointNumKept is the expected minimum number of checkpoints to keep.
	CheckpointNumKept uint64 `json:"checkpoint_num_kept"`

	// CheckpointChunkSize is the chunk size parameter for checkpoint creation.
	CheckpointChunkSize uint64 `json:"checkpoint_chunk_size"`
}

// ValidateBasic performs basic storage parameter validity checks.
func (s *StorageParameters) ValidateBasic() error {
	// Verify storage checkpointing configuration if enabled.
	if s.CheckpointInterval > 0 && !flags.DebugDontBlameOasis() {
		if s.CheckpointInterval < 10 {
			return fmt.Errorf("storage CheckpointInterval parameter too small")
		}
		if s.CheckpointNumKept == 0 {
			return fmt.Errorf("storage CheckpointNumKept parameter too small")
		}
		if s.CheckpointChunkSize < 1024*1024 {
			return fmt.Errorf("storage CheckpointChunkSize parameter too small")
		}
	}

	return nil
}

// AnyNodeRuntimeAdmissionPolicy allows any node to register.
type AnyNodeRuntimeAdmissionPolicy struct{}

// EntityWhitelistRuntimeAdmissionPolicy allows only whitelisted entities' nodes to register.
type EntityWhitelistRuntimeAdmissionPolicy struct {
	Entities map[signature.PublicKey]EntityWhitelistConfig `json:"entities"`
}

type EntityWhitelistConfig struct {
	// MaxNodes is the maximum number of nodes that an entity can register under
	// the given runtime for a specific role. If the map is empty or absent, the
	// number of nodes is unlimited. If the map is present and non-empty, the
	// the number of nodes is restricted to the specified maximum (where zero
	// means no nodes allowed), any missing roles imply zero nodes.
	MaxNodes map[node.RolesMask]uint16 `json:"max_nodes,omitempty"`
}

// RuntimeAdmissionPolicy is a specification of which nodes are allowed to register for a runtime.
type RuntimeAdmissionPolicy struct {
	AnyNode         *AnyNodeRuntimeAdmissionPolicy         `json:"any_node,omitempty"`
	EntityWhitelist *EntityWhitelistRuntimeAdmissionPolicy `json:"entity_whitelist,omitempty"`
}

// SchedulingConstraints are the node scheduling constraints.
//
// Multiple fields may be set in which case the ALL the constraints must be satisfied.
type SchedulingConstraints struct {
	ValidatorSet *ValidatorSetConstraint `json:"validator_set,omitempty"`
	MaxNodes     *MaxNodesConstraint     `json:"max_nodes,omitempty"`
	MinPoolSize  *MinPoolSizeConstraint  `json:"min_pool_size,omitempty"`
}

// ValidatorSetConstraint specifies that the entity must have a node that is part of the validator
// set. No other options can currently be specified.
type ValidatorSetConstraint struct{}

// MaxNodesConstraint specifies that only the given number of nodes may be eligible per entity.
type MaxNodesConstraint struct {
	Limit uint16 `json:"limit"`
}

// MinPoolSizeConstraint is the minimum required candidate pool size constraint.
type MinPoolSizeConstraint struct {
	Limit uint16 `json:"limit"`
}

// RuntimeStakingParameters are the stake-related parameters for a runtime.
type RuntimeStakingParameters struct {
	// Thresholds are the minimum stake thresholds for a runtime. These per-runtime thresholds are
	// in addition to the global thresholds. May be left unspecified.
	//
	// In case a node is registered for multiple runtimes, it will need to satisfy the maximum
	// threshold of all the runtimes.
	Thresholds map[staking.ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`

	// Slashing are the per-runtime misbehavior slashing parameters.
	Slashing map[staking.SlashReason]staking.Slash `json:"slashing,omitempty"`

	// RewardSlashEquvocationRuntimePercent is the percentage of the reward obtained when slashing
	// for equivocation that is transferred to the runtime's account.
	RewardSlashEquvocationRuntimePercent uint8 `json:"reward_equivocation,omitempty"`

	// RewardSlashBadResultsRuntimePercent is the percentage of the reward obtained when slashing
	// for incorrect results that is transferred to the runtime's account.
	RewardSlashBadResultsRuntimePercent uint8 `json:"reward_bad_results,omitempty"`

	// MinInMessageFee specifies the minimum fee that the incoming message must include for the
	// message to be queued.
	MinInMessageFee quantity.Quantity `json:"min_in_message_fee,omitempty"`
}

// ValidateBasic performs basic descriptor validity checks.
func (s *RuntimeStakingParameters) ValidateBasic(runtimeKind RuntimeKind) error {
	if s.RewardSlashEquvocationRuntimePercent > 100 {
		return fmt.Errorf("runtime reward percentage from slashing for equivocation must be <= 100")
	}
	if s.RewardSlashBadResultsRuntimePercent > 100 {
		return fmt.Errorf("runtime reward percentage from slashing for bad results must be <= 100")
	}
	for kind, q := range s.Thresholds {
		switch kind {
		case staking.KindNodeCompute:
			if runtimeKind != KindCompute {
				return fmt.Errorf("unsupported staking threshold kind for runtime: %s", kind)
			}
		case staking.KindNodeKeyManager:
			if runtimeKind != KindKeyManager {
				return fmt.Errorf("unsupported staking threshold kind for runtime: %s", kind)
			}
		default:
			return fmt.Errorf("unsupported staking threshold kind for runtime: %s", kind)
		}

		if !q.IsValid() {
			return fmt.Errorf("invalid threshold of kind %s specified", kind)
		}
	}
	return nil
}

const (
	// LatestRuntimeDescriptorVersion is the latest entity descriptor version that should be used
	// for all new descriptors. Using earlier versions may be rejected.
	LatestRuntimeDescriptorVersion = 3

	// Minimum and maximum descriptor versions that are allowed.
	minRuntimeDescriptorVersion = 3
	maxRuntimeDescriptorVersion = LatestRuntimeDescriptorVersion
)

// Runtime represents a runtime.
type Runtime struct { // nolint: maligned
	cbor.Versioned

	// ID is a globally unique long term identifier of the runtime.
	ID common.Namespace `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the runtime.
	EntityID signature.PublicKey `json:"entity_id"`

	// Genesis is the runtime genesis information.
	Genesis RuntimeGenesis `json:"genesis"`

	// Kind is the type of runtime.
	Kind RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager *common.Namespace `json:"key_manager,omitempty"`

	// Executor stores parameters of the executor committee.
	Executor ExecutorParameters `json:"executor,omitempty"`

	// TxnScheduler stores transaction scheduling parameters of the executor
	// committee.
	TxnScheduler TxnSchedulerParameters `json:"txn_scheduler,omitempty"`

	// Storage stores parameters of the storage committee.
	Storage StorageParameters `json:"storage,omitempty"`

	// AdmissionPolicy sets which nodes are allowed to register for this runtime.
	// This policy applies to all roles.
	AdmissionPolicy RuntimeAdmissionPolicy `json:"admission_policy"`

	// Constraints are the node scheduling constraints.
	Constraints map[scheduler.CommitteeKind]map[scheduler.Role]SchedulingConstraints `json:"constraints,omitempty"`

	// Staking stores the runtime's staking-related parameters.
	Staking RuntimeStakingParameters `json:"staking,omitempty"`

	// GovernanceModel specifies the runtime governance model.
	GovernanceModel RuntimeGovernanceModel `json:"governance_model"`

	// Deployments specifies the runtime deployments (versions).
	Deployments []*VersionInfo `json:"deployments,omitempty"`
}

// RuntimeGovernanceModel specifies the runtime governance model.
type RuntimeGovernanceModel uint8

const (
	GovernanceInvalid   RuntimeGovernanceModel = 0
	GovernanceEntity    RuntimeGovernanceModel = 1
	GovernanceRuntime   RuntimeGovernanceModel = 2
	GovernanceConsensus RuntimeGovernanceModel = 3

	GovernanceMax = GovernanceConsensus

	gmInvalid   = "invalid"
	gmEntity    = "entity"
	gmRuntime   = "runtime"
	gmConsensus = "consensus"
)

// String returns a string representation of a runtime governance model.
func (gm RuntimeGovernanceModel) String() string {
	model, err := gm.MarshalText()
	if err != nil {
		return "[unsupported runtime governance model]"
	}
	return string(model)
}

func (gm RuntimeGovernanceModel) MarshalText() ([]byte, error) {
	switch gm {
	case GovernanceInvalid:
		return []byte(gmInvalid), nil
	case GovernanceEntity:
		return []byte(gmEntity), nil
	case GovernanceRuntime:
		return []byte(gmRuntime), nil
	case GovernanceConsensus:
		return []byte(gmConsensus), nil
	default:
		return nil, ErrUnsupportedRuntimeGovernanceModel
	}
}

func (gm *RuntimeGovernanceModel) UnmarshalText(text []byte) error {
	switch string(text) {
	case gmEntity:
		*gm = GovernanceEntity
	case gmRuntime:
		*gm = GovernanceRuntime
	case gmConsensus:
		*gm = GovernanceConsensus
	default:
		return fmt.Errorf("%w: '%s'", ErrUnsupportedRuntimeGovernanceModel, string(text))
	}

	return nil
}

// ValidateBasic performs basic descriptor validity checks.
func (r *Runtime) ValidateBasic(strictVersion bool) error {
	v := r.Versioned.V
	switch strictVersion {
	case true:
		// Only the latest version is allowed.
		if v != LatestRuntimeDescriptorVersion {
			return fmt.Errorf("invalid runtime descriptor version (expected: %d got: %d)",
				LatestRuntimeDescriptorVersion,
				v,
			)
		}
	case false:
		// A range of versions is allowed.
		if v < minRuntimeDescriptorVersion || v > maxRuntimeDescriptorVersion {
			return fmt.Errorf("invalid runtime descriptor version (min: %d max: %d)",
				minRuntimeDescriptorVersion,
				maxRuntimeDescriptorVersion,
			)
		}
	}

	switch r.Kind {
	case KindCompute:
		// Compute runtime.
		if r.ID.IsKeyManager() {
			return fmt.Errorf("compute runtime ID has the key manager flag set")
		}
		if r.KeyManager != nil && r.ID.Equal(r.KeyManager) {
			return fmt.Errorf("compute runtime has self as key manager")
		}

		if err := r.Executor.ValidateBasic(); err != nil {
			return fmt.Errorf("bad executor parameters: %w", err)
		}
		if err := r.TxnScheduler.ValidateBasic(); err != nil {
			return fmt.Errorf("bad txn scheduler parameters: %w", err)
		}
		if err := r.Storage.ValidateBasic(); err != nil {
			return fmt.Errorf("bad storage parameters: %w", err)
		}
	case KindKeyManager:
		// Key manager runtime.
		if !r.ID.IsKeyManager() {
			return fmt.Errorf("key manager runtime ID does not have the key manager flag set")
		}
		if r.KeyManager != nil {
			return fmt.Errorf("key manager runtime cannot itself have a key manager")
		}

		// Currently the keymanager implementation assumes SGX. Unless this is a
		// test runtime, a keymanager without SGX is disallowed.
		if !r.ID.IsTest() && r.TEEHardware != node.TEEHardwareIntelSGX {
			return fmt.Errorf("non-SGX keymanager runtime")
		}
	default:
		return fmt.Errorf("bad runtime kind: %s", r.Kind)
	}

	if err := r.Staking.ValidateBasic(r.Kind); err != nil {
		return fmt.Errorf("bad staking parameters: %w", err)
	}

	if r.GovernanceModel < 1 || r.GovernanceModel > GovernanceMax {
		return fmt.Errorf("%w: out of range", ErrUnsupportedRuntimeGovernanceModel)
	}

	if len(r.Deployments) == 0 {
		return fmt.Errorf("no deployment information specified")
	}

	return nil
}

// ActiveDeployment returns the currently active deployment for the specified
// epoch if it exists.
func (r *Runtime) ActiveDeployment(now beacon.EpochTime) *VersionInfo {
	var activeDeployment *VersionInfo
	for i, deployment := range r.Deployments {
		// Ignore versions that are not valid yet.
		if deployment.ValidFrom > now {
			continue
		}
		switch activeDeployment {
		case nil:
			activeDeployment = r.Deployments[i]
		default:
			if activeDeployment.ValidFrom < deployment.ValidFrom {
				activeDeployment = r.Deployments[i]
			}
		}
	}
	return activeDeployment
}

// DeploymentForVersion returns the deployment corresponding to the passed version if it exists.
func (r *Runtime) DeploymentForVersion(v version.Version) *VersionInfo {
	for _, deployment := range r.Deployments {
		if deployment.Version == v {
			return deployment
		}
	}
	return nil
}

// ValidateDeployments validates a runtime descriptor's Deployments field
// at the specified epoch.
func (r *Runtime) ValidateDeployments(now beacon.EpochTime, params *ConsensusParameters) error {
	// The runtime descriptor's deployments field is considered valid
	// if:
	//  * There is at least one entry present.
	//  * All of the entries are well-formed.
	//  * There is at most max(2, params.MaxRuntimeDeployments) entries:
	//  * The versions field increases as versions are deployed.

	if len(r.Deployments) == 0 {
		return fmt.Errorf("%w: no deployments", ErrInvalidArgument)
	}
	maxRuntimeDeployments := uint8(2) // We must allow at least two deployments.
	if params.MaxRuntimeDeployments > maxRuntimeDeployments {
		maxRuntimeDeployments = params.MaxRuntimeDeployments
	}
	if len(r.Deployments) > int(maxRuntimeDeployments) {
		return fmt.Errorf("%w: too many deployments", ErrInvalidArgument)
	}
	// Ensure no nil deployments.
	for _, d := range r.Deployments {
		if d == nil {
			return fmt.Errorf("%w: nil deployment", ErrInvalidArgument)
		}
	}

	deployments := make([]*VersionInfo, len(r.Deployments))
	copy(deployments, r.Deployments)
	sort.SliceStable(deployments, func(i, j int) bool {
		return deployments[i].Version.ToU64() < deployments[j].Version.ToU64()
	})

	versionMap := make(map[version.Version]bool)

	var (
		numFuture      int
		prevDeployment *VersionInfo
	)
	for i, deployment := range deployments {
		if versionMap[deployment.Version] {
			return fmt.Errorf("%w: duplicate version", ErrInvalidArgument)
		}
		versionMap[deployment.Version] = true

		// Validate that versions increase.  As we are traversing a slice
		// sorted by increasing version, and we explicitly disallow duplicate
		// versions, we only need to validate that the validity windows
		// are strictly increasing here to satisfy the invariants.
		if prevDeployment != nil {
			if prevDeployment.ValidFrom >= deployment.ValidFrom {
				return fmt.Errorf("%w: versions must increase over time", ErrInvalidArgument)
			}
		}
		prevDeployment = deployments[i]

		if deployment.ValidFrom > now {
			numFuture++
		}

		switch r.TEEHardware {
		case node.TEEHardwareInvalid:
			if deployment.TEE != nil {
				return fmt.Errorf("%w: TEE constraints when no TEE specified", ErrInvalidArgument)
			}
		case node.TEEHardwareIntelSGX:
			var cs node.SGXConstraints
			if err := cbor.Unmarshal(deployment.TEE, &cs); err != nil {
				return fmt.Errorf("%w: invalid SGX TEE constraints", ErrInvalidArgument)
			}
			if err := cs.ValidateBasic(params.TEEFeatures); err != nil {
				return fmt.Errorf("%w: invalid SGX TEE constraints", ErrInvalidArgument)
			}
			if len(cs.Enclaves) == 0 {
				return fmt.Errorf("%w: invalid SGX TEE constraints", ErrNoEnclaveForRuntime)
			}
		default:
			return fmt.Errorf("%w: invalid TEE hardware", ErrInvalidArgument)
		}
	}
	if numFuture > 1 {
		return fmt.Errorf("%w: more than one future deployment", ErrInvalidArgument)
	}

	return nil
}

// String returns a string representation of itself.
func (r Runtime) String() string {
	return "<Runtime id=" + r.ID.String() + ">"
}

// IsCompute returns true iff the runtime is a generic compute runtime.
func (r *Runtime) IsCompute() bool {
	return r.Kind == KindCompute
}

// StakingAddress returns the correct staking address for the runtime based
// on its governance model or nil if there is no staking address under the
// given governance model.
func (r *Runtime) StakingAddress() *staking.Address {
	var acctAddr staking.Address
	switch r.GovernanceModel {
	case GovernanceEntity:
		acctAddr = staking.NewAddress(r.EntityID)
	case GovernanceRuntime:
		acctAddr = staking.NewRuntimeAddress(r.ID)
	default:
		return nil
	}
	return &acctAddr
}

// VersionInfo is the per-runtime version information.
type VersionInfo struct {
	// Version of the runtime.
	Version version.Version `json:"version"`

	// ValidFrom stores the epoch at which, this version is valid.
	ValidFrom beacon.EpochTime `json:"valid_from"`

	// TEE is the enclave version information, in an enclave provider specific
	// format if any.
	TEE []byte `json:"tee,omitempty"`
}

// Equal compares vs another VersionInfo for equality.
func (vi *VersionInfo) Equal(cmp *VersionInfo) bool {
	if vi.Version.ToU64() != cmp.Version.ToU64() {
		return false
	}
	if vi.ValidFrom != cmp.ValidFrom {
		return false
	}
	if !bytes.Equal(vi.TEE, cmp.TEE) {
		return false
	}
	return true
}

// RuntimeGenesis is the runtime genesis information that is used to
// initialize runtime state in the first block.
type RuntimeGenesis struct {
	// StateRoot is the state root that should be used at genesis time. If
	// the runtime should start with empty state, this must be set to the
	// empty hash.
	StateRoot hash.Hash `json:"state_root"`

	// Round is the runtime round in the genesis.
	Round uint64 `json:"round"`
}

// Equal compares vs another RuntimeGenesis for equality.
func (rtg *RuntimeGenesis) Equal(cmp *RuntimeGenesis) bool {
	if !rtg.StateRoot.Equal(&cmp.StateRoot) {
		return false
	}
	if rtg.Round != cmp.Round {
		return false
	}
	return true
}

// SanityCheck does basic sanity checking of RuntimeGenesis.
// isGenesis is true, if it is called during consensus chain init.
func (rtg *RuntimeGenesis) SanityCheck(isGenesis bool) error {
	return nil
}

// RuntimeDescriptorProvider is an interface that provides access to runtime descriptors.
type RuntimeDescriptorProvider interface {
	// ActiveDescriptor waits for the runtime to be initialized and then returns its active
	// descriptor.
	ActiveDescriptor(ctx context.Context) (*Runtime, error)
}
