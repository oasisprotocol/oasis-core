// Package fixgenesis implements the fix-genesis command.
package fixgenesis

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const cfgNewGenesis = "genesis.new_file"

var (
	fixGenesisCmd = &cobra.Command{
		Use:   "fix-genesis",
		Short: "fix a genesis document",
		Run:   doFixGenesis,
	}

	newGenesisFlag = flag.NewFlagSet("", flag.ContinueOnError)

	logger = logging.GetLogger("cmd/debug/fix-genesis")
)

const (
	slashBeaconInvalidCommitName    = "beacon-invalid-commit"
	slashBeaconInvalidRevealName    = "beacon-invalid-reveal"
	slashBeaconNonparticipationName = "beacon-nonparticipation"
)

type v4Document struct {
	// Height is the block height at which the document was generated.
	Height int64 `json:"height"`
	// Time is the time the genesis block was constructed.
	Time time.Time `json:"genesis_time"`
	// ChainID is the ID of the chain.
	ChainID string `json:"chain_id"`
	// Registry is the registry genesis state.
	Registry v4RegistryGenesis `json:"registry"`
	// RootHash is the roothash genesis state.
	RootHash roothash.Genesis `json:"roothash"`
	// Staking is the staking genesis state.
	Staking v4StakingGenesis `json:"staking"`
	// KeyManager is the key manager genesis state.
	KeyManager keymanager.Genesis `json:"keymanager"`
	// Scheduler is the scheduler genesis state.
	Scheduler scheduler.Genesis `json:"scheduler"`
	// Beacon is the beacon genesis state.
	Beacon v4BeaconGenesis `json:"beacon"`
	// Governance is the governance genesis state.
	Governance v4GovernanceGenesis `json:"governance"`
	// Consensus is the consensus genesis state.
	Consensus consensus.Genesis `json:"consensus"`
	// HaltEpoch is the epoch height at which the network will stop processing
	// any transactions and will halt.
	HaltEpoch beacon.EpochTime `json:"halt_epoch"`
	// Extra data is arbitrary extra data that is part of the
	// genesis block but is otherwise ignored by the protocol.
	ExtraData map[string][]byte `json:"extra_data"`
}

type v4BeaconGenesis struct {
	// Base is the starting epoch.
	Base beacon.EpochTime `json:"base"`

	// Parameters are the beacon consensus parameters.
	Parameters v4BeaconConsensusParameters `json:"params"`
}

type v4BeaconConsensusParameters struct {
	// Backend is the beacon backend.
	Backend string `json:"backend"`

	// DebugMockBackend is flag for enabling the mock epochtime backend.
	DebugMockBackend bool `json:"debug_mock_backend,omitempty"`

	// DebugDeterministic is true iff the output should be deterministic.
	DebugDeterministic bool `json:"debug_deterministic,omitempty"`

	// InsecureParameters are the beacon parameters for the insecure backend.
	InsecureParameters *beacon.InsecureParameters `json:"insecure_parameters,omitempty"`

	// PVSSParameters are the beacon parameters for the PVSS backend.
	PVSSParameters *v4BeaconPVSSParameters `json:"pvss_parameters,omitempty"`
}

type v4BeaconPVSSParameters struct {
	Participants uint32 `json:"participants"`
	Threshold    uint32 `json:"threshold"`

	CommitInterval  int64 `json:"commit_interval"`
	RevealInterval  int64 `json:"reveal_interval"`
	TransitionDelay int64 `json:"transition_delay"`

	DebugForcedParticipants []signature.PublicKey `json:"debug_forced_participants,omitempty"`
}

type v4RegistryGenesis struct {
	// Runtimes is the initial list of runtimes.
	Runtimes []*v4Runtime `json:"runtimes,omitempty"`
	// SuspendedRuntimes is the list of suspended runtimes.
	SuspendedRuntimes []*v4Runtime `json:"suspended_runtimes,omitempty"`

	// Everything below is unchanged.

	// Parameters are the registry consensus parameters.
	Parameters registry.ConsensusParameters `json:"params"`

	// Entities is the initial list of entities.
	Entities []*entity.SignedEntity `json:"entities,omitempty"`

	// Nodes is the initial list of nodes.
	Nodes []*node.MultiSignedNode `json:"nodes,omitempty"`

	// NodeStatuses is a set of node statuses.
	NodeStatuses map[signature.PublicKey]*registry.NodeStatus `json:"node_statuses,omitempty"`
}

type v4Runtime struct { // nolint: maligned
	cbor.Versioned

	// ID is a globally unique long term identifier of the runtime.
	ID common.Namespace `json:"id"`

	// EntityID is the public key identifying the Entity controlling
	// the runtime.
	EntityID signature.PublicKey `json:"entity_id"`

	// Genesis is the runtime genesis information.
	Genesis registry.RuntimeGenesis `json:"genesis"`

	// Kind is the type of runtime.
	Kind registry.RuntimeKind `json:"kind"`

	// TEEHardware specifies the runtime's TEE hardware requirements.
	TEEHardware node.TEEHardware `json:"tee_hardware"`

	// Version is the runtime version information.
	Version registry.VersionInfo `json:"versions"`

	// KeyManager is the key manager runtime ID for this runtime.
	KeyManager *common.Namespace `json:"key_manager,omitempty"`

	// Executor stores parameters of the executor committee.
	Executor registry.ExecutorParameters `json:"executor,omitempty"`

	// TxnScheduler stores transaction scheduling parameters of the executor
	// committee.
	TxnScheduler registry.TxnSchedulerParameters `json:"txn_scheduler,omitempty"`

	// Storage stores parameters of the storage committee.
	Storage registry.StorageParameters `json:"storage,omitempty"`

	// AdmissionPolicy sets which nodes are allowed to register for this runtime.
	// This policy applies to all roles.
	AdmissionPolicy registry.RuntimeAdmissionPolicy `json:"admission_policy"`

	// Constraints are the node scheduling constraints.
	Constraints map[v4SchedulerCommitteeKind]map[scheduler.Role]registry.SchedulingConstraints `json:"constraints,omitempty"`

	// Staking stores the runtime's staking-related parameters.
	Staking registry.RuntimeStakingParameters `json:"staking,omitempty"`

	// GovernanceModel specifies the runtime governance model.
	GovernanceModel registry.RuntimeGovernanceModel `json:"governance_model"`
}

type v4SchedulerCommitteeKind scheduler.CommitteeKind

const v4SchedulerCommitteeKindStorage = v4SchedulerCommitteeKind(scheduler.CommitteeKind(2))

func (k *v4SchedulerCommitteeKind) UnmarshalText(text []byte) error {
	// v4 supported storage nodes which we should remove.
	if string(text) == "storage" {
		*k = v4SchedulerCommitteeKindStorage
		return nil
	}

	var ck scheduler.CommitteeKind
	if err := ck.UnmarshalText(text); err != nil {
		return err
	}
	*k = v4SchedulerCommitteeKind(ck)
	return nil
}

type v4StakingGenesis struct {
	// Parameters are the staking consensus parameters.
	Parameters v4StakingConsensusParameters `json:"params"`

	// Everything below is unchanged.

	// TokenSymbol is the token's ticker symbol.
	// Only upper case A-Z characters are allowed.
	TokenSymbol string `json:"token_symbol"`
	// TokenValueExponent is the token's value base-10 exponent, i.e.
	// 1 token = 10**TokenValueExponent base units.
	TokenValueExponent uint8 `json:"token_value_exponent"`

	// TokenSupply is the network's total amount of stake in base units.
	TotalSupply quantity.Quantity `json:"total_supply"`
	// CommonPool is the network's common stake pool.
	CommonPool quantity.Quantity `json:"common_pool"`
	// LastBlockFees are the collected fees for previous block.
	LastBlockFees quantity.Quantity `json:"last_block_fees"`
	// GovernanceDeposits are network's governance deposits.
	GovernanceDeposits quantity.Quantity `json:"governance_deposits"`

	// Ledger is a map of staking accounts.
	Ledger map[staking.Address]*staking.Account `json:"ledger,omitempty"`

	// Delegations is a nested map of staking delegations of the form:
	// DELEGATEE-ACCOUNT-ADDRESS: DELEGATOR-ACCOUNT-ADDRESS: DELEGATION.
	Delegations map[staking.Address]map[staking.Address]*staking.Delegation `json:"delegations,omitempty"`
	// DebondingDelegations is a nested map of staking delegations of the form:
	// DEBONDING-DELEGATEE-ACCOUNT-ADDRESS: DEBONDING-DELEGATOR-ACCOUNT-ADDRESS: list of DEBONDING-DELEGATIONs.
	DebondingDelegations map[staking.Address]map[staking.Address][]*staking.DebondingDelegation `json:"debonding_delegations,omitempty"`
}

type v4StakingConsensusParameters struct {
	Thresholds map[v4StakingThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
	Slashing   map[string]staking.Slash                     `json:"slashing,omitempty"`

	// Everything below is unchanged.

	DebondingInterval                 beacon.EpochTime                `json:"debonding_interval,omitempty"`
	RewardSchedule                    []staking.RewardStep            `json:"reward_schedule,omitempty"`
	SigningRewardThresholdNumerator   uint64                          `json:"signing_reward_threshold_numerator,omitempty"`
	SigningRewardThresholdDenominator uint64                          `json:"signing_reward_threshold_denominator,omitempty"`
	CommissionScheduleRules           staking.CommissionScheduleRules `json:"commission_schedule_rules,omitempty"`
	GasCosts                          transaction.Costs               `json:"gas_costs,omitempty"`
	MinDelegationAmount               quantity.Quantity               `json:"min_delegation"`

	DisableTransfers       bool                     `json:"disable_transfers,omitempty"`
	DisableDelegation      bool                     `json:"disable_delegation,omitempty"`
	UndisableTransfersFrom map[staking.Address]bool `json:"undisable_transfers_from,omitempty"`

	// AllowEscrowMessages can be used to allow runtimes to perform AddEscrow
	// and ReclaimEscrow via runtime messages.
	AllowEscrowMessages bool `json:"allow_escrow_messages,omitempty"`

	// MaxAllowances is the maximum number of allowances an account can have. Zero means disabled.
	MaxAllowances uint32 `json:"max_allowances,omitempty"`

	// FeeSplitWeightPropose is the proportion of block fee portions that go to the proposer.
	FeeSplitWeightPropose quantity.Quantity `json:"fee_split_weight_propose"`
	// FeeSplitWeightVote is the proportion of block fee portions that go to the validator that votes.
	FeeSplitWeightVote quantity.Quantity `json:"fee_split_weight_vote"`
	// FeeSplitWeightNextPropose is the proportion of block fee portions that go to the next block's proposer.
	FeeSplitWeightNextPropose quantity.Quantity `json:"fee_split_weight_next_propose"`

	// RewardFactorEpochSigned is the factor for a reward distributed per epoch to
	// entities that have signed at least a threshold fraction of the blocks.
	RewardFactorEpochSigned quantity.Quantity `json:"reward_factor_epoch_signed"`
	// RewardFactorBlockProposed is the factor for a reward distributed per block
	// to the entity that proposed the block.
	RewardFactorBlockProposed quantity.Quantity `json:"reward_factor_block_proposed"`
}

type v4StakingThresholdKind staking.ThresholdKind

const v4StakingThresholdKindNodeStorage = v4StakingThresholdKind(staking.ThresholdKind(3))

func (k *v4StakingThresholdKind) UnmarshalText(text []byte) error {
	// v4 supported storage nodes which we should remove.
	if string(text) == "node-storage" {
		*k = v4StakingThresholdKindNodeStorage
		return nil
	}

	var st staking.ThresholdKind
	if err := st.UnmarshalText(text); err != nil {
		return err
	}
	*k = v4StakingThresholdKind(st)
	return nil
}

type v4GovernanceGenesis struct {
	// Parameters are the genesis consensus parameters.
	Parameters v4GovernanceConsensusParameters `json:"params"`

	// Proposals are the governance proposals.
	Proposals []*governance.Proposal `json:"proposals,omitempty"`

	// VoteEntries are the governance proposal vote entries.
	VoteEntries map[uint64][]*governance.VoteEntry `json:"vote_entries,omitempty"`
}

type v4GovernanceConsensusParameters struct {
	// GasCosts are the governance transaction gas costs.
	GasCosts transaction.Costs `json:"gas_costs,omitempty"`

	// MinProposalDeposit is the number of base units that are deposited when
	// creating a new proposal.
	MinProposalDeposit quantity.Quantity `json:"min_proposal_deposit,omitempty"`

	// VotingPeriod is the number of epochs after which the voting for a proposal
	// is closed and the votes are tallied.
	VotingPeriod beacon.EpochTime `json:"voting_period,omitempty"`

	// Quorum is he minimum percentage of voting power that needs to be cast on
	// a proposal for the result to be valid.
	Quorum uint8 `json:"quorum,omitempty"`

	// Threshold is the minimum percentage of VoteYes votes in order for a
	// proposal to be accepted.
	Threshold uint8 `json:"threshold,omitempty"`

	// UpgradeMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade proposal to be valid.
	// This is also the minimum number of epochs between two pending upgrades.
	UpgradeMinEpochDiff beacon.EpochTime `json:"upgrade_min_epoch_diff,omitempty"`

	// UpgradeCancelMinEpochDiff is the minimum number of epochs between the current
	// epoch and the proposed upgrade epoch for the upgrade cancellation proposal to be valid.
	UpgradeCancelMinEpochDiff beacon.EpochTime `json:"upgrade_cancel_min_epoch_diff,omitempty"`
}

func doFixGenesis(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	// Load the old genesis document.
	f := flags.GenesisFile()
	raw, err := ioutil.ReadFile(f)
	if err != nil {
		logger.Error("failed to open genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Parse the genesis.
	var doc v4Document
	if err = json.Unmarshal(raw, &doc); err != nil {
		logger.Error("failed to parse old genesis file",
			"err", err,
		)
		os.Exit(1)
	}

	// Actually fix the genesis document.
	newDoc, err := updateGenesisDoc(doc)
	if err != nil {
		logger.Error("failed to fix genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	// Validate the new genesis document.
	if err = newDoc.SanityCheck(); err != nil {
		logger.Warn("new genesis document sanity check failed",
			"err", err,
		)
	}

	// Write out the new genesis document.
	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, cfgNewGenesis)
	if err != nil {
		logger.Error("failed to get writer for fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}
	canonJSON, err := newDoc.CanonicalJSON()
	if err != nil {
		logger.Error("failed to get canonical form of fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = w.Write(canonJSON); err != nil {
		logger.Error("failed to write fixed genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

func updateStakingGenesis(old *v4StakingGenesis) (staking.Genesis, error) {
	new := staking.Genesis{
		TokenSymbol:          old.TokenSymbol,
		TokenValueExponent:   old.TokenValueExponent,
		TotalSupply:          old.TotalSupply,
		CommonPool:           old.CommonPool,
		LastBlockFees:        old.LastBlockFees,
		GovernanceDeposits:   old.GovernanceDeposits,
		Ledger:               old.Ledger,
		Delegations:          old.Delegations,
		DebondingDelegations: old.DebondingDelegations,
	}

	// With parameters we need to remove the old storage-related thresholds and beacon-related
	// slashing parameters.
	new.Parameters = staking.ConsensusParameters{
		Thresholds: make(map[staking.ThresholdKind]quantity.Quantity),
		Slashing:   make(map[staking.SlashReason]staking.Slash),

		// Everything else below is just copied over unchanged.

		DebondingInterval:                 old.Parameters.DebondingInterval,
		RewardSchedule:                    old.Parameters.RewardSchedule,
		SigningRewardThresholdNumerator:   old.Parameters.SigningRewardThresholdNumerator,
		SigningRewardThresholdDenominator: old.Parameters.SigningRewardThresholdDenominator,
		CommissionScheduleRules:           old.Parameters.CommissionScheduleRules,
		GasCosts:                          old.Parameters.GasCosts,
		MinDelegationAmount:               old.Parameters.MinDelegationAmount,

		DisableTransfers:       old.Parameters.DisableTransfers,
		DisableDelegation:      old.Parameters.DisableDelegation,
		UndisableTransfersFrom: old.Parameters.UndisableTransfersFrom,

		AllowEscrowMessages: old.Parameters.AllowEscrowMessages,

		MaxAllowances: old.Parameters.MaxAllowances,

		FeeSplitWeightPropose:     old.Parameters.FeeSplitWeightPropose,
		FeeSplitWeightVote:        old.Parameters.FeeSplitWeightVote,
		FeeSplitWeightNextPropose: old.Parameters.FeeSplitWeightNextPropose,

		RewardFactorEpochSigned:   old.Parameters.RewardFactorEpochSigned,
		RewardFactorBlockProposed: old.Parameters.RewardFactorBlockProposed,
	}

	// Convert thresholds.
	delete(old.Parameters.Thresholds, v4StakingThresholdKindNodeStorage)
	for t, v := range old.Parameters.Thresholds {
		new.Parameters.Thresholds[staking.ThresholdKind(t)] = v
	}

	// Convert slashing parameters.
	for reason, slash := range old.Parameters.Slashing {
		switch reason {
		case slashBeaconInvalidCommitName, slashBeaconInvalidRevealName, slashBeaconNonparticipationName:
			// These conditions no longer exist.
		default:
			var newReason staking.SlashReason
			if err := newReason.UnmarshalText([]byte(reason)); err != nil {
				return staking.Genesis{}, fmt.Errorf("failed to parse slash reason: %w", err)
			}
			new.Parameters.Slashing[newReason] = slash
		}
	}

	return new, nil
}

func updateRegistryRuntime(old *v4Runtime) (registry.Runtime, error) {
	new := registry.Runtime{
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		Constraints: make(map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints),

		// Everything else below is just copied over unchanged.

		ID:              old.ID,
		EntityID:        old.EntityID,
		Genesis:         old.Genesis,
		Kind:            old.Kind,
		TEEHardware:     old.TEEHardware,
		Version:         old.Version,
		KeyManager:      old.KeyManager,
		Executor:        old.Executor,
		TxnScheduler:    old.TxnScheduler,
		Storage:         old.Storage,
		AdmissionPolicy: old.AdmissionPolicy,
		Staking:         old.Staking,
		GovernanceModel: old.GovernanceModel,
	}

	delete(old.Constraints, v4SchedulerCommitteeKindStorage)
	for k, v := range old.Constraints {
		new.Constraints[scheduler.CommitteeKind(k)] = v
	}

	return new, nil
}

func updateGovernanceGenesis(old *v4GovernanceGenesis) (governance.Genesis, error) {
	// Use `ceil(quorum * threshold / 100)` to work out the new voting power
	// threshold, as it should be close to what we want.  With the 75% quorum
	// and 90% threshold in the current genesis document this formula gives
	// a stake threshold of 68 (`ceil(75 * 90 / 100) = ceil(67.50) = 68`).
	stakeThreshold := math.Ceil(float64(old.Parameters.Quorum) * float64(old.Parameters.Threshold) / 100)

	new := governance.Genesis{
		Parameters: governance.ConsensusParameters{
			StakeThreshold: uint8(stakeThreshold),

			// Everything else below is just copied over unchanged.

			GasCosts:                  old.Parameters.GasCosts,
			MinProposalDeposit:        old.Parameters.MinProposalDeposit,
			VotingPeriod:              old.Parameters.VotingPeriod,
			UpgradeMinEpochDiff:       old.Parameters.UpgradeMinEpochDiff,
			UpgradeCancelMinEpochDiff: old.Parameters.UpgradeCancelMinEpochDiff,
		},

		// Everything else below is just copied over unchanged.

		Proposals:   old.Proposals,
		VoteEntries: old.VoteEntries,
	}
	return new, nil
}

func updateGenesisDoc(oldDoc v4Document) (*genesis.Document, error) {
	// Create the new genesis document template.
	newDoc := &genesis.Document{
		Height:     oldDoc.Height,
		Time:       oldDoc.Time,
		ChainID:    oldDoc.ChainID,
		RootHash:   oldDoc.RootHash,
		KeyManager: oldDoc.KeyManager,
		Scheduler:  oldDoc.Scheduler,
		Consensus:  oldDoc.Consensus,
		HaltEpoch:  oldDoc.HaltEpoch,
		ExtraData:  oldDoc.ExtraData,
	}

	var err error

	// Transition from the PVSS to VRF beacon, using approximately the
	// same parameters, and reasonable defaults.
	if newDoc.Beacon, err = updateBeaconGenesis(&oldDoc); err != nil {
		return nil, err
	}

	// Update staking genesis.
	if newDoc.Staking, err = updateStakingGenesis(&oldDoc.Staking); err != nil {
		return nil, err
	}

	// Update governance genesis.
	if newDoc.Governance, err = updateGovernanceGenesis(&oldDoc.Governance); err != nil {
		return nil, err
	}

	// Update roothash genesis.
	newDoc.RootHash.Parameters.MaxInRuntimeMessages = 128

	// Update registry genesis.
	newDoc.Registry = registry.Genesis{
		Parameters:   oldDoc.Registry.Parameters,
		NodeStatuses: oldDoc.Registry.NodeStatuses,
	}

	// Update runtimes.
	for _, oldRt := range oldDoc.Registry.Runtimes {
		var newRt registry.Runtime
		if newRt, err = updateRegistryRuntime(oldRt); err != nil {
			return nil, fmt.Errorf("failed to update runtime %s: %w", oldRt.ID, err)
		}
		newDoc.Registry.Runtimes = append(newDoc.Registry.Runtimes, &newRt)
	}
	for _, oldRt := range oldDoc.Registry.SuspendedRuntimes {
		var newRt registry.Runtime
		if newRt, err = updateRegistryRuntime(oldRt); err != nil {
			return nil, fmt.Errorf("failed to update suspended runtime %s: %w", oldRt.ID, err)
		}
		newDoc.Registry.SuspendedRuntimes = append(newDoc.Registry.SuspendedRuntimes, &newRt)
	}

	newDoc.Registry.Entities = make([]*entity.SignedEntity, 0)
	newDoc.Registry.Nodes = make([]*node.MultiSignedNode, 0)

	// Remove entities with not enough stake.
	var entities []*entity.Entity
	var nodes []*node.Node
	var runtimes []*registry.Runtime
	for _, sigEntity := range oldDoc.Registry.Entities {
		var entity entity.Entity
		if err = sigEntity.Open(registry.RegisterGenesisEntitySignatureContext, &entity); err != nil {
			return nil, fmt.Errorf("unable to open signed entity: %w", err)
		}
		entities = append(entities, &entity)
	}
	for _, sigNode := range oldDoc.Registry.Nodes {
		var node node.Node
		if err = sigNode.Open(registry.RegisterGenesisNodeSignatureContext, &node); err != nil {
			return nil, fmt.Errorf("unable to open signed node: %w", err)
		}
		nodes = append(nodes, &node)
	}
	runtimes = append(runtimes, newDoc.Registry.Runtimes...)
	runtimes = append(runtimes, newDoc.Registry.SuspendedRuntimes...)

	generatedEscrows, err := computeStakeClaims(
		entities,
		nodes,
		runtimes,
		newDoc.Staking.Parameters.Thresholds,
		newDoc.Staking.Ledger,
	)
	if err != nil {
		return nil, fmt.Errorf("unable to compute stake claims: %w", err)
	}

	removedEntities := make(map[signature.PublicKey]*entity.Entity)
	entityMap := make(map[signature.PublicKey]*entity.Entity)
	for _, sigEntity := range oldDoc.Registry.Entities {
		var entity entity.Entity
		if err := sigEntity.Open(registry.RegisterEntitySignatureContext, &entity); err != nil {
			return nil, fmt.Errorf("unable to open signed entity: %w", err)
		}
		addr := staking.NewAddress(entity.ID)
		escrowAcc := generatedEscrows[addr]
		if escrowAcc == nil {
			// Entity cannot pass stake claims, drop entity.
			logger.Warn("removing entity not passing stake claims: no account in ledger",
				"entity_id", entity.ID,
			)
			removedEntities[entity.ID] = &entity
			continue
		}

		if err := escrowAcc.CheckStakeClaims(newDoc.Staking.Parameters.Thresholds); err != nil {
			logger.Warn("removing entity not passing stake claims",
				"entity_id", entity.ID,
				"err", err,
			)
			removedEntities[entity.ID] = &entity
			continue
		}
		newDoc.Registry.Entities = append(newDoc.Registry.Entities, sigEntity)
		entityMap[entity.ID] = &entity
	}
	for _, sigNode := range oldDoc.Registry.Nodes {
		var node node.Node
		if err := sigNode.Open(registry.RegisterGenesisNodeSignatureContext, &node); err != nil {
			return nil, fmt.Errorf("unable to open signed node: %w", err)
		}
		if ent := removedEntities[node.EntityID]; ent != nil {
			logger.Warn("removing node as owning entity doesn't pass stake claims",
				"entity_id", node.EntityID,
				"node_id", node.ID,
			)
			continue
		}
		if !entityMap[node.EntityID].HasNode(node.ID) {
			logger.Warn("removing node as owning entity does not have it in its whitelist",
				"entity_id", node.EntityID,
				"node_id", node.ID,
			)
			continue
		}
		newDoc.Registry.Nodes = append(newDoc.Registry.Nodes, sigNode)
	}

	return newDoc, nil
}

func computeStakeClaims(
	entities []*entity.Entity,
	nodes []*node.Node,
	runtimes []*registry.Runtime,
	stakeThresholds map[staking.ThresholdKind]quantity.Quantity,
	accounts map[staking.Address]*staking.Account,
) (map[staking.Address]*staking.EscrowAccount, error) {
	computedStakeClaims := make(map[staking.Address]*staking.EscrowAccount)

	// Entity accounts.
	for _, entity := range entities {
		addr := staking.NewAddress(entity.ID)
		acc := accounts[addr]
		accumulator := staking.StakeAccumulator{
			Claims: make(map[staking.StakeClaim][]staking.StakeThreshold),
		}
		accumulator.AddClaimUnchecked(registry.StakeClaimRegisterEntity, staking.GlobalStakeThresholds(staking.KindEntity))
		computedStakeClaims[addr] = &staking.EscrowAccount{
			Active:           acc.Escrow.Active,
			StakeAccumulator: accumulator,
		}
	}

	// Runtime accounts.
	runtimeMap := make(map[common.Namespace]*registry.Runtime)
	for _, rt := range runtimes {
		runtimeMap[rt.ID] = rt

		if rt.GovernanceModel == registry.GovernanceRuntime {
			addr := staking.NewRuntimeAddress(rt.ID)
			acc := accounts[addr]
			accumulator := staking.StakeAccumulator{
				Claims: make(map[staking.StakeClaim][]staking.StakeThreshold),
			}
			computedStakeClaims[addr] = &staking.EscrowAccount{
				Active:           acc.Escrow.Active,
				StakeAccumulator: accumulator,
			}
		}
	}

	// Node stake claims.
	for _, node := range nodes {
		var nodeRts []*registry.Runtime
		for _, rt := range node.Runtimes {
			nodeRts = append(nodeRts, runtimeMap[rt.ID])
		}
		addr := staking.NewAddress(node.EntityID)
		computedStakeClaims[addr].StakeAccumulator.AddClaimUnchecked(registry.StakeClaimForNode(node.ID), registry.StakeThresholdsForNode(node, nodeRts))
	}

	// Runtime stake claims.
	for _, rt := range runtimes {
		addr := rt.StakingAddress()
		if addr == nil {
			continue
		}

		computedStakeClaims[*addr].StakeAccumulator.AddClaimUnchecked(registry.StakeClaimForRuntime(rt.ID), registry.StakeThresholdsForRuntime(rt))
	}

	return computedStakeClaims, nil
}

func updateBeaconGenesis(old *v4Document) (beacon.Genesis, error) {
	oldP := &old.Beacon.Parameters // Save some typing.

	// Check to see if we know how to set this up in a sensible manner.
	if oldP.DebugMockBackend || oldP.InsecureParameters != nil || oldP.DebugDeterministic {
		return beacon.Genesis{}, fmt.Errorf("existing document has debug/insecure beacon parameters set")
	}
	if oldP.Backend != "pvss" {
		return beacon.Genesis{}, fmt.Errorf("existing document is not using the PVSS beacon")
	}

	// Derive "reasonable" parameters based off the existing parameters.
	pvssP := oldP.PVSSParameters
	alphaHighQualityThreshold := uint64(pvssP.Participants)
	interval := pvssP.CommitInterval + pvssP.RevealInterval + pvssP.TransitionDelay
	proofSubmissionDelay := pvssP.CommitInterval

	return beacon.Genesis{
		Base: old.Beacon.Base,
		Parameters: beacon.ConsensusParameters{
			Backend:            beacon.BackendVRF,
			DebugMockBackend:   false,
			InsecureParameters: nil,
			VRFParameters: &beacon.VRFParameters{
				AlphaHighQualityThreshold: alphaHighQualityThreshold,
				Interval:                  interval,
				ProofSubmissionDelay:      proofSubmissionDelay,
				GasCosts:                  beacon.DefaultVRFGasCosts,
			},
		},
	}, nil
}

// Register registers the fix-genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	fixGenesisCmd.PersistentFlags().AddFlagSet(flags.GenesisFileFlags)
	fixGenesisCmd.PersistentFlags().AddFlagSet(newGenesisFlag)
	parentCmd.AddCommand(fixGenesisCmd)
}

func init() {
	newGenesisFlag.String(cfgNewGenesis, "genesis_fixed.json", "path to fixed genesis document")
	_ = viper.BindPFlags(newGenesisFlag)
}
