// Package fixgenesis implements the fix-genesis command.
package fixgenesis

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
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
	Registry registry.Genesis `json:"registry"`
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
	Governance governance.Genesis `json:"governance"`
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

type v4StakingGenesis struct {
	// Parameters are the staking consensus parameters.
	Parameters v4StakingConsensusParameters `json:"params"`

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

type v4StakingConsensusParameters struct { // nolint: maligned
	Thresholds                        map[staking.ThresholdKind]quantity.Quantity `json:"thresholds,omitempty"`
	DebondingInterval                 beacon.EpochTime                            `json:"debonding_interval,omitempty"`
	RewardSchedule                    []staking.RewardStep                        `json:"reward_schedule,omitempty"`
	SigningRewardThresholdNumerator   uint64                                      `json:"signing_reward_threshold_numerator,omitempty"`
	SigningRewardThresholdDenominator uint64                                      `json:"signing_reward_threshold_denominator,omitempty"`
	CommissionScheduleRules           staking.CommissionScheduleRules             `json:"commission_schedule_rules,omitempty"`
	Slashing                          map[string]staking.Slash                    `json:"slashing,omitempty"`
	GasCosts                          transaction.Costs                           `json:"gas_costs,omitempty"`
	MinDelegationAmount               quantity.Quantity                           `json:"min_delegation"`

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

func updateGenesisDoc(oldDoc v4Document) (*genesis.Document, error) {
	// Create the new genesis document template.
	newDoc := &genesis.Document{
		Height:     oldDoc.Height,
		Time:       oldDoc.Time,
		ChainID:    oldDoc.ChainID,
		Registry:   oldDoc.Registry,
		RootHash:   oldDoc.RootHash,
		KeyManager: oldDoc.KeyManager,
		Scheduler:  oldDoc.Scheduler,
		Governance: oldDoc.Governance,
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

	// Fix up the staking state.
	if newDoc.Staking, err = updateStakeGenesis(&oldDoc); err != nil {
		return nil, err
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

func updateStakeGenesis(old *v4Document) (staking.Genesis, error) {
	var newS staking.Genesis

	oldS := old.Staking // Shallow copy

	// Instead of doing something as error-prone as copying every field
	// apart from the slashing parameters, do this instead.
	newSlash := make(map[string]staking.Slash)
	for reason, slash := range oldS.Parameters.Slashing {
		switch reason {
		case slashBeaconInvalidCommitName, slashBeaconInvalidRevealName, slashBeaconNonparticipationName:
			// These conditions no longer exist.
		default:
			newSlash[reason] = slash
		}
	}
	oldS.Parameters.Slashing = newSlash

	b, err := json.Marshal(oldS)
	if err != nil {
		return staking.Genesis{}, fmt.Errorf("failed to reserialize patched stake: %w", err)
	}

	if err = json.Unmarshal(b, &newS); err != nil {
		return staking.Genesis{}, fmt.Errorf("failed to deserialize patched stake: %w", err)
	}

	return newS, nil
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
