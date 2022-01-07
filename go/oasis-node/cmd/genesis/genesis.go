// Package genesis implements the genesis sub-commands.
package genesis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/diff"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	tendermint "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisFile "github.com/oasisprotocol/oasis-core/go/genesis/file"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	cmdCmnGenesis "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/genesis"
	cmdGrpc "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	cfgEntity        = "entity"
	cfgRuntime       = "runtime"
	cfgNode          = "node"
	cfgRootHash      = "roothash"
	cfgKeyManager    = "keymanager"
	cfgStaking       = "staking"
	cfgBlockHeight   = "height"
	cfgChainID       = "chain.id"
	cfgHaltEpoch     = "halt.epoch"
	cfgInitialHeight = "initial_height"

	// Registry config flags.
	CfgRegistryMaxNodeExpiration             = "registry.max_node_expiration"
	CfgRegistryDisableRuntimeRegistration    = "registry.disable_runtime_registration"
	cfgRegistryDebugAllowUnroutableAddresses = "registry.debug.allow_unroutable_addresses"
	CfgRegistryDebugAllowTestRuntimes        = "registry.debug.allow_test_runtimes"
	cfgRegistryDebugBypassStake              = "registry.debug.bypass_stake" // nolint: gosec
	cfgRegistryEnableRuntimeGovernanceModels = "registry.enable_runtime_governance_models"

	// Scheduler config flags.
	cfgSchedulerMinValidators          = "scheduler.min_validators"
	cfgSchedulerMaxValidators          = "scheduler.max_validators"
	cfgSchedulerMaxValidatorsPerEntity = "scheduler.max_validators_per_entity"
	cfgSchedulerDebugBypassStake       = "scheduler.debug.bypass_stake" // nolint: gosec
	CfgSchedulerDebugForceElect        = "scheduler.debug.force_elect"
	CfgSchedulerDebugAllowWeakAlpha    = "scheduler.debug.allow_weak_alpha"

	// Governance config flags.
	CfgGovernanceMinProposalDeposit        = "governance.min_proposal_deposit"
	CfgGovernanceStakeThreshold            = "governance.stake_threshold"
	CfgGovernanceUpgradeCancelMinEpochDiff = "governance.upgrade_cancel_min_epoch_diff"
	CfgGovernanceUpgradeMinEpochDiff       = "governance.upgrade_min_epoch_diff"
	CfgGovernanceVotingPeriod              = "governance.voting_period"

	// Beacon config flags.
	CfgBeaconBackend                    = "beacon.backend"
	CfgBeaconDebugMockBackend           = "beacon.debug.mock_backend"
	CfgBeaconInsecureTendermintInterval = "beacon.insecure.tendermint.interval"
	CfgBeaconVRFAlphaThreshold          = "beacon.vrf.alpha_threshold"
	CfgBeaconVRFInterval                = "beacon.vrf.interval"
	CfgBeaconVRFProofSubmissionDelay    = "beacon.vrf.submission_delay"

	// Roothash config flags.
	cfgRoothashDebugDoNotSuspendRuntimes = "roothash.debug.do_not_suspend_runtimes"
	cfgRoothashDebugBypassStake          = "roothash.debug.bypass_stake" // nolint: gosec
	cfgRoothashMaxRuntimeMessages        = "roothash.max_runtime_messages"
	cfgRoothashMaxInRuntimeMessages      = "roothash.max_in_runtime_messages"

	// Staking config flags.
	CfgStakingTokenSymbol        = "staking.token_symbol"
	CfgStakingTokenValueExponent = "staking.token_value_exponent"

	// Tendermint config flags.
	cfgConsensusTimeoutCommit            = "consensus.tendermint.timeout_commit"
	cfgConsensusSkipTimeoutCommit        = "consensus.tendermint.skip_timeout_commit"
	cfgConsensusEmptyBlockInterval       = "consensus.tendermint.empty_block_interval"
	cfgConsensusMaxTxSizeBytes           = "consensus.tendermint.max_tx_size"
	cfgConsensusMaxBlockSizeBytes        = "consensus.tendermint.max_block_size"
	cfgConsensusMaxBlockGas              = "consensus.tendermint.max_block_gas"
	cfgConsensusMaxEvidenceSizeBytes     = "consensus.tendermint.max_evidence_size"
	CfgConsensusStateCheckpointInterval  = "consensus.state_checkpoint.interval"
	CfgConsensusStateCheckpointNumKept   = "consensus.state_checkpoint.num_kept"
	CfgConsensusStateCheckpointChunkSize = "consensus.state_checkpoint.chunk_size"
	CfgConsensusGasCostsTxByte           = "consensus.gas_costs.tx_byte"
	cfgConsensusBlacklistPublicKey       = "consensus.blacklist_public_key"

	// Consensus backend config flag.
	cfgConsensusBackend = "consensus.backend"

	// Our 'entity' flag overlaps with the common flag 'entity'.
	// We bind it to a separate Viper key to disambiguate at runtime.
	viperEntity = "provision_entity"
)

var (
	checkGenesisFlags = flag.NewFlagSet("", flag.ContinueOnError)
	dumpGenesisFlags  = flag.NewFlagSet("", flag.ContinueOnError)
	initGenesisFlags  = flag.NewFlagSet("", flag.ContinueOnError)

	genesisCmd = &cobra.Command{
		Use:   "genesis",
		Short: "genesis block utilities",
	}

	initGenesisCmd = &cobra.Command{
		Use:   "init",
		Short: "initialize the genesis file",
		Run:   doInitGenesis,
	}

	dumpGenesisCmd = &cobra.Command{
		Use:   "dump",
		Short: "dump state into genesis file",
		Run:   doDumpGenesis,
	}

	checkGenesisCmd = &cobra.Command{
		Use:   "check",
		Short: "sanity check the genesis file",
		Run:   doCheckGenesis,
	}

	logger = logging.GetLogger("cmd/genesis")
)

func doInitGenesis(cmd *cobra.Command, args []string) {
	var ok bool
	defer func() {
		if !ok {
			os.Exit(1)
		}
	}()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	f := flags.GenesisFile()
	if len(f) == 0 {
		logger.Error("failed to determine output location")
		return
	}

	chainID := viper.GetString(cfgChainID)
	if chainID == "" {
		logger.Error("genesis chain id missing")
		return
	}

	// Build the genesis state, if any.
	doc := &genesis.Document{
		Height:    viper.GetInt64(cfgInitialHeight),
		ChainID:   chainID,
		Time:      time.Now(),
		HaltEpoch: beacon.EpochTime(viper.GetUint64(cfgHaltEpoch)),
	}
	entities := viper.GetStringSlice(viperEntity)
	runtimes := viper.GetStringSlice(cfgRuntime)
	nodes := viper.GetStringSlice(cfgNode)
	if err := AppendRegistryState(doc, entities, runtimes, nodes, logger); err != nil {
		logger.Error("failed to parse registry genesis state",
			"err", err,
		)
		return
	}

	rh := viper.GetStringSlice(cfgRootHash)
	if err := AppendRootHashState(doc, rh, logger); err != nil {
		logger.Error("failed to parse roothash genesis state",
			"err", err,
		)
		return
	}

	keymanager := viper.GetStringSlice(cfgKeyManager)
	if err := AppendKeyManagerState(doc, keymanager, logger); err != nil {
		logger.Error("failed to parse key manager genesis state",
			"err", err,
		)
		return
	}

	stakingStatePath := viper.GetString(cfgStaking)
	if err := appendStakingState(doc, stakingStatePath); err != nil {
		logger.Error("failed to append staking genesis state",
			"err", err,
		)
		return
	}

	doc.Scheduler = scheduler.Genesis{
		Parameters: scheduler.ConsensusParameters{
			MinValidators:          viper.GetInt(cfgSchedulerMinValidators),
			MaxValidators:          viper.GetInt(cfgSchedulerMaxValidators),
			MaxValidatorsPerEntity: viper.GetInt(cfgSchedulerMaxValidatorsPerEntity),
			DebugBypassStake:       viper.GetBool(cfgSchedulerDebugBypassStake),
			DebugAllowWeakAlpha:    viper.GetBool(CfgSchedulerDebugAllowWeakAlpha),
		},
	}
	if forceElectStrs := viper.GetStringSlice(CfgSchedulerDebugForceElect); forceElectStrs != nil {
		m := make(map[common.Namespace]map[signature.PublicKey]*scheduler.ForceElectCommitteeRole)
		for _, s := range forceElectStrs {
			subS := strings.Split(s, ",")
			if len(subS) != 5 {
				tmp, _ := json.Marshal(subS)
				logger.Error("malformed forced scheduler elect directive",
					"directive", s,
					"sub_s", string(tmp),
				)
				return
			}
			var (
				ns common.Namespace
				pk signature.PublicKey
			)
			if err := ns.UnmarshalText([]byte(subS[0])); err != nil {
				logger.Error("failed to parse namespace for forced election",
					"err", err,
					"ns_str", subS[0],
				)
				return
			}
			if err := pk.UnmarshalText([]byte(subS[1])); err != nil {
				logger.Error("failed to parse public key for forced election",
					"err", err,
					"pk_str", subS[1],
				)
				return
			}
			i, err := strconv.Atoi(subS[2])
			if err != nil {
				logger.Error("failed to parse kind for forced election",
					"err", err,
					"kind_str", subS[2],
				)
				return
			}
			j, err := strconv.Atoi(subS[3])
			if err != nil {
				logger.Error("failed to parse role for forced election",
					"err", err,
					"role_str", subS[3],
				)
				return
			}
			k, err := strconv.ParseBool(subS[4])
			if err != nil {
				logger.Error("failed to parse is_scheduler for forced election",
					"err", err,
					"is_scheduler_str", subS[4],
				)
				return
			}
			subM := m[ns]
			if subM == nil {
				subM = make(map[signature.PublicKey]*scheduler.ForceElectCommitteeRole)
				m[ns] = subM
			}
			m[ns][pk] = &scheduler.ForceElectCommitteeRole{
				Kind:        scheduler.CommitteeKind(i),
				Role:        scheduler.Role(j),
				IsScheduler: k,
			}
		}
		doc.Scheduler.Parameters.DebugForceElect = m
	}

	doc.Governance = governance.Genesis{
		Parameters: governance.ConsensusParameters{
			GasCosts:                  governance.DefaultGasCosts, // TODO: configurable.
			MinProposalDeposit:        *quantity.NewFromUint64(viper.GetUint64(CfgGovernanceMinProposalDeposit)),
			StakeThreshold:            uint8(viper.GetInt(CfgGovernanceStakeThreshold)),
			UpgradeCancelMinEpochDiff: beacon.EpochTime(viper.GetUint64(CfgGovernanceUpgradeCancelMinEpochDiff)),
			UpgradeMinEpochDiff:       beacon.EpochTime(viper.GetUint64(CfgGovernanceUpgradeMinEpochDiff)),
			VotingPeriod:              beacon.EpochTime(viper.GetUint64(CfgGovernanceVotingPeriod)),
		},
	}

	doc.Beacon = beacon.Genesis{
		Parameters: beacon.ConsensusParameters{
			Backend:          viper.GetString(CfgBeaconBackend),
			DebugMockBackend: viper.GetBool(CfgBeaconDebugMockBackend),
		},
	}
	switch doc.Beacon.Parameters.Backend {
	case beacon.BackendInsecure:
		doc.Beacon.Parameters.InsecureParameters = &beacon.InsecureParameters{
			Interval: viper.GetInt64(CfgBeaconInsecureTendermintInterval),
		}
	case beacon.BackendVRF:
		doc.Beacon.Parameters.VRFParameters = &beacon.VRFParameters{
			AlphaHighQualityThreshold: viper.GetUint64(CfgBeaconVRFAlphaThreshold),
			Interval:                  viper.GetInt64(CfgBeaconVRFInterval),
			ProofSubmissionDelay:      viper.GetInt64(CfgBeaconVRFProofSubmissionDelay),
			GasCosts:                  beacon.DefaultVRFGasCosts, // TODO: configurable.
		}
	default:
		logger.Error("unsupported beacon backend",
			"backend", doc.Beacon.Parameters.Backend,
		)
		return
	}

	pkBlacklist, pkErr := parsePublicKeyStringSlice(cfgConsensusBlacklistPublicKey)
	if pkErr != nil {
		logger.Error("failed to parse blacklisted public key",
			"err", pkErr,
		)
		return
	}

	doc.Consensus = consensusGenesis.Genesis{
		Backend: viper.GetString(cfgConsensusBackend),
		Parameters: consensusGenesis.Parameters{
			TimeoutCommit:            viper.GetDuration(cfgConsensusTimeoutCommit),
			SkipTimeoutCommit:        viper.GetBool(cfgConsensusSkipTimeoutCommit),
			EmptyBlockInterval:       viper.GetDuration(cfgConsensusEmptyBlockInterval),
			MaxTxSize:                uint64(viper.GetSizeInBytes(cfgConsensusMaxTxSizeBytes)),
			MaxBlockSize:             uint64(viper.GetSizeInBytes(cfgConsensusMaxBlockSizeBytes)),
			MaxBlockGas:              transaction.Gas(viper.GetUint64(cfgConsensusMaxBlockGas)),
			MaxEvidenceSize:          uint64(viper.GetSizeInBytes(cfgConsensusMaxEvidenceSizeBytes)),
			StateCheckpointInterval:  viper.GetUint64(CfgConsensusStateCheckpointInterval),
			StateCheckpointNumKept:   viper.GetUint64(CfgConsensusStateCheckpointNumKept),
			StateCheckpointChunkSize: uint64(viper.GetSizeInBytes(CfgConsensusStateCheckpointChunkSize)),
			GasCosts: transaction.Costs{
				consensusGenesis.GasOpTxByte: transaction.Gas(viper.GetUint64(CfgConsensusGasCostsTxByte)),
			},
			PublicKeyBlacklist: pkBlacklist,
		},
	}

	// Ensure consistency/sanity.
	if err := doc.SanityCheck(); err != nil {
		logger.Error("genesis document failed sanity check",
			"err", err,
		)
		return
	}

	canonJSON, err := doc.CanonicalJSON()
	if err != nil {
		logger.Error("failed to get canonical form of genesis file",
			"err", err,
		)
		return
	}
	if err := ioutil.WriteFile(f, canonJSON, 0o600); err != nil {
		logger.Error("failed to write genesis file",
			"err", err,
		)
		return
	}

	ok = true
}

// AppendRegistryState appends the registry genesis state given a vector
// of entity registrations and runtime registrations.
func AppendRegistryState(doc *genesis.Document, entities, runtimes, nodes []string, l *logging.Logger) error {
	regSt := registry.Genesis{
		Parameters: registry.ConsensusParameters{
			DebugAllowUnroutableAddresses: viper.GetBool(cfgRegistryDebugAllowUnroutableAddresses),
			DebugAllowTestRuntimes:        viper.GetBool(CfgRegistryDebugAllowTestRuntimes),
			DebugBypassStake:              viper.GetBool(cfgRegistryDebugBypassStake),
			GasCosts:                      registry.DefaultGasCosts, // TODO: Make these configurable.
			MaxNodeExpiration:             viper.GetUint64(CfgRegistryMaxNodeExpiration),
			DisableRuntimeRegistration:    viper.GetBool(CfgRegistryDisableRuntimeRegistration),
			EnableRuntimeGovernanceModels: make(map[registry.RuntimeGovernanceModel]bool),
		},
		Entities: make([]*entity.SignedEntity, 0, len(entities)),
		Runtimes: make([]*registry.Runtime, 0, len(runtimes)),
		Nodes:    make([]*node.MultiSignedNode, 0, len(nodes)),
	}

	for _, gmStr := range viper.GetStringSlice(cfgRegistryEnableRuntimeGovernanceModels) {
		var gm registry.RuntimeGovernanceModel
		if err := gm.UnmarshalText([]byte(strings.ToLower(gmStr))); err != nil {
			return fmt.Errorf("%w: '%s'", err, gmStr)
		}
		regSt.Parameters.EnableRuntimeGovernanceModels[gm] = true
	}

	entMap := make(map[signature.PublicKey]bool)
	appendToEntities := func(signedEntity *entity.SignedEntity, ent *entity.Entity) error {
		if entMap[ent.ID] {
			return errors.New("genesis: duplicate entity registration")
		}
		entMap[ent.ID] = true

		regSt.Entities = append(regSt.Entities, signedEntity)

		return nil
	}

	loadSignedEntity := func(fn string) (*entity.SignedEntity, *entity.Entity, error) {
		b, err := ioutil.ReadFile(fn)
		if err != nil {
			return nil, nil, err
		}

		var signedEntity entity.SignedEntity
		if err = json.Unmarshal(b, &signedEntity); err != nil {
			return nil, nil, err
		}

		var ent entity.Entity
		if err := signedEntity.Open(registry.RegisterGenesisEntitySignatureContext, &ent); err != nil {
			return nil, nil, err
		}

		return &signedEntity, &ent, nil
	}

	for _, v := range entities {
		signedEntity, ent, err := loadSignedEntity(v)
		if err != nil {
			l.Error("failed to load genesis entity",
				"err", err,
				"filename", v,
			)
			return err
		}

		if err = appendToEntities(signedEntity, ent); err != nil {
			l.Error("failed to process genesis entity",
				"err", err,
				"filename", v,
			)
		}
	}
	if flags.DebugTestEntity() {
		l.Warn("registering debug test entity")

		ent, signer, err := entity.TestEntity()
		if err != nil {
			l.Error("failed to retrieve test entity",
				"err", err,
			)
			return err
		}

		signedEntity, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, ent)
		if err != nil {
			l.Error("failed to sign test entity",
				"err", err,
			)
			return err
		}

		if err = appendToEntities(signedEntity, ent); err != nil {
			l.Error("failed to process test entity",
				"err", err,
			)
			return err
		}
	}

	for _, v := range runtimes {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis runtime registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var rt registry.Runtime
		if err = json.Unmarshal(b, &rt); err != nil {
			l.Error("failed to parse genesis runtime registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Runtimes = append(regSt.Runtimes, &rt)
	}

	for _, v := range nodes {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis node registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		var n node.MultiSignedNode
		if err = json.Unmarshal(b, &n); err != nil {
			l.Error("failed to parse genesis node registration",
				"err", err,
				"filename", v,
			)
			return err
		}

		regSt.Nodes = append(regSt.Nodes, &n)
	}

	doc.Registry = regSt

	return nil
}

// AppendRootHashState appends the roothash genesis state given files with
// exported runtime states.
func AppendRootHashState(doc *genesis.Document, exports []string, l *logging.Logger) error {
	rootSt := roothash.Genesis{
		RuntimeStates: make(map[common.Namespace]*roothash.GenesisRuntimeState),

		Parameters: roothash.ConsensusParameters{
			DebugDoNotSuspendRuntimes: viper.GetBool(cfgRoothashDebugDoNotSuspendRuntimes),
			DebugBypassStake:          viper.GetBool(cfgRoothashDebugBypassStake),
			MaxRuntimeMessages:        viper.GetUint32(cfgRoothashMaxRuntimeMessages),
			MaxInRuntimeMessages:      viper.GetUint32(cfgRoothashMaxInRuntimeMessages),
			// TODO: Make these configurable.
			GasCosts: roothash.DefaultGasCosts,
		},
	}

	for _, v := range exports {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis roothash runtime states",
				"err", err,
				"filename", v,
			)
			return err
		}

		var rtStates map[common.Namespace]*roothash.GenesisRuntimeState
		if err = json.Unmarshal(b, &rtStates); err != nil {
			l.Error("failed to parse genesis roothash runtime states",
				"err", err,
				"filename", v,
			)
			return err
		}

		for id, rtg := range rtStates {
			// Each runtime state must be described exactly once!
			if _, ok := rootSt.RuntimeStates[id]; ok {
				l.Error("duplicate genesis roothash runtime state",
					"runtime_id", id,
					"block", rtg,
				)
				return errors.New("duplicate genesis roothash runtime states")
			}
			rootSt.RuntimeStates[id] = rtg
		}
	}

	doc.RootHash = rootSt

	return nil
}

// AppendKeyManagerState appends the key manager genesis state given a vector of
// key manager statuses.
func AppendKeyManagerState(doc *genesis.Document, statuses []string, l *logging.Logger) error {
	var kmSt keymanager.Genesis

	for _, v := range statuses {
		b, err := ioutil.ReadFile(v)
		if err != nil {
			l.Error("failed to load genesis key manager status",
				"err", err,
				"filename", v,
			)
			return err
		}

		var status keymanager.Status
		if err = json.Unmarshal(b, &status); err != nil {
			l.Error("failed to parse genesis key manager status",
				"err", err,
				"filename", v,
			)
			return err
		}

		kmSt.Statuses = append(kmSt.Statuses, &status)
	}

	doc.KeyManager = kmSt

	return nil
}

func appendStakingState(doc *genesis.Document, statePath string) error {
	var (
		st  *cmdCmnGenesis.AppendableStakingState
		err error
	)

	switch statePath {
	case "":
		st, err = cmdCmnGenesis.NewAppendableStakingState()
	default:
		st, err = cmdCmnGenesis.NewAppendableStakingStateFromFile(statePath)
	}
	if err != nil {
		return err
	}

	// Apply config based overrides to the state.
	st.DebugTestEntity = flags.DebugTestEntity()
	if tokenSymbol := viper.GetString(CfgStakingTokenSymbol); tokenSymbol != "" {
		st.State.TokenSymbol = tokenSymbol
	}
	// NOTE: The viper package doesn't have a GetUint8() method, so we defer to
	// using strconv.ParseUint().
	tokenValueExponentUint64, err := strconv.ParseUint(viper.Get(CfgStakingTokenValueExponent).(string), 10, 8)
	if err != nil {
		// NOTE: This shouldn't happen at all since CfgStakingTokenValueExponent
		// flag is bound to an uint8.
		panic(err)
	}
	if tokenValueExponent := uint8(tokenValueExponentUint64); tokenValueExponent != 0 {
		st.State.TokenValueExponent = tokenValueExponent
	}

	if err = st.AppendTo(doc); err != nil {
		return err
	}

	return nil
}

func doDumpGenesis(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	conn, err := cmdGrpc.NewClient(cmd)
	if err != nil {
		logger.Error("failed to establish connection with node",
			"err", err,
		)
		os.Exit(1)
	}
	defer conn.Close()

	client := consensus.NewConsensusClient(conn)

	doc, err := client.StateToGenesis(ctx, viper.GetInt64(cfgBlockHeight))
	if err != nil {
		logger.Error("failed to generate genesis document",
			"err", err,
		)
		os.Exit(1)
	}

	w, shouldClose, err := cmdCommon.GetOutputWriter(cmd, flags.CfgGenesisFile)
	if err != nil {
		logger.Error("failed to get writer for genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if shouldClose {
		defer w.Close()
	}

	canonJSON, err := doc.CanonicalJSON()
	if err != nil {
		logger.Error("failed to get canonical form of genesis file",
			"err", err,
		)
		os.Exit(1)
	}
	if _, err = w.Write(canonJSON); err != nil {
		logger.Error("failed to write genesis file",
			"err", err,
		)
		os.Exit(1)
	}
}

func doCheckGenesis(cmd *cobra.Command, args []string) {
	if err := cmdCommon.Init(); err != nil {
		cmdCommon.EarlyLogAndExit(err)
	}

	filename := flags.GenesisFile()
	provider, err := genesisFile.NewFileProvider(filename)
	if err != nil {
		logger.Error("failed to open genesis file", "err", err)
		os.Exit(1)
	}
	// NOTE: The genesis document sanity checks are performed inside the
	// NewFileProvider() function.
	doc, err := provider.GetGenesisDocument()
	if err != nil {
		logger.Error("failed to get genesis document", "err", err)
		os.Exit(1)
	}

	// Load genesis file to check if it is in the canonical form.
	actualGenesis, err := ioutil.ReadFile(filename)
	if err != nil {
		logger.Error("failed to read genesis file:", "err", err)
		os.Exit(1)
	}
	// Get canonical form of the genesis document serialized into a file.
	canonicalJSON, err := doc.CanonicalJSON()
	if err != nil {
		logger.Error("failed to get canonical form of genesis file", "err", err)
		os.Exit(1)
	}
	// Actual genesis file should equal the canonical form.
	if !bytes.Equal(actualGenesis, canonicalJSON) {
		var err error
		if len(strings.Split(strings.TrimSpace(string(actualGenesis)), "\n")) == 1 {
			err = fmt.Errorf("genesis file has everything on a single line")
		} else {
			err = fmt.Errorf("genesis file is not in canonical form, see the diff on stderr")
		}
		diff, derr := diff.UnifiedDiffString(
			string(actualGenesis), string(canonicalJSON), "Actual", "Canonical")
		if derr != nil {
			err = fmt.Errorf("genesis file is not in canonical form, error computing diff: %w", derr)
		}
		logger.Error("genesis file is not in canonical form", "err", err)
		if derr == nil {
			fmt.Fprintf(os.Stderr, "Diff:\n%s\n", diff)
		}
		os.Exit(1)
	}

	fmt.Println("genesis file is valid and in canonical form")
	fmt.Printf("genesis document's hash: %s\n", doc.ChainContext())
	fmt.Printf("genesis file's SHA256 checksum: ")

	sha256Hasher := sha256.New()
	_, herr := sha256Hasher.Write(actualGenesis)
	switch herr {
	case nil:
		fmt.Printf("%x\n", sha256Hasher.Sum(nil))
	default:
		fmt.Println("[unknown]")
	}
}

// Register registers the genesis sub-command and all of it's children.
func Register(parentCmd *cobra.Command) {
	initGenesisCmd.Flags().AddFlagSet(initGenesisFlags)
	dumpGenesisCmd.Flags().AddFlagSet(dumpGenesisFlags)
	dumpGenesisCmd.PersistentFlags().AddFlagSet(cmdGrpc.ClientFlags)
	checkGenesisCmd.Flags().AddFlagSet(checkGenesisFlags)

	for _, v := range []*cobra.Command{
		initGenesisCmd,
		dumpGenesisCmd,
		checkGenesisCmd,
	} {
		genesisCmd.AddCommand(v)
	}

	parentCmd.AddCommand(genesisCmd)
}

func init() {
	_ = viper.BindPFlags(checkGenesisFlags)
	checkGenesisFlags.AddFlagSet(flags.GenesisFileFlags)

	dumpGenesisFlags.Int64(cfgBlockHeight, consensus.HeightLatest, "block height at which to dump state")
	_ = viper.BindPFlags(dumpGenesisFlags)
	dumpGenesisFlags.AddFlagSet(flags.GenesisFileFlags)

	initGenesisFlags.StringSlice(cfgRuntime, nil, "path to runtime registration file")
	initGenesisFlags.StringSlice(cfgNode, nil, "path to node registration file")
	initGenesisFlags.StringSlice(cfgRootHash, nil, "path to roothash genesis runtime states file")
	initGenesisFlags.String(cfgStaking, "", "path to staking genesis file")
	initGenesisFlags.StringSlice(cfgKeyManager, nil, "path to key manager genesis status file")
	initGenesisFlags.String(cfgChainID, "", "genesis chain id")
	initGenesisFlags.Uint64(cfgHaltEpoch, math.MaxUint64, "genesis halt epoch height")
	initGenesisFlags.Int64(cfgInitialHeight, 1, "initial block height")

	// Registry config flags.
	initGenesisFlags.Uint64(CfgRegistryMaxNodeExpiration, 5, "maximum node registration lifespan in epochs")
	initGenesisFlags.Bool(CfgRegistryDisableRuntimeRegistration, false, "disable non-genesis runtime registration")
	initGenesisFlags.Bool(cfgRegistryDebugAllowUnroutableAddresses, false, "allow unroutable addreses (UNSAFE)")
	initGenesisFlags.Bool(CfgRegistryDebugAllowTestRuntimes, false, "enable test runtime registration")
	initGenesisFlags.Bool(cfgRegistryDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")
	initGenesisFlags.StringSlice(cfgRegistryEnableRuntimeGovernanceModels, []string{"entity"}, "set of enabled runtime governance models")
	_ = initGenesisFlags.MarkHidden(cfgRegistryDebugAllowUnroutableAddresses)
	_ = initGenesisFlags.MarkHidden(CfgRegistryDebugAllowTestRuntimes)
	_ = initGenesisFlags.MarkHidden(cfgRegistryDebugBypassStake)

	// Scheduler config flags.
	initGenesisFlags.Int(cfgSchedulerMinValidators, 1, "minimum number of validators")
	initGenesisFlags.Int(cfgSchedulerMaxValidators, 100, "maximum number of validators")
	initGenesisFlags.Int(cfgSchedulerMaxValidatorsPerEntity, 1, "maximum number of validators per entity")
	initGenesisFlags.Bool(cfgSchedulerDebugBypassStake, false, "bypass all stake checks and operations (UNSAFE)")
	initGenesisFlags.StringSlice(CfgSchedulerDebugForceElect, nil, "force elect the (runtime, node, role) tuple(s) (UNSAFE)")
	initGenesisFlags.Bool(CfgSchedulerDebugAllowWeakAlpha, false, "bypass alpha strength check for VRF elections (UNSAFE)")
	_ = initGenesisFlags.MarkHidden(cfgSchedulerDebugBypassStake)
	_ = initGenesisFlags.MarkHidden(CfgSchedulerDebugForceElect)
	_ = initGenesisFlags.MarkHidden(CfgSchedulerDebugAllowWeakAlpha)

	// Governance config flags.
	initGenesisFlags.Uint64(CfgGovernanceMinProposalDeposit, 100, "proposal deposit for governance proposals")
	initGenesisFlags.Uint8(CfgGovernanceStakeThreshold, 90, "required stake threshold for governance proposals to be accepted")
	initGenesisFlags.Uint64(CfgGovernanceUpgradeCancelMinEpochDiff, 300, "minimum number of epochs in advance for canceling proposals")
	initGenesisFlags.Uint64(CfgGovernanceUpgradeMinEpochDiff, 300, "minimum number of epochs the upgrade needs to be scheduled in advance")
	initGenesisFlags.Uint64(CfgGovernanceVotingPeriod, 100, "voting period (in epochs)")

	// Beacon config flags.
	initGenesisFlags.String(CfgBeaconBackend, "insecure", "beacon backend")
	initGenesisFlags.Bool(CfgBeaconDebugMockBackend, false, "use debug mock Epoch time backend")
	initGenesisFlags.Int64(CfgBeaconInsecureTendermintInterval, 86400, "Epoch interval (in blocks)")
	initGenesisFlags.Uint64(CfgBeaconVRFAlphaThreshold, 1, "Number of proofs required to allow runtime elections")
	initGenesisFlags.Int64(CfgBeaconVRFInterval, 86300, "Epoch interval (in blocks)")
	initGenesisFlags.Int64(CfgBeaconVRFProofSubmissionDelay, 43150, "Proof submission delay (in blocks)")
	_ = initGenesisFlags.MarkHidden(CfgBeaconDebugMockBackend)

	// Roothash config flags.
	initGenesisFlags.Bool(cfgRoothashDebugDoNotSuspendRuntimes, false, "do not suspend runtimes (UNSAFE)")
	initGenesisFlags.Bool(cfgRoothashDebugBypassStake, false, "bypass all roothash stake checks and operations (UNSAFE)")
	initGenesisFlags.Uint32(cfgRoothashMaxRuntimeMessages, 128, "maximum number of runtime messages submitted in a round")
	initGenesisFlags.Uint32(cfgRoothashMaxInRuntimeMessages, 128, "maximum number of ququed incoming runtime messages")
	_ = initGenesisFlags.MarkHidden(cfgRoothashDebugDoNotSuspendRuntimes)
	_ = initGenesisFlags.MarkHidden(cfgRoothashDebugBypassStake)

	// Staking config flags.
	initGenesisFlags.String(CfgStakingTokenSymbol, "", "token's ticker symbol")
	initGenesisFlags.Uint8(CfgStakingTokenValueExponent, 0, "token value's base-10 exponent")

	// Tendermint config flags.
	initGenesisFlags.Duration(cfgConsensusTimeoutCommit, 1*time.Second, "tendermint commit timeout")
	initGenesisFlags.Bool(cfgConsensusSkipTimeoutCommit, false, "skip tendermint commit timeout")
	initGenesisFlags.Duration(cfgConsensusEmptyBlockInterval, 0*time.Second, "tendermint empty block interval")
	initGenesisFlags.String(cfgConsensusMaxTxSizeBytes, "32kb", "tendermint maximum transaction size (in bytes)")
	initGenesisFlags.String(cfgConsensusMaxBlockSizeBytes, "21mb", "tendermint maximum block size (in bytes)")
	initGenesisFlags.Uint64(cfgConsensusMaxBlockGas, 0, "tendermint max gas used per block")
	initGenesisFlags.String(cfgConsensusMaxEvidenceSizeBytes, "1mb", "tendermint max evidence size (in bytes)")
	initGenesisFlags.Uint64(CfgConsensusStateCheckpointInterval, 10000, "consensus state checkpoint interval (in blocks)")
	initGenesisFlags.Uint64(CfgConsensusStateCheckpointNumKept, 2, "number of kept consensus state checkpoints")
	initGenesisFlags.String(CfgConsensusStateCheckpointChunkSize, "8mb", "consensus state checkpoint chunk size (in bytes)")
	initGenesisFlags.Uint64(CfgConsensusGasCostsTxByte, 1, "consensus gas costs: each transaction byte")
	initGenesisFlags.StringSlice(cfgConsensusBlacklistPublicKey, nil, "blacklist public key")

	// Consensus backend flag.
	initGenesisFlags.String(cfgConsensusBackend, tendermint.BackendName, "consensus backend")

	_ = viper.BindPFlags(initGenesisFlags)
	initGenesisFlags.StringSlice(cfgEntity, nil, "path to entity registration file")
	_ = viper.BindPFlag(viperEntity, initGenesisFlags.Lookup(cfgEntity))
	initGenesisFlags.AddFlagSet(flags.DebugTestEntityFlags)
	initGenesisFlags.AddFlagSet(flags.GenesisFileFlags)
	initGenesisFlags.AddFlagSet(flags.DebugDontBlameOasisFlag)
}

func parsePublicKeyStringSlice(cfg string) ([]signature.PublicKey, error) {
	var pks []signature.PublicKey
	for _, pkStr := range viper.GetStringSlice(cfg) {
		var pk signature.PublicKey
		if err := pk.UnmarshalText([]byte(pkStr)); err != nil {
			logger.Error("failed to parse public key",
				"err", err,
			)
			return nil, err
		}
		pks = append(pks, pk)
	}

	return pks, nil
}
