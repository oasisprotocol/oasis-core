package fixtures

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/viper"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
	mkvsAPI "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/badger"
)

const (
	cfgDebugTestEntity                     = "fixture.default.debug_test_entity"
	cfgDeterministicIdentities             = "fixture.default.deterministic_entities"
	cfgRestoreIdentities                   = "fixture.default.restore_identities"
	cfgFundEntities                        = "fixture.default.fund_entities"
	cfgEpochtimeMock                       = "fixture.default.epochtime_mock"
	cfgEpochtimeInterval                   = "fixture.default.epochtime_interval"
	cfgHaltEpoch                           = "fixture.default.halt_epoch"
	cfgKeymanagerBinary                    = "fixture.default.keymanager.binary"
	cfgNodeBinary                          = "fixture.default.node.binary"
	cfgNumEntities                         = "fixture.default.num_entities"
	cfgRuntimeID                           = "fixture.default.runtime.id"
	cfgRuntimeBinary                       = "fixture.default.runtime.binary"
	cfgRuntimeVersion                      = "fixture.default.runtime.version"
	cfgRuntimeStatePath                    = "fixture.default.runtime.state_path"
	cfgRuntimeProvisioner                  = "fixture.default.runtime.provisioner"
	cfgRuntimeLoader                       = "fixture.default.runtime.loader"
	cfgGovernanceUpgradeMinEpochDiff       = "fixture.default.governance.upgrade_min_epoch_diff"
	cfgGovernanceUpgradeCancelMinEpochDiff = "fixture.default.governance.upgrade_cancel_min_epoch_diff"
	cfgGovernanceVotingPeriod              = "fixture.default.governance.voting_period"
	cfgGovernanceStakeThreshold            = "fixture.default.governance.stake_threshold"
	cfgGovernanceMinProposalDeposit        = "fixture.default.governance.min_proposal_deposit"
	cfgSetupRuntimes                       = "fixture.default.setup_runtimes"
	cfgTEEHardware                         = "fixture.default.tee_hardware"
	cfgInitialHeight                       = "fixture.default.initial_height"
	cfgStakingGenesis                      = "fixture.default.staking_genesis"
	cfgGenesis                             = "fixture.default.genesis"
)

var keymanagerID common.Namespace

// newDefaultFixture returns a default network fixture.
func newDefaultFixture() (*oasis.NetworkFixture, error) { // nolint: gocyclo
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &sgx.FortanixDummyMrSigner
	}

	// Default staking genesis enables 16 allowances per account which matches the current
	// mainnet and testnet setting.
	stakingGenesis := staking.Genesis{
		Parameters: staking.ConsensusParameters{
			MaxAllowances: 16,
		},
	}
	if genesis := viper.GetString(cfgStakingGenesis); genesis != "" {
		var raw []byte
		raw, err = os.ReadFile(genesis)
		if err != nil {
			return nil, fmt.Errorf("loading staking genesis file: %w", err)
		}
		if err = json.Unmarshal(raw, &stakingGenesis); err != nil {
			return nil, fmt.Errorf("loading staking genesis: %w", err)
		}
	}

	govStakeThreshold := viper.GetUint(cfgGovernanceStakeThreshold)
	if govStakeThreshold > 100 {
		return nil, fmt.Errorf("governance stake threshold must not be greater than 100")
	}

	fixture := &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:             viper.GetString(cfgNodeBinary),
			RuntimeSGXLoaderBinary: viper.GetString(cfgRuntimeLoader),
			Consensus: consensusGenesis.Genesis{
				Parameters: consensusGenesis.Parameters{
					TimeoutCommit: 1 * time.Second,
				},
			},
			Beacon: beacon.ConsensusParameters{
				Backend: beacon.BackendInsecure,
			},
			GovernanceParameters: &governance.ConsensusParameters{
				UpgradeMinEpochDiff:       beacon.EpochTime(viper.GetUint64(cfgGovernanceUpgradeMinEpochDiff)),
				VotingPeriod:              beacon.EpochTime(viper.GetUint64(cfgGovernanceVotingPeriod)),
				UpgradeCancelMinEpochDiff: beacon.EpochTime(viper.GetUint64(cfgGovernanceUpgradeCancelMinEpochDiff)),
				StakeThreshold:            uint8(govStakeThreshold),
				MinProposalDeposit:        *quantity.NewFromUint64(viper.GetUint64(cfgGovernanceMinProposalDeposit)),
			},
			InitialHeight: viper.GetInt64(cfgInitialHeight),
			HaltEpoch:     viper.GetUint64(cfgHaltEpoch),
			IAS: oasis.IASCfg{
				Mock: true,
			},
			DeterministicIdentities: viper.GetBool(cfgDeterministicIdentities),
			RestoreIdentities:       viper.GetBool(cfgRestoreIdentities),
			FundEntities:            viper.GetBool(cfgFundEntities),
			StakingGenesis:          &stakingGenesis,
			GenesisFile:             viper.GetString(cfgGenesis),
		},
		Entities: []oasis.EntityCfg{},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, Consensus: oasis.ConsensusFixture{SupplementarySanityInterval: 1}},
		},
		Seeds: []oasis.SeedFixture{{}},
	}
	if viper.GetBool(cfgDebugTestEntity) {
		fixture.Entities = append(fixture.Entities, oasis.EntityCfg{IsDebugTestEntity: true})
	}
	if viper.GetBool(cfgEpochtimeMock) {
		fixture.Network.SetMockEpoch()
	}
	if interval := viper.GetInt64(cfgEpochtimeInterval); interval > 0 {
		fixture.Network.Beacon.InsecureParameters = &beacon.InsecureParameters{
			Interval: interval,
		}
	}

	for i := 0; i < viper.GetInt(cfgNumEntities); i++ {
		fixture.Entities = append(fixture.Entities, oasis.EntityCfg{})
	}

	runtimeProvisionerRaw := []byte(viper.GetString(cfgRuntimeProvisioner))
	var runtimeProvisioner runtimeConfig.RuntimeProvisioner
	if err = runtimeProvisioner.UnmarshalText(runtimeProvisionerRaw); err != nil {
		return nil, err
	}

	// Always run a client node.
	fixture.Clients = []oasis.ClientFixture{{
		RuntimeProvisioner: runtimeProvisioner,
	}}

	usingKeymanager := len(viper.GetString(cfgKeymanagerBinary)) > 0

	if viper.GetBool(cfgSetupRuntimes) {
		if usingKeymanager {
			// Key manager runtime.
			fixture.Runtimes = append(fixture.Runtimes, oasis.RuntimeFixture{
				ID:         keymanagerID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				GovernanceModel: registry.GovernanceEntity,
				Deployments: []oasis.DeploymentCfg{
					{
						Binaries: map[node.TEEHardware]string{
							tee: viper.GetString(cfgKeymanagerBinary),
						},
					},
				},
			})
			fixture.KeymanagerPolicies = []oasis.KeymanagerPolicyFixture{
				{Runtime: 0, Serial: 1},
			}
			fixture.Keymanagers = []oasis.KeymanagerFixture{
				{Runtime: 0, Entity: 1, RuntimeProvisioner: runtimeProvisioner},
			}
		}
		fixture.ComputeWorkers = []oasis.ComputeWorkerFixture{
			{Entity: 1, Runtimes: []int{}, RuntimeProvisioner: runtimeProvisioner, RuntimeStatePaths: make(map[int]string)},
			{Entity: 1, Runtimes: []int{}, RuntimeProvisioner: runtimeProvisioner, RuntimeStatePaths: make(map[int]string)},
			{Entity: 1, Runtimes: []int{}, RuntimeProvisioner: runtimeProvisioner, RuntimeStatePaths: make(map[int]string)},
		}

		var runtimeIDs []common.Namespace
		for _, rtID := range viper.GetStringSlice(cfgRuntimeID) {
			var rt common.Namespace
			if err = rt.UnmarshalHex(rtID); err != nil {
				cmdCommon.EarlyLogAndExit(fmt.Errorf("invalid runtime ID: %s: %w", rtID, err))
			}
			runtimeIDs = append(runtimeIDs, rt)
		}

		runtimes := viper.GetStringSlice(cfgRuntimeBinary)
		if l1, l2 := len(runtimeIDs), len(runtimes); l1 < l2 {
			cmdCommon.EarlyLogAndExit(fmt.Errorf("missing runtime IDs, required: %d, provided: %d", l1, l2))
		}

		// Runtime versions should be ignored or must be one-to-one mapped to runtimes.
		runtimeVersions := viper.GetStringSlice(cfgRuntimeVersion)
		if l1, l2 := len(runtimeIDs), len(runtimeVersions); l2 != 0 && l1 != l2 {
			cmdCommon.EarlyLogAndExit(fmt.Errorf("runtime versions number mismatch, required: %d, provided: %d", l1, l2))
		}

		keymanagerIdx := -1
		if usingKeymanager {
			keymanagerIdx = 0
		}
		runtimeStatePaths := viper.GetStringSlice(cfgRuntimeStatePath)
		if l1, l2 := len(runtimeStatePaths), len(runtimeIDs); l1 > 0 && l1 != l2 {
			cmdCommon.EarlyLogAndExit(fmt.Errorf("missing runtime state paths: number of runtimes: %d, provided state paths: %d", l2, l1))
		}

		for i, rt := range runtimes {
			// Compute runtime.
			rtVersion := version.Version{}
			if len(runtimeVersions) > i {
				rtVersion, err = version.FromString(runtimeVersions[i])
				if err != nil {
					return nil, fmt.Errorf("parsing runtime version: %w", err)
				}
			}
			fixture.Runtimes = append(fixture.Runtimes, oasis.RuntimeFixture{
				ID:         runtimeIDs[i],
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: keymanagerIdx,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    20,
					MaxMessages:     128,
				},
				TxnScheduler: registry.TxnSchedulerParameters{
					MaxBatchSize:      1000,
					MaxBatchSizeBytes: 16 * 1024 * 1024, // 16 MiB
					BatchFlushTimeout: 1 * time.Second,
					ProposerTimeout:   20,
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				GenesisRound:    0,
				GovernanceModel: registry.GovernanceEntity,
				Deployments: []oasis.DeploymentCfg{
					{
						Version:   rtVersion,
						ValidFrom: 0,
						Binaries: map[node.TEEHardware]string{
							tee: rt,
						},
					},
				},
			})
			rtIndex := len(fixture.Runtimes) - 1

			for j := range fixture.ComputeWorkers {
				fixture.ComputeWorkers[j].Runtimes = append(fixture.ComputeWorkers[j].Runtimes, rtIndex)
			}
			fixture.Clients[0].Runtimes = append(fixture.Clients[0].Runtimes, rtIndex)

			// Runtime state paths to use to initialize the runtime with.
			if len(runtimeStatePaths) <= i {
				continue
			}
			runtimeStatePath := runtimeStatePaths[i]
			if runtimeStatePath == "" {
				continue
			}

			// Set workers runtime state.
			for j := range fixture.ComputeWorkers {
				fixture.ComputeWorkers[j].RuntimeStatePaths[i] = runtimeStatePath
			}

			dbPath := filepath.Join(runtimeStatePath, database.DBFileBadgerDB)
			_, err := os.Stat(dbPath)
			if err != nil {
				return nil, fmt.Errorf("runtime state path: %w", err)
			}
			db, err := badger.New(&mkvsAPI.Config{
				DB:        dbPath,
				Namespace: runtimeIDs[i],
			})
			if err != nil {
				return nil, fmt.Errorf("opening state path: %w", err)
			}

			version, stateRoot, err := getLatestVersionAndStateRoot(db)
			if err != nil {
				return nil, fmt.Errorf("loading version and state root: %w", err)
			}

			// Set runtime genesis state.
			fixture.Runtimes[i].GenesisRound = version
			fixture.Runtimes[i].GenesisStateRoot = stateRoot

		}
	}

	return fixture, nil
}

// Loads latest runtime version and state root from the NodeDB.
func getLatestVersionAndStateRoot(db mkvsAPI.NodeDB) (uint64, *hash.Hash, error) {
	// Get latest version.
	dbVersion, exists := db.GetLatestVersion()
	if !exists {
		return 0, nil, fmt.Errorf("no version found in runtime state db: %v", dbVersion)
	}
	rts, err := db.GetRootsForVersion(context.Background(), dbVersion)
	if err != nil {
		return 0, nil, err
	}

	// Get latest state root.
	var stateRootHash hash.Hash
	for _, r := range rts {
		if r.Type == storage.RootTypeState {
			stateRootHash = r.Hash
		}
	}

	return dbVersion, &stateRootHash, nil
}

func init() {
	DefaultFixtureFlags.Bool(cfgDebugTestEntity, true, "include the debug test entity in genesis")
	DefaultFixtureFlags.Bool(cfgDeterministicIdentities, false, "generate nodes with deterministic identities")
	DefaultFixtureFlags.Bool(cfgRestoreIdentities, false, "restore identities")
	DefaultFixtureFlags.Bool(cfgFundEntities, false, "fund all entities in genesis")
	DefaultFixtureFlags.Bool(cfgEpochtimeMock, false, "use mock epochtime")
	DefaultFixtureFlags.Uint64(cfgEpochtimeInterval, 0, "epochtime interval")
	DefaultFixtureFlags.Bool(cfgSetupRuntimes, true, "initialize the network with runtimes and runtime nodes")
	DefaultFixtureFlags.Int(cfgNumEntities, 1, "number of (non debug) entities in genesis")
	DefaultFixtureFlags.String(cfgKeymanagerBinary, "simple-keymanager", "path to the keymanager runtime")
	DefaultFixtureFlags.String(cfgNodeBinary, "oasis-node", "path to the oasis-node binary")
	DefaultFixtureFlags.StringSlice(cfgRuntimeID, []string{"8000000000000000000000000000000000000000000000000000000000000000"}, "runtime ID")
	DefaultFixtureFlags.StringSlice(cfgRuntimeBinary, []string{"simple-keyvalue"}, "path to the runtime binary")
	DefaultFixtureFlags.StringSlice(cfgRuntimeVersion, []string{"0.1.0"}, "runtime version to register")
	DefaultFixtureFlags.StringSlice(cfgRuntimeStatePath, []string{""}, "runtime state path to initialize the runtime (and nodes) with")
	DefaultFixtureFlags.String(cfgRuntimeProvisioner, "sandboxed", "the runtime provisioner: mock, unconfined, or sandboxed")
	DefaultFixtureFlags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	DefaultFixtureFlags.Uint64(cfgGovernanceUpgradeMinEpochDiff, 100, "minimum epoch difference for upgrade proposals")
	DefaultFixtureFlags.Uint64(cfgGovernanceUpgradeCancelMinEpochDiff, 70, "minimum epoch difference for cancel upgrade proposals")
	DefaultFixtureFlags.Uint64(cfgGovernanceVotingPeriod, 20, "voting period for governance proposals")
	DefaultFixtureFlags.Uint8(cfgGovernanceStakeThreshold, 90, "stake threshold for governance proposals")
	DefaultFixtureFlags.Uint64(cfgGovernanceMinProposalDeposit, 100, "minimum proposal deposit for governance proposals")
	DefaultFixtureFlags.String(cfgTEEHardware, "", "TEE hardware to use")
	DefaultFixtureFlags.Uint64(cfgHaltEpoch, math.MaxUint64, "halt epoch height")
	DefaultFixtureFlags.Int64(cfgInitialHeight, 1, "initial block height")
	DefaultFixtureFlags.String(cfgStakingGenesis, "", "path to the staking genesis to use")
	DefaultFixtureFlags.String(cfgGenesis, "", "path to the genesis to use")

	_ = viper.BindPFlags(DefaultFixtureFlags)

	_ = keymanagerID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
}
