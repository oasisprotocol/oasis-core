package fixtures

import (
	"math"
	"time"

	"github.com/spf13/viper"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	cfgDeterministicIdentities = "fixture.default.deterministic_entities"
	cfgFundEntities            = "fixture.default.fund_entities"
	cfgEpochtimeMock           = "fixture.default.epochtime_mock"
	cfgHaltEpoch               = "fixture.default.halt_epoch"
	cfgKeymanagerBinary        = "fixture.default.keymanager.binary"
	cfgNodeBinary              = "fixture.default.node.binary"
	cfgNumEntities             = "fixture.default.num_entities"
	cfgRuntimeBinary           = "fixture.default.runtime.binary"
	cfgRuntimeGenesisState     = "fixture.default.runtime.genesis_state"
	cfgRuntimeLoader           = "fixture.default.runtime.loader"
	cfgSetupRuntimes           = "fixture.default.setup_runtimes"
	cfgTEEHardware             = "fixture.default.tee_hardware"
	cfgInitialHeight           = "fixture.default.initial_height"
)

var (
	runtimeID    common.Namespace
	keymanagerID common.Namespace
)

// newDefaultFixture returns a default network fixture.
func newDefaultFixture() (*oasis.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &sgx.FortanixDummyMrSigner
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
			InitialHeight: viper.GetInt64(cfgInitialHeight),
			HaltEpoch:     viper.GetUint64(cfgHaltEpoch),
			IAS: oasis.IASCfg{
				Mock: true,
			},
			DeterministicIdentities: viper.GetBool(cfgDeterministicIdentities),
			FundEntities:            viper.GetBool(cfgFundEntities),
			StakingGenesis:          &staking.Genesis{},
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1},
		},
		Seeds: []oasis.SeedFixture{{}},
	}
	if viper.GetBool(cfgEpochtimeMock) {
		fixture.Network.SetMockEpoch()
	}

	for i := 0; i < viper.GetInt(cfgNumEntities); i++ {
		fixture.Entities = append(fixture.Entities, oasis.EntityCfg{})
	}

	if viper.GetBool(cfgSetupRuntimes) {
		fixture.Runtimes = []oasis.RuntimeFixture{
			// Key manager runtime.
			{
				ID:         keymanagerID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				Binaries: map[node.TEEHardware][]string{
					tee: viper.GetStringSlice(cfgKeymanagerBinary),
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
			},
			// Compute runtime.
			{
				ID:         runtimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Binaries: map[node.TEEHardware][]string{
					tee: viper.GetStringSlice(cfgRuntimeBinary),
				},
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    20,
					MinPoolSize:     3, // GroupSize + GroupBackupSize
				},
				TxnScheduler: registry.TxnSchedulerParameters{
					Algorithm:         registry.TxnSchedulerSimple,
					MaxBatchSize:      1,
					MaxBatchSizeBytes: 16 * 1024 * 1024, // 16 MiB
					BatchFlushTimeout: 20 * time.Second,
					ProposerTimeout:   20,
				},
				Storage: registry.StorageParameters{
					GroupSize:               1,
					MinWriteReplication:     1,
					MaxApplyWriteLogEntries: 100_000,
					MaxApplyOps:             2,
					MinPoolSize:             1,
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				GenesisStatePath: viper.GetString(cfgRuntimeGenesisState),
				GenesisRound:     0,
			},
		}
		fixture.KeymanagerPolicies = []oasis.KeymanagerPolicyFixture{
			{Runtime: 0, Serial: 1},
		}
		fixture.Keymanagers = []oasis.KeymanagerFixture{
			{Runtime: 0, Entity: 1},
		}
		fixture.StorageWorkers = []oasis.StorageWorkerFixture{
			{Backend: "badger", Entity: 1},
		}
		fixture.ComputeWorkers = []oasis.ComputeWorkerFixture{
			{Entity: 1, Runtimes: []int{1}},
			{Entity: 1, Runtimes: []int{1}},
			{Entity: 1, Runtimes: []int{1}},
		}
		fixture.Clients = []oasis.ClientFixture{{}}
	}

	return fixture, nil
}

func init() {
	DefaultFixtureFlags.Bool(cfgDeterministicIdentities, false, "generate nodes with deterministic identities")
	DefaultFixtureFlags.Bool(cfgFundEntities, false, "fund all entities in genesis")
	DefaultFixtureFlags.Bool(cfgEpochtimeMock, false, "use mock epochtime")
	DefaultFixtureFlags.Bool(cfgSetupRuntimes, true, "initialize the network with runtimes and runtime nodes")
	DefaultFixtureFlags.Int(cfgNumEntities, 1, "number of (non debug) entities in genesis")
	DefaultFixtureFlags.String(cfgKeymanagerBinary, "simple-keymanager", "path to the keymanager runtime")
	DefaultFixtureFlags.String(cfgNodeBinary, "oasis-node", "path to the oasis-node binary")
	DefaultFixtureFlags.String(cfgRuntimeBinary, "simple-keyvalue", "path to the runtime binary")
	DefaultFixtureFlags.String(cfgRuntimeGenesisState, "", "path to the runtime genesis state")
	DefaultFixtureFlags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	DefaultFixtureFlags.String(cfgTEEHardware, "", "TEE hardware to use")
	DefaultFixtureFlags.Uint64(cfgHaltEpoch, math.MaxUint64, "halt epoch height")
	DefaultFixtureFlags.Int64(cfgInitialHeight, 1, "initial block height")

	_ = viper.BindPFlags(DefaultFixtureFlags)

	_ = runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	_ = keymanagerID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
}
