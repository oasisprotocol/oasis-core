package fixtures

import (
	"math"
	"time"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const (
	cfgEpochtimeMock       = "fixture.default.epochtime_mock"
	cfgHaltEpoch           = "fixture.default.halt_epoch"
	cfgKeymanagerBinary    = "fixture.default.keymanager.binary"
	cfgNodeBinary          = "fixture.default.node.binary"
	cfgRuntimeBinary       = "fixture.default.runtime.binary"
	cfgRuntimeGenesisState = "fixture.default.runtime.genesis_state"
	cfgRuntimeLoader       = "fixture.default.runtime.loader"
	cfgTEEHardware         = "fixture.default.tee_hardware"
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
		mrSigner = &ias.FortanixTestMrSigner
	}

	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:             viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary:    viper.GetString(cfgRuntimeLoader),
			ConsensusTimeoutCommit: 1 * time.Second,
			EpochtimeMock:          viper.GetBool(cfgEpochtimeMock),
			HaltEpoch:              viper.GetUint64(cfgHaltEpoch),
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{},
		},
		Runtimes: []oasis.RuntimeFixture{
			// Key manager runtime.
			oasis.RuntimeFixture{
				ID:         keymanagerID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				Binary:     viper.GetString(cfgKeymanagerBinary),
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
			},
			// Compute runtime.
			oasis.RuntimeFixture{
				ID:         runtimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Binary:     viper.GetString(cfgRuntimeBinary),
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    20 * time.Second,
				},
				Merge: registry.MergeParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    20 * time.Second,
				},
				TxnScheduler: registry.TxnSchedulerParameters{
					Algorithm:         registry.TxnSchedulerAlgorithmBatching,
					GroupSize:         2,
					MaxBatchSize:      1,
					MaxBatchSizeBytes: 16 * 1024 * 1024, // 16 MiB
					BatchFlushTimeout: 20 * time.Second,
				},
				Storage: registry.StorageParameters{
					GroupSize:               1,
					MaxApplyWriteLogEntries: 100_000,
					MaxApplyOps:             2,
					MaxMergeRoots:           8,
					MaxMergeOps:             2,
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				GenesisState: viper.GetString(cfgRuntimeGenesisState),
				GenesisRound: 0,
			},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1},
		},
		Keymanagers: []oasis.KeymanagerFixture{
			oasis.KeymanagerFixture{Runtime: 0, Entity: 1},
		},
		StorageWorkers: []oasis.StorageWorkerFixture{
			oasis.StorageWorkerFixture{Backend: "badger", Entity: 1},
		},
		ComputeWorkers: []oasis.ComputeWorkerFixture{
			oasis.ComputeWorkerFixture{Entity: 1},
			oasis.ComputeWorkerFixture{Entity: 1},
			oasis.ComputeWorkerFixture{Entity: 1},
		},
		Clients: []oasis.ClientFixture{
			oasis.ClientFixture{},
		},
	}, nil
}

func init() {
	DefaultFixtureFlags.Bool(cfgEpochtimeMock, false, "use mock epochtime")
	DefaultFixtureFlags.Uint64(cfgHaltEpoch, math.MaxUint64, "halt epoch height")
	DefaultFixtureFlags.String(cfgKeymanagerBinary, "simple-keymanager", "path to the keymanager runtime")
	DefaultFixtureFlags.String(cfgNodeBinary, "oasis-node", "path to the oasis-node binary")
	DefaultFixtureFlags.String(cfgRuntimeBinary, "simple-keyvalue", "path to the runtime binary")
	DefaultFixtureFlags.String(cfgRuntimeGenesisState, "", "path to the runtime genesis state")
	DefaultFixtureFlags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	DefaultFixtureFlags.String(cfgTEEHardware, "", "TEE hardware to use")
	_ = viper.BindPFlags(DefaultFixtureFlags)

	_ = runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	_ = keymanagerID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
}
