// Package fixtures provides network configuration fixtures.
package fixtures

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

const (
	cfgNodeBinary          = "net.node.binary"
	cfgRuntimeBinary       = "net.runtime.binary"
	cfgRuntimeGenesisState = "net.runtime.genesis_state"
	cfgRuntimeLoader       = "net.runtime.loader"
	cfgKeymanagerBinary    = "net.keymanager.binary"
	cfgTEEHardware         = "net.tee_hardware"
	cfgEpochtimeBackend    = "net.epochtime_backend"
)

var (
	// Flags is the command line flags for the fixtures.
	Flags = flag.NewFlagSet("", flag.ContinueOnError)

	runtimeID    signature.PublicKey
	keymanagerID signature.PublicKey
)

// NewDefaultFixture returns a default network fixture.
func NewDefaultFixture() (*oasis.NetworkFixture, error) {
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
			EpochtimeBackend:       viper.GetString(cfgEpochtimeBackend),
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{AllowEntitySignedNodes: true},
		},
		Runtimes: []oasis.RuntimeFixture{
			// Key manager runtime.
			oasis.RuntimeFixture{
				ID:         keymanagerID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				Binary:     viper.GetString(cfgKeymanagerBinary),
			},
			// Compute runtime.
			oasis.RuntimeFixture{
				ID:                     runtimeID,
				Kind:                   registry.KindCompute,
				Entity:                 0,
				Keymanager:             0,
				Binary:                 viper.GetString(cfgRuntimeBinary),
				ReplicaGroupSize:       2,
				ReplicaGroupBackupSize: 1,
				StorageGroupSize:       1,
				GenesisState:           viper.GetString(cfgRuntimeGenesisState),
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
	Flags.String(cfgNodeBinary, "oasis-node", "path to the oasis-node binary")
	Flags.String(cfgRuntimeBinary, "simple-keyvalue", "path to the runtime binary")
	Flags.String(cfgRuntimeGenesisState, "", "path to the runtime genesis state")
	Flags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	Flags.String(cfgKeymanagerBinary, "oasis-core-keymanager-runtime", "path to the keymanager runtime")
	Flags.String(cfgTEEHardware, "", "TEE hardware to use")
	Flags.String(cfgEpochtimeBackend, "tendermint", "epochtime backend to use")
	_ = viper.BindPFlags(Flags)

	_ = runtimeID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")
	_ = keymanagerID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
}
