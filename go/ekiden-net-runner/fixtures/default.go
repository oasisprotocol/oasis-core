// Package fixtures provides network configuration fixtures.
package fixtures

import (
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

const (
	cfgEkidenBinary        = "net.ekiden.binary"
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
func NewDefaultFixture() (*ekiden.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrsigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrsigner = &ias.FortanixTestMrSigner
	}

	return &ekiden.NetworkFixture{
		TEE: ekiden.TEEFixture{
			Hardware: tee,
			MrSigner: mrsigner,
		},
		Network: ekiden.NetworkCfg{
			EkidenBinary:           viper.GetString(cfgEkidenBinary),
			RuntimeLoaderBinary:    viper.GetString(cfgRuntimeLoader),
			ConsensusTimeoutCommit: 1 * time.Second,
			EpochtimeBackend:       viper.GetString(cfgEpochtimeBackend),
		},
		Entities: []ekiden.EntityCfg{
			ekiden.EntityCfg{IsDebugTestEntity: true},
			ekiden.EntityCfg{AllowEntitySignedNodes: true},
		},
		Runtimes: []ekiden.RuntimeFixture{
			// Key manager runtime.
			ekiden.RuntimeFixture{
				ID:         keymanagerID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				Binary:     viper.GetString(cfgKeymanagerBinary),
			},
			// Compute runtime.
			ekiden.RuntimeFixture{
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
		Validators: []ekiden.ValidatorFixture{
			ekiden.ValidatorFixture{Entity: 1},
		},
		Keymanagers: []ekiden.KeymanagerFixture{
			ekiden.KeymanagerFixture{Runtime: 0, Entity: 1},
		},
		StorageWorkers: []ekiden.StorageWorkerFixture{
			ekiden.StorageWorkerFixture{Backend: "badger", Entity: 1},
		},
		ComputeWorkers: []ekiden.ComputeWorkerFixture{
			ekiden.ComputeWorkerFixture{Entity: 1},
			ekiden.ComputeWorkerFixture{Entity: 1},
			ekiden.ComputeWorkerFixture{Entity: 1},
		},
		Clients: []ekiden.ClientFixture{
			ekiden.ClientFixture{},
		},
	}, nil
}

func init() {
	Flags.String(cfgEkidenBinary, "ekiden", "path to the ekiden binary")
	Flags.String(cfgRuntimeBinary, "simple-keyvalue", "path to the runtime binary")
	Flags.String(cfgRuntimeGenesisState, "", "path to the runtime genesis state")
	Flags.String(cfgRuntimeLoader, "ekiden-runtime-loader", "path to the runtime loader")
	Flags.String(cfgKeymanagerBinary, "ekiden-keymanager-runtime", "path to the keymanager runtime")
	Flags.String(cfgTEEHardware, "", "TEE hardware to use")
	Flags.String(cfgEpochtimeBackend, "tendermint", "epochtime backend to use")
	_ = viper.BindPFlags(Flags)

	_ = runtimeID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")
	_ = keymanagerID.UnmarshalHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
}
