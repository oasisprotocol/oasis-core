package e2e

import (
	"fmt"
	"os/exec"

	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/common/sgx/ias"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/log"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/scenario"
	registry "github.com/oasislabs/ekiden/go/registry/api"
)

var (
	// Basic is the basic network + client test case.
	Basic scenario.Scenario = &basicImpl{
		name:         "basic",
		clientBinary: "simple-keyvalue-client",
	}
	// BasicEncryption is the basic network + client with encryption test case.
	BasicEncryption scenario.Scenario = &basicImpl{
		name:         "basic_encryption",
		clientBinary: "simple-keyvalue-enc-client",
	}

	// DefaultBasicLogWatcherHandlers is a list of default basic log watcher handlers.
	DefaultBasicLogWatcherHandlers = []log.WatcherHandler{
		ekiden.LogAssertNoTimeouts(),
		ekiden.LogAssertNoRoundFailures(),
		ekiden.LogAssertNoComputeDiscrepancyDetected(),
		ekiden.LogAssertNoMergeDiscrepancyDetected(),
	}
)

type basicImpl struct {
	net *ekiden.Network

	name         string
	clientBinary string
	clientArgs   []string
}

func (sc *basicImpl) Name() string {
	return sc.name
}

func (sc *basicImpl) Fixture() (*ekiden.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrsigner *sgx.Mrsigner
	if tee == node.TEEHardwareIntelSGX {
		mrsigner = &ias.FortanixTestMrSigner
	}

	return &ekiden.NetworkFixture{
		TEE: ekiden.TEEFixture{
			Hardware: tee,
			Mrsigner: mrsigner,
		},
		Network: ekiden.NetworkCfg{
			EkidenBinary:        viper.GetString(cfgEkidenBinary),
			RuntimeLoaderBinary: viper.GetString(cfgRuntimeLoader),
			LogWatcherHandlers:  DefaultBasicLogWatcherHandlers,
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
				StorageGroupSize:       2,
			},
		},
		Validators: []ekiden.ValidatorFixture{
			ekiden.ValidatorFixture{Entity: 1},
			ekiden.ValidatorFixture{Entity: 1},
			ekiden.ValidatorFixture{Entity: 1},
		},
		Keymanagers: []ekiden.KeymanagerFixture{
			ekiden.KeymanagerFixture{Runtime: 0, Entity: 1, Restartable: true},
		},
		StorageWorkers: []ekiden.StorageWorkerFixture{
			ekiden.StorageWorkerFixture{Backend: "badger", Entity: 1},
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

func (sc *basicImpl) Init(childEnv *env.Env, net *ekiden.Network) error {
	sc.net = net
	return nil
}

func (sc *basicImpl) start(childEnv *env.Env) (<-chan error, *exec.Cmd, error) {
	var err error
	if err = sc.net.Start(); err != nil {
		return nil, nil, err
	}

	cmd, err := startClient(childEnv, sc.net, sc.clientBinary, sc.clientArgs)
	if err != nil {
		return nil, nil, err
	}

	clientErrCh := make(chan error)
	go func() {
		clientErrCh <- cmd.Wait()
	}()
	return clientErrCh, cmd, nil
}

func (sc *basicImpl) wait(childEnv *env.Env, cmd *exec.Cmd, clientErrCh <-chan error) error {
	var err error
	select {
	case err = <-sc.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
		fmt.Printf("client terminated\n")
	}
	if err != nil {
		return err
	}

	if err = sc.net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}

func (sc *basicImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.start(childEnv)
	if err != nil {
		return err
	}

	return sc.wait(childEnv, cmd, clientErrCh)
}
