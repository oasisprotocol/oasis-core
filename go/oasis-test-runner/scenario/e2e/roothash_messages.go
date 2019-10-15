package e2e

import (
	"context"
	"fmt"
	"github.com/pkg/errors"
	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	tendermintmock "github.com/oasislabs/oasis-core/go/epochtime/tendermint_mock"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
)

var (
	RoothashMessages scenario.Scenario = &roothashMessagesImpl{}
)

type roothashMessagesImpl struct {
	net *oasis.Network
}

func (sc *roothashMessagesImpl) Name() string {
	return "roothash-messages"
}

func (sc *roothashMessagesImpl) Fixture() (*oasis.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &ias.FortanixTestMrSigner
	}
	keyManagerBinary, err := resolveDefaultKeyManagerBinary()
	if err != nil {
		return nil, err
	}
	runtimeBinary, err := resolveRuntimeBinary("staking-arbitrary")
	if err != nil {
		return nil, err
	}

	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:          viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary: viper.GetString(cfgRuntimeLoader),
			EpochtimeBackend:    tendermintmock.BackendName,
			StakingGenesis:      "tests/fixture-data/roothash-messages/staking-genesis.json",
			LogWatcherHandlers:  DefaultBasicLogWatcherHandlers,
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
				Binary:     keyManagerBinary,
			},
			// Compute runtime.
			oasis.RuntimeFixture{
				ID:                     runtimeID,
				Kind:                   registry.KindCompute,
				Entity:                 0,
				Keymanager:             0,
				Binary:                 runtimeBinary,
				ReplicaGroupSize:       1,
				ReplicaGroupBackupSize: 0,
				StorageGroupSize:       1,
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
		},
		Clients: []oasis.ClientFixture{
			oasis.ClientFixture{},
		},
	}, nil
}

func (sc *roothashMessagesImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.net = net
	return nil
}

func (sc *roothashMessagesImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return err
	}

	client, err := startClient(childEnv, sc.net, "staking-arbitrary-client", nil)
	if err != nil {
		return err
	}
	clientErrCh := make(chan error)
	go func() {
		clientErrCh <- client.Wait()
	}()

	ctx := context.Background()
	logger.Info("waiting for nodes to register")
	if err = sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return errors.Wrap(err, "waiting for nodes to register")
	}
	logger.Info("nodes registered")

	logger.Info("triggering epoch transition")
	if err = sc.net.Controller().SetEpoch(ctx, 1); err != nil {
		return errors.Wrap(err, "setting epoch")
	}
	logger.Info("epoch transition done")

	select {
	case err = <-sc.net.Errors():
		_ = client.Process.Kill()
		return errors.Wrapf(err, "network")
	case err = <-clientErrCh:
		fmt.Println("client terminated")
		if err != nil {
			return errors.Wrap(err, "waiting for client")
		}
	}

	if err = sc.net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}
