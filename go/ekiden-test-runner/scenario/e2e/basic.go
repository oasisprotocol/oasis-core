package e2e

import (
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/common/sgx"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/ekiden"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/env"
	"github.com/oasislabs/ekiden/go/ekiden-test-runner/scenario"
)

// Basic is the basic network + client test case.
var Basic scenario.Scenario = &basicImpl{}

type basicImpl struct {
	net *ekiden.Network
}

func (sc *basicImpl) Name() string {
	return "basic"
}

func (sc *basicImpl) Init(childEnv *env.Env) error {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return err
	}
	var mrsigner *sgx.Mrsigner
	if tee == node.TEEHardwareIntelSGX {
		mrsigner = &testMrsigner
	}

	// Create the top level ekiden network.
	if sc.net, err = ekiden.New(childEnv, &ekiden.NetworkCfg{
		EkidenBinary:        viper.GetString(cfgEkidenBinary),
		RuntimeLoaderBinary: viper.GetString(cfgRuntimeLoader),
	}); err != nil {
		return err
	}

	// Provision the debug test entity and a new entity.
	testEnt, err := sc.net.NewEntity(&ekiden.EntityCfg{
		IsDebugTestEntity: true,
	})
	if err != nil {
		return err
	}

	ent, err := sc.net.NewEntity(&ekiden.EntityCfg{
		AllowEntitySignedNodes: true,
	})
	if err != nil {
		return err
	}

	// Provision a few validators.
	valCfg := &ekiden.ValidatorCfg{
		Entity: ent,
	}
	for i := 0; i < numValidators; i++ {
		if _, err = sc.net.NewValidator(valCfg); err != nil {
			return err
		}
	}
	// XXX: The entity should include at least the validator's node IDs.

	// Provision the key manager and runtime.
	km, err := sc.net.NewKeymanager(&ekiden.KeymanagerCfg{
		ID:           keymanagerID,
		Entity:       testEnt,
		TEEHardware:  tee,
		Mrsigner:     mrsigner,
		WorkerEntity: ent,
		Binary:       viper.GetString(cfgKeymanagerBinary),
	})
	if err != nil {
		return err
	}

	if _, err = sc.net.NewRuntime(&ekiden.RuntimeCfg{
		ID:                     runtimeID,
		Entity:                 testEnt,
		Keymanager:             km,
		TEEHardware:            tee,
		Mrsigner:               mrsigner,
		ReplicaGroupSize:       2,
		ReplicaGroupBackupSize: 1,
		StorageGroupSize:       numStorage,
		Binary:                 viper.GetString(cfgRuntimeBinary),
	}); err != nil {
		return err
	}

	// Provision the storage workers.
	stoCfg := &ekiden.StorageCfg{
		Backend: "badger",
		Entity:  ent,
	}
	for i := 0; i < numStorage; i++ {
		if _, err = sc.net.NewStorage(stoCfg); err != nil {
			return err
		}
	}

	// Provision the compute workers.
	comCfg := &ekiden.ComputeCfg{
		Entity: ent,
	}
	for i := 0; i < numCompute; i++ {
		if _, err = sc.net.NewCompute(comCfg); err != nil {
			return err
		}
	}

	// Provision the client node.
	if _, err = sc.net.NewClient(); err != nil {
		return err
	}

	return nil
}

func (sc *basicImpl) Run(childEnv *env.Env) error {
	var err error
	if err = sc.net.Start(); err != nil {
		return err
	}

	cmd, err := startClient(childEnv, sc.net)
	if err != nil {
		return err
	}

	clientErrCh := make(chan error)
	go func() {
		clientErrCh <- cmd.Wait()
	}()

	select {
	case err = <-sc.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
	}

	return err
}
