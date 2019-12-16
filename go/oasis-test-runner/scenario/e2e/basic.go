package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/storage/database"
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

	// DefaultBasicLogWatcherHandlerFactories is a list of default log watcher
	// handler factories for the basic scenario.
	DefaultBasicLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertNoComputeDiscrepancyDetected(),
		oasis.LogAssertNoMergeDiscrepancyDetected(),
	}
)

type basicImpl struct {
	net *oasis.Network

	name         string
	clientBinary string
	clientArgs   []string
}

func (sc *basicImpl) Name() string {
	return sc.name
}

func (sc *basicImpl) Fixture() (*oasis.NetworkFixture, error) {
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
	runtimeBinary, err := resolveRuntimeBinary("simple-keyvalue")
	if err != nil {
		return nil, err
	}

	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:                        viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary:               viper.GetString(cfgRuntimeLoader),
			DefaultLogWatcherHandlerFactories: DefaultBasicLogWatcherHandlerFactories,
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
				Binary:     keyManagerBinary,
			},
			// Compute runtime.
			oasis.RuntimeFixture{
				ID:         runtimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Binary:     runtimeBinary,
				Compute: registry.ComputeParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    10 * time.Second,
				},
				Merge: registry.MergeParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    10 * time.Second,
				},
				TxnScheduler: registry.TxnSchedulerParameters{
					Algorithm:         registry.TxnSchedulerAlgorithmBatching,
					GroupSize:         1,
					MaxBatchSize:      1,
					MaxBatchSizeBytes: 1000,
					BatchFlushTimeout: 10 * time.Second,
				},
				Storage: registry.StorageParameters{GroupSize: 2},
			},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1},
			oasis.ValidatorFixture{Entity: 1},
			oasis.ValidatorFixture{Entity: 1},
		},
		Keymanagers: []oasis.KeymanagerFixture{
			oasis.KeymanagerFixture{Runtime: 0, Entity: 1},
		},
		StorageWorkers: []oasis.StorageWorkerFixture{
			oasis.StorageWorkerFixture{Backend: database.BackendNameBadgerDB, Entity: 1},
			oasis.StorageWorkerFixture{Backend: database.BackendNameBadgerDB, Entity: 1},
		},
		ComputeWorkers: []oasis.ComputeWorkerFixture{
			oasis.ComputeWorkerFixture{Entity: 1},
			oasis.ComputeWorkerFixture{Entity: 1},
			oasis.ComputeWorkerFixture{Entity: 1},
		},
		Sentries: []oasis.SentryFixture{},
		Clients: []oasis.ClientFixture{
			oasis.ClientFixture{},
		},
	}, nil
}

func (sc *basicImpl) Init(childEnv *env.Env, net *oasis.Network) error {
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

func (sc *basicImpl) cleanTendermintStorage() error {
	var err error
	preservePaths := make(map[string]bool)
	preserveComponents := make(map[string]bool)
	preservePath := func(path string) {
		preservePaths[path] = true

		for len(path) > 1 {
			path = filepath.Clean(path)
			preserveComponents[path] = true
			path, _ = filepath.Split(path)
		}
	}

	// Preserve all identities and exported data.
	for _, ent := range sc.net.Entities() {
		preservePath(ent.EntityKeyPath())
		preservePath(ent.DescriptorPath())
	}
	for _, val := range sc.net.Validators() {
		preservePath(val.IdentityKeyPath())
		preservePath(val.P2PKeyPath())
		preservePath(val.ConsensusKeyPath())
		preservePath(val.ExportsPath())
	}
	for _, sw := range sc.net.StorageWorkers() {
		preservePath(sw.IdentityKeyPath())
		preservePath(sw.P2PKeyPath())
		preservePath(sw.ConsensusKeyPath())
		preservePath(sw.TLSKeyPath())
		preservePath(sw.TLSCertPath())
		preservePath(sw.ExportsPath())
	}
	for _, cw := range sc.net.ComputeWorkers() {
		preservePath(cw.IdentityKeyPath())
		preservePath(cw.P2PKeyPath())
		preservePath(cw.ConsensusKeyPath())
		preservePath(cw.TLSKeyPath())
		preservePath(cw.TLSCertPath())
		preservePath(cw.ExportsPath())
	}
	km := sc.net.Keymanager()
	preservePath(km.IdentityKeyPath())
	preservePath(km.P2PKeyPath())
	preservePath(km.ConsensusKeyPath())
	preservePath(km.TLSKeyPath())
	preservePath(km.TLSCertPath())
	preservePath(km.ExportsPath())
	// Preserve key manager state.
	preservePath(km.LocalStoragePath())

	// Preserve storage.
	for _, sw := range sc.net.StorageWorkers() {
		preservePath(sw.DatabasePath())
	}

	// Remove all files except what should be preserved.
	err = filepath.Walk(sc.net.BasePath(), func(path string, info os.FileInfo, fErr error) error {
		// Preserve everything under a path.
		if preservePaths[path] {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		// Also preserve any components of paths.
		if preserveComponents[path] {
			return nil
		}
		// Remove everything else.
		if err = os.RemoveAll(path); err != nil {
			return err
		}
		if info.IsDir() {
			// No need to recurse into directory as it has been removed.
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}

func (sc *basicImpl) wait(childEnv *env.Env, cmd *exec.Cmd, clientErrCh <-chan error) error {
	var err error
	select {
	case err = <-sc.net.Errors():
		_ = cmd.Process.Kill()
	case err = <-clientErrCh:
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
