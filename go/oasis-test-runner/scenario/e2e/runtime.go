package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdNode "github.com/oasislabs/oasis-core/go/oasis-node/cmd/node"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/log"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
	runtimeTransaction "github.com/oasislabs/oasis-core/go/runtime/transaction"
	"github.com/oasislabs/oasis-core/go/storage/database"
)

const (
	cfgClientBinaryDir  = "client.binary_dir"
	cfgRuntimeBinaryDir = "runtime.binary_dir"
	cfgRuntimeLoader    = "runtime.loader"
	cfgTEEHardware      = "tee_hardware"

	cfgIasMock = "ias.mock"
)

var (
	// RuntimeParamsDummy is a dummy instance of runtimeImpl used to register runtime-wise parameters.
	RuntimeParamsDummy *runtimeImpl = &runtimeImpl{e2eImpl: *newE2eImpl("runtime")}

	// Runtime is the basic network + client test case with runtime support.
	Runtime scenario.Scenario = newRuntimeImpl("runtime", "simple-keyvalue-client", nil)
	// RuntimeEncryption is the basic network + client with encryption test case.
	RuntimeEncryption scenario.Scenario = newRuntimeImpl("runtime-encryption", "simple-keyvalue-enc-client", nil)

	// DefaultRuntimeLogWatcherHandlerFactories is a list of default log watcher
	// handler factories for the basic scenario.
	DefaultRuntimeLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertNoExecutionDiscrepancyDetected(),
		oasis.LogAssertNoMergeDiscrepancyDetected(),
	}

	runtimeID    common.Namespace
	keymanagerID common.Namespace
	_            = runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	_            = keymanagerID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
)

// runtimeImpl is a base class for tests involving oasis-node with runtime.
type runtimeImpl struct {
	e2eImpl

	clientBinary string
	clientArgs   []string

	clientBinaryDir  string
	runtimeBinaryDir string
	runtimeLoader    string
	TEEHardware      string

	iasMock bool
}

func newRuntimeImpl(name, clientBinary string, clientArgs []string) *runtimeImpl {
	return &runtimeImpl{
		e2eImpl:          *newE2eImpl("runtime/" + name),
		clientBinary:     clientBinary,
		clientArgs:       clientArgs,
		clientBinaryDir:  "",
		runtimeBinaryDir: "",
		runtimeLoader:    "oasis-core-runtime-loader",
		TEEHardware:      "",
	}
}

func (sc *runtimeImpl) Clone() scenario.Scenario {
	return &runtimeImpl{
		e2eImpl:          sc.e2eImpl.Clone(),
		clientBinary:     sc.clientBinary,
		clientArgs:       sc.clientArgs,
		clientBinaryDir:  sc.clientBinaryDir,
		runtimeBinaryDir: sc.runtimeBinaryDir,
		runtimeLoader:    sc.runtimeLoader,
		TEEHardware:      sc.TEEHardware,
		iasMock:          sc.iasMock,
	}
}

func (sc *runtimeImpl) Parameters() *flag.FlagSet {
	f := sc.e2eImpl.Parameters()
	f.StringVar(&sc.clientBinaryDir, cfgClientBinaryDir, sc.clientBinaryDir, "path to the client binaries directory")
	f.StringVar(&sc.runtimeBinaryDir, cfgRuntimeBinaryDir, sc.runtimeBinaryDir, "path to the runtime binaries directory")
	f.StringVar(&sc.runtimeLoader, cfgRuntimeLoader, sc.runtimeLoader, "path to the runtime loader")
	f.StringVar(&sc.TEEHardware, cfgTEEHardware, sc.TEEHardware, "TEE hardware to use")
	// XXX: change the default to `true` after:
	// https://github.com/oasislabs/oasis-core/issues/2897
	f.BoolVar(&sc.iasMock, cfgIasMock, sc.iasMock, "if mock IAS service should be used")

	return f
}

func (sc *runtimeImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *runtimeImpl) Fixture() (*oasis.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(sc.TEEHardware)
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &ias.FortanixTestMrSigner
	}
	keyManagerBinary, err := sc.resolveDefaultKeyManagerBinary()
	if err != nil {
		return nil, err
	}
	runtimeBinary, err := sc.resolveRuntimeBinary("simple-keyvalue")
	if err != nil {
		return nil, err
	}

	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:                        sc.nodeBinary,
			RuntimeLoaderBinary:               sc.runtimeLoader,
			DefaultLogWatcherHandlerFactories: DefaultRuntimeLogWatcherHandlerFactories,
			ConsensusGasCostsTxByte:           1,
			IAS: oasis.IASCfg{
				Mock: sc.iasMock,
			},
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
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				Binary: keyManagerBinary,
			},
			// Compute runtime.
			oasis.RuntimeFixture{
				ID:         runtimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Binary:     runtimeBinary,
				Executor: registry.ExecutorParameters{
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
					BatchFlushTimeout: 1 * time.Second,
				},
				Storage: registry.StorageParameters{
					GroupSize:               2,
					MaxApplyWriteLogEntries: 100_000,
					MaxApplyOps:             2,
					MaxMergeRoots:           8,
					MaxMergeOps:             2,
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
			},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			oasis.ValidatorFixture{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
		},
		KeymanagerPolicies: []oasis.KeymanagerPolicyFixture{
			oasis.KeymanagerPolicyFixture{Runtime: 0, Serial: 1},
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

func (sc *runtimeImpl) start(childEnv *env.Env) (<-chan error, *exec.Cmd, error) {
	var err error
	if err = sc.net.Start(); err != nil {
		return nil, nil, err
	}

	cmd, err := sc.startClient(childEnv)
	if err != nil {
		return nil, nil, err
	}

	clientErrCh := make(chan error)
	go func() {
		clientErrCh <- cmd.Wait()
	}()
	return clientErrCh, cmd, nil
}

func (sc *runtimeImpl) resolveClientBinary(clientBinary string) string {
	return filepath.Join(sc.clientBinaryDir, clientBinary)
}

func (sc *runtimeImpl) resolveRuntimeBinary(runtimeBinary string) (string, error) {
	var tee node.TEEHardware
	err := tee.FromString(sc.TEEHardware)
	if err != nil {
		return "", err
	}

	var runtimeExt string
	switch tee {
	case node.TEEHardwareInvalid:
		runtimeExt = ""
	case node.TEEHardwareIntelSGX:
		runtimeExt = ".sgxs"
	}

	return filepath.Join(sc.runtimeBinaryDir, runtimeBinary+runtimeExt), nil
}

func (sc *runtimeImpl) resolveDefaultKeyManagerBinary() (string, error) {
	return sc.resolveRuntimeBinary("simple-keymanager")
}

func (sc *runtimeImpl) startClient(env *env.Env) (*exec.Cmd, error) {
	clients := sc.net.Clients()
	if len(clients) == 0 {
		return nil, fmt.Errorf("scenario/e2e: network has no client nodes")
	}

	d, err := env.NewSubDir("client")
	if err != nil {
		return nil, err
	}

	w, err := d.NewLogWriter("client.log")
	if err != nil {
		return nil, err
	}

	args := []string{
		"--node-address", "unix:" + clients[0].SocketPath(),
		"--runtime-id", runtimeID.String(),
	}
	args = append(args, sc.clientArgs...)

	binary := sc.resolveClientBinary(sc.clientBinary)
	cmd := exec.Command(binary, args...)
	cmd.SysProcAttr = oasis.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	logger.Info("launching client",
		"binary", binary,
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("scenario/e2e: failed to start client: %w", err)
	}

	return cmd, nil
}

func (sc *runtimeImpl) cleanTendermintStorage(childEnv *env.Env) error {
	doClean := func(dataDir string, cleanArgs []string) error {
		args := append([]string{
			"unsafe-reset",
			"--" + cmdCommon.CfgDataDir, dataDir,
		}, cleanArgs...)

		return cli.RunSubCommand(childEnv, logger, "unsafe-reset", sc.net.Config().NodeBinary, args)
	}

	for _, val := range sc.net.Validators() {
		if err := doClean(val.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, cw := range sc.net.ComputeWorkers() {
		if err := doClean(cw.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, cl := range sc.net.Clients() {
		if err := doClean(cl.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, bz := range sc.net.Byzantine() {
		if err := doClean(bz.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, se := range sc.net.Sentries() {
		if err := doClean(se.DataDir(), nil); err != nil {
			return err
		}
	}
	for _, sw := range sc.net.StorageWorkers() {
		if err := doClean(sw.DataDir(), []string{"--" + cmdNode.CfgPreserveMKVSDatabase}); err != nil {
			return err
		}
	}
	for _, kw := range sc.net.Keymanagers() {
		if err := doClean(kw.DataDir(), []string{"--" + cmdNode.CfgPreserveLocalStorage}); err != nil {
			return err
		}
	}

	return nil
}

func (sc *runtimeImpl) dumpRestoreNetwork(childEnv *env.Env, fixture *oasis.NetworkFixture) error {
	// Dump-restore network.
	sc.logger.Info("dumping network state",
		"child", childEnv,
	)

	dumpPath := filepath.Join(childEnv.Dir(), "genesis_dump.json")
	args := []string{
		"genesis", "dump",
		"--height", "0",
		"--genesis.file", dumpPath,
		"--address", "unix:" + sc.net.Validators()[0].SocketPath(),
	}

	if err := cli.RunSubCommand(childEnv, logger, "genesis-dump", sc.net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to dump state: %w", err)
	}

	// Stop the network.
	logger.Info("stopping the network")
	sc.net.Stop()

	if len(sc.net.StorageWorkers()) > 0 {
		// Dump storage.
		args = []string{
			"debug", "storage", "export",
			"--genesis.file", dumpPath,
			"--datadir", sc.net.StorageWorkers()[0].DataDir(),
			"--storage.export.dir", filepath.Join(childEnv.Dir(), "storage_dumps"),
			"--debug.dont_blame_oasis",
			"--debug.allow_test_keys",
		}
		if err := cli.RunSubCommand(childEnv, logger, "storage-dump", sc.net.Config().NodeBinary, args); err != nil {
			return fmt.Errorf("scenario/e2e/dump_restore: failed to dump storage: %w", err)
		}
	}

	// Reset all the state back to the vanilla state.
	if err := sc.cleanTendermintStorage(childEnv); err != nil {
		return fmt.Errorf("scenario/e2e/dump_restore: failed to clean tendemint storage: %w", err)
	}

	// Start the network and the client again.
	logger.Info("starting the network again")

	fixture.Network.GenesisFile = dumpPath
	// Make sure to not overwrite entities.
	for i, entity := range fixture.Entities {
		if !entity.IsDebugTestEntity {
			fixture.Entities[i].Restore = true
		}
	}

	var err error
	if sc.net, err = fixture.Create(childEnv); err != nil {
		return err
	}

	// If network is used, enable shorter per-node socket paths, because some e2e test datadir
	// exceed maximum unix socket path length.
	sc.net.Config().UseShortGrpcSocketPaths = true

	return nil
}

func (sc *runtimeImpl) finishWithoutChild() error {
	var err error
	select {
	case err = <-sc.net.Errors():
		return err
	default:
		return sc.net.CheckLogWatchers()
	}
}

func (sc *runtimeImpl) wait(childEnv *env.Env, cmd *exec.Cmd, clientErrCh <-chan error) error {
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

func (sc *runtimeImpl) Run(childEnv *env.Env) error {
	clientErrCh, cmd, err := sc.start(childEnv)
	if err != nil {
		return err
	}

	return sc.wait(childEnv, cmd, clientErrCh)
}

func (sc *runtimeImpl) submitRuntimeTx(ctx context.Context, id common.Namespace, method string, args interface{}) (cbor.RawMessage, error) {
	c := sc.net.ClientController().RuntimeClient

	// Submit a transaction and check the result.
	var rsp runtimeTransaction.TxnOutput
	rawRsp, err := c.SubmitTx(ctx, &runtimeClient.SubmitTxRequest{
		RuntimeID: id,
		Data: cbor.Marshal(&runtimeTransaction.TxnCall{
			Method: method,
			Args:   args,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit runtime tx: %w", err)
	}
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return nil, fmt.Errorf("malformed tx output from runtime: %w", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("runtime tx failed: %s", *rsp.Error)
	}
	return rsp.Success, nil
}

func (sc *runtimeImpl) submitKeyValueRuntimeInsertTx(ctx context.Context, id common.Namespace, key, value string) error {
	_, err := sc.submitRuntimeTx(ctx, id, "insert", struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{
		Key:   key,
		Value: value,
	})
	return err
}

func (sc *runtimeImpl) waitNodesSynced() error {
	ctx := context.Background()

	checkSynced := func(n *oasis.Node) error {
		c, err := oasis.NewController(n.SocketPath())
		if err != nil {
			return fmt.Errorf("failed to create node controller: %w", err)
		}
		defer c.Close()

		if err = c.WaitSync(ctx); err != nil {
			return fmt.Errorf("failed to wait for node to sync: %w", err)
		}
		return nil
	}

	sc.logger.Info("waiting for all nodes to be synced")

	for _, n := range sc.net.Validators() {
		if err := checkSynced(&n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.net.StorageWorkers() {
		if err := checkSynced(&n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.net.ComputeWorkers() {
		if err := checkSynced(&n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.net.Clients() {
		if err := checkSynced(&n.Node); err != nil {
			return err
		}
	}

	sc.logger.Info("nodes synced")
	return nil
}

func (sc *runtimeImpl) initialEpochTransitions() error {
	ctx := context.Background()

	if len(sc.net.Keymanagers()) > 0 {
		// First wait for validator and key manager nodes to register. Then perform an epoch
		// transition which will cause the compute and storage nodes to register.
		numNodes := len(sc.net.Validators()) + len(sc.net.Keymanagers())
		sc.logger.Info("waiting for (some) nodes to register",
			"num_nodes", numNodes,
		)

		if err := sc.net.Controller().WaitNodesRegistered(ctx, numNodes); err != nil {
			return fmt.Errorf("failed to wait for nodes: %w", err)
		}

		sc.logger.Info("triggering epoch transition")
		if err := sc.net.Controller().SetEpoch(ctx, 1); err != nil {
			return fmt.Errorf("failed to set epoch: %w", err)
		}
		sc.logger.Info("epoch transition done")
	}

	// Wait for all nodes to register.
	sc.logger.Info("waiting for (all) nodes to register",
		"num_nodes", sc.net.NumRegisterNodes(),
	)

	if err := sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
		return fmt.Errorf("failed to wait for nodes: %w", err)
	}

	// Then perform another epoch transition to elect the committees.
	sc.logger.Info("triggering epoch transition")
	if err := sc.net.Controller().SetEpoch(ctx, 2); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.logger.Info("epoch transition done")
	return nil
}
