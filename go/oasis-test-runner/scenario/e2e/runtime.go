package e2e

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	runtimeTransaction "github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	"github.com/oasisprotocol/oasis-core/go/storage/database"
)

const (
	cfgClientBinaryDir  = "client.binary_dir"
	cfgRuntimeBinaryDir = "runtime.binary_dir"
	cfgRuntimeLoader    = "runtime.loader"
	cfgTEEHardware      = "tee_hardware"
	cfgIasMock          = "ias.mock"
)

var (
	// RuntimeParamsDummy is a dummy instance of runtimeImpl used to register global e2e/runtime flags.
	RuntimeParamsDummy *runtimeImpl = newRuntimeImpl("", "", []string{})

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
}

func newRuntimeImpl(name, clientBinary string, clientArgs []string) *runtimeImpl {
	// Empty scenario name is used for registering global parameters only.
	fullName := "runtime"
	if name != "" {
		fullName += "/" + name
	}

	sc := &runtimeImpl{
		e2eImpl:      *newE2eImpl(fullName),
		clientBinary: clientBinary,
		clientArgs:   clientArgs,
	}
	sc.flags.String(cfgClientBinaryDir, "", "path to the client binaries directory")
	sc.flags.String(cfgRuntimeBinaryDir, "", "path to the runtime binaries directory")
	sc.flags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	sc.flags.String(cfgTEEHardware, "", "TEE hardware to use")
	sc.flags.Bool(cfgIasMock, true, "if mock IAS service should be used")

	return sc
}

func (sc *runtimeImpl) Clone() scenario.Scenario {
	return &runtimeImpl{
		e2eImpl:      sc.e2eImpl.Clone(),
		clientBinary: sc.clientBinary,
		clientArgs:   sc.clientArgs,
	}
}

func (sc *runtimeImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *runtimeImpl) Fixture() (*oasis.NetworkFixture, error) {
	tee, err := sc.getTEEHardware()
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &sgx.FortanixDummyMrSigner
	}
	keyManagerBinary, err := sc.resolveDefaultKeyManagerBinary()
	if err != nil {
		return nil, err
	}
	runtimeBinary, err := sc.resolveRuntimeBinary("simple-keyvalue")
	if err != nil {
		return nil, err
	}
	nodeBinary, _ := sc.flags.GetString(cfgNodeBinary)
	runtimeLoader, _ := sc.flags.GetString(cfgRuntimeLoader)
	iasMock, _ := sc.flags.GetBool(cfgIasMock)
	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:                        nodeBinary,
			RuntimeSGXLoaderBinary:            runtimeLoader,
			DefaultLogWatcherHandlerFactories: DefaultRuntimeLogWatcherHandlerFactories,
			ConsensusGasCostsTxByte:           1,
			IAS: oasis.IASCfg{
				Mock: iasMock,
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
				Binaries: []string{keyManagerBinary},
			},
			// Compute runtime.
			oasis.RuntimeFixture{
				ID:         runtimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Binaries:   []string{runtimeBinary},
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
					MinWriteReplication:     2,
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

// getTEEHardware returns the configured TEE hardware.
func (sc *runtimeImpl) getTEEHardware() (node.TEEHardware, error) {
	teeStr, _ := sc.flags.GetString(cfgTEEHardware)
	var tee node.TEEHardware
	if err := tee.FromString(teeStr); err != nil {
		return node.TEEHardwareInvalid, err
	}
	return tee, nil
}

func (sc *runtimeImpl) resolveClientBinary(clientBinary string) string {
	cbDir, _ := sc.flags.GetString(cfgClientBinaryDir)
	return filepath.Join(cbDir, clientBinary)
}

func (sc *runtimeImpl) resolveRuntimeBinary(runtimeBinary string) (string, error) {
	tee, err := sc.getTEEHardware()
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

	rtBinDir, _ := sc.flags.GetString(cfgRuntimeBinaryDir)
	return filepath.Join(rtBinDir, runtimeBinary+runtimeExt), nil
}

func (sc *runtimeImpl) resolveDefaultKeyManagerBinary() (string, error) {
	return sc.resolveRuntimeBinary("simple-keymanager")
}

func (sc *runtimeImpl) startClient(childEnv *env.Env) (*exec.Cmd, error) {
	clients := sc.net.Clients()
	if len(clients) == 0 {
		return nil, fmt.Errorf("scenario/e2e: network has no client nodes")
	}

	d, err := childEnv.NewSubDir("client")
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
	cmd.SysProcAttr = env.CmdAttrs
	cmd.Stdout = w
	cmd.Stderr = w

	sc.logger.Info("launching client",
		"binary", binary,
		"args", strings.Join(args, " "),
	)

	if err = cmd.Start(); err != nil {
		return nil, fmt.Errorf("scenario/e2e: failed to start client: %w", err)
	}

	return cmd, nil
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
		sc.logger.Info("waiting for validators to initialize",
			"num_validators", len(sc.net.Validators()),
		)
		for _, n := range sc.net.Validators() {
			if err := n.WaitReady(ctx); err != nil {
				return fmt.Errorf("failed to wait for a validator: %w", err)
			}
		}
		sc.logger.Info("waiting for key managers to initialize",
			"num_keymanagers", len(sc.net.Keymanagers()),
		)
		for _, n := range sc.net.Keymanagers() {
			if err := n.WaitReady(ctx); err != nil {
				return fmt.Errorf("failed to wait for a key manager: %w", err)
			}
		}
		sc.logger.Info("triggering epoch transition")
		if err := sc.net.Controller().SetEpoch(ctx, 1); err != nil {
			return fmt.Errorf("failed to set epoch: %w", err)
		}
		sc.logger.Info("epoch transition done")
	}

	// Wait for storage workers and compute workers to become ready.
	sc.logger.Info("waiting for storage workers to initialize",
		"num_storage_workers", len(sc.net.StorageWorkers()),
	)
	for _, n := range sc.net.StorageWorkers() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a storage worker: %w", err)
		}
	}
	sc.logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.net.ComputeWorkers()),
	)
	for _, n := range sc.net.ComputeWorkers() {
		if err := n.WaitReady(ctx); err != nil {
			return fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Byzantine nodes can only registered. If defined, since we cannot control them directly, wait
	// for all nodes to become registered.
	if len(sc.net.Byzantine()) > 0 {
		sc.logger.Info("waiting for (all) nodes to register",
			"num_nodes", sc.net.NumRegisterNodes(),
		)
		if err := sc.net.Controller().WaitNodesRegistered(ctx, sc.net.NumRegisterNodes()); err != nil {
			return fmt.Errorf("failed to wait for nodes: %w", err)
		}
	}

	// Then perform another epoch transition to elect the committees.
	sc.logger.Info("triggering epoch transition")
	if err := sc.net.Controller().SetEpoch(ctx, 2); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}
	sc.logger.Info("epoch transition done")

	return nil
}
