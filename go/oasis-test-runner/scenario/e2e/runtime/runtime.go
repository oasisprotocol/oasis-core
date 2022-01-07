package runtime

import (
	"context"
	"crypto/rand"
	"fmt"
	"path/filepath"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	cfgRuntimeBinaryDirDefault  = "runtime.binary_dir.default"
	cfgRuntimeBinaryDirIntelSGX = "runtime.binary_dir.intel-sgx"
	cfgRuntimeLoader            = "runtime.loader"
	cfgTEEHardware              = "tee_hardware"
	cfgIasMock                  = "ias.mock"
	cfgEpochInterval            = "epoch.interval"
)

var (
	// RuntimeParamsDummy is a dummy instance of runtimeImpl used to register global e2e/runtime flags.
	RuntimeParamsDummy *runtimeImpl = newRuntimeImpl("", nil)

	// Runtime is the basic network + client test case with runtime support.
	Runtime scenario.Scenario = newRuntimeImpl("runtime", BasicKVTestClient)
	// RuntimeEncryption is the basic network + client with encryption test case.
	RuntimeEncryption scenario.Scenario = newRuntimeImpl("runtime-encryption", BasicKVEncTestClient)

	// DefaultRuntimeLogWatcherHandlerFactories is a list of default log watcher
	// handler factories for the basic scenario.
	DefaultRuntimeLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertNoExecutionDiscrepancyDetected(),
	}

	runtimeID    common.Namespace
	keymanagerID common.Namespace
	_            = runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	_            = keymanagerID.UnmarshalHex("c000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff")
)

// TxnCall is a transaction call in the test runtime.
type TxnCall struct {
	// Method is the called method name.
	Method string `json:"method"`
	// Args are the method arguments.
	Args interface{} `json:"args"`
}

// TxnOutput is a transaction call output in the test runtime.
type TxnOutput struct {
	// Success can be of any type.
	Success cbor.RawMessage
	// Error is a string describing the error message.
	Error *string
}

// runtimeImpl is a base class for tests involving oasis-node with runtime.
type runtimeImpl struct {
	e2e.E2E

	testClient TestClient

	// This disables the random initial epoch for tests that are extremely
	// sensitive to the initial epoch.  Ideally this shouldn't be set for
	// any of our tests, but I'm sick and tired of trying to debug poorly
	// written test cases.
	//
	// If your new test needs this, your test is bad, and you should go
	// and rewrite it so that this option isn't set.
	debugNoRandomInitialEpoch bool

	// The byzantine tests also explode since the node only runs for
	// a single epoch.
	//
	// If your new test needs this, your test is bad, and you should go
	// and rewrite it so that this option isn't set.
	debugWeakAlphaOk bool
}

func newRuntimeImpl(name string, testClient TestClient) *runtimeImpl {
	// Empty scenario name is used for registering global parameters only.
	fullName := "runtime"
	if name != "" {
		fullName += "/" + name
	}

	sc := &runtimeImpl{
		E2E:        *e2e.NewE2E(fullName),
		testClient: testClient,
	}
	sc.Flags.String(cfgRuntimeBinaryDirDefault, "", "(no-TEE) path to the runtime binaries directory")
	sc.Flags.String(cfgRuntimeBinaryDirIntelSGX, "", "(Intel SGX) path to the runtime binaries directory")
	sc.Flags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	sc.Flags.String(cfgTEEHardware, "", "TEE hardware to use")
	sc.Flags.Bool(cfgIasMock, true, "if mock IAS service should be used")
	sc.Flags.Int64(cfgEpochInterval, 0, "epoch interval")

	return sc
}

func (sc *runtimeImpl) Clone() scenario.Scenario {
	var testClient TestClient
	if sc.testClient != nil {
		testClient = sc.testClient.Clone()
	}
	return &runtimeImpl{
		E2E:                       sc.E2E.Clone(),
		testClient:                testClient,
		debugNoRandomInitialEpoch: sc.debugNoRandomInitialEpoch,
		debugWeakAlphaOk:          sc.debugWeakAlphaOk,
	}
}

func (sc *runtimeImpl) PreInit(childEnv *env.Env) error {
	return nil
}

func (sc *runtimeImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	tee, err := sc.getTEEHardware()
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &sgx.FortanixDummyMrSigner
	}
	keyManagerBinary := "simple-keymanager"
	runtimeBinary := "simple-keyvalue"
	runtimeLoader, _ := sc.Flags.GetString(cfgRuntimeLoader)
	iasMock, _ := sc.Flags.GetBool(cfgIasMock)
	ff := &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:                        f.Network.NodeBinary,
			RuntimeSGXLoaderBinary:            runtimeLoader,
			DefaultLogWatcherHandlerFactories: DefaultRuntimeLogWatcherHandlerFactories,
			Consensus:                         f.Network.Consensus,
			IAS: oasis.IASCfg{
				Mock: iasMock,
			},
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
			{},
		},
		Runtimes: []oasis.RuntimeFixture{
			// Key manager runtime.
			{
				ID:         keymanagerID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				Binaries:        sc.resolveRuntimeBinaries([]string{keyManagerBinary}),
				GovernanceModel: registry.GovernanceEntity,
			},
			// Compute runtime.
			{
				ID:         runtimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Binaries:   sc.resolveRuntimeBinaries([]string{runtimeBinary}),
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    20,
					MaxMessages:     128,
				},
				TxnScheduler: registry.TxnSchedulerParameters{
					Algorithm:         registry.TxnSchedulerSimple,
					MaxBatchSize:      1,
					MaxBatchSizeBytes: 1024,
					BatchFlushTimeout: 1 * time.Second,
					ProposerTimeout:   20,
					MaxInMessages:     128,
				},
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
					scheduler.KindComputeExecutor: {
						scheduler.RoleWorker: {
							MinPoolSize: &registry.MinPoolSizeConstraint{
								Limit: 2,
							},
						},
						scheduler.RoleBackupWorker: {
							MinPoolSize: &registry.MinPoolSizeConstraint{
								Limit: 1,
							},
						},
					},
				},
				GovernanceModel: registry.GovernanceEntity,
			},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true, SupplementarySanityInterval: 1}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{EnableConsensusRPCWorker: true}},
		},
		KeymanagerPolicies: []oasis.KeymanagerPolicyFixture{
			{Runtime: 0, Serial: 1},
		},
		Keymanagers: []oasis.KeymanagerFixture{
			{Runtime: 0, Entity: 1},
		},
		ComputeWorkers: []oasis.ComputeWorkerFixture{
			{Entity: 1, Runtimes: []int{1}},
			{Entity: 1, Runtimes: []int{1}, RuntimeConfig: map[int]map[string]interface{}{
				1: {
					"core": map[string]interface{}{
						"min_gas_price": 1, // Just to test support for runtime configuration.
					},
				},
			}},
			{Entity: 1, Runtimes: []int{1}},
		},
		Sentries: []oasis.SentryFixture{},
		Seeds:    []oasis.SeedFixture{{}},
		Clients: []oasis.ClientFixture{
			{Runtimes: []int{1}},
		},
	}

	if epochInterval, _ := sc.Flags.GetInt64(cfgEpochInterval); epochInterval > 0 {
		ff.Network.Beacon.InsecureParameters = &beacon.InsecureParameters{
			Interval: epochInterval,
		}
		ff.Network.Beacon.VRFParameters = &beacon.VRFParameters{
			AlphaHighQualityThreshold: 3,
			Interval:                  epochInterval,
			ProofSubmissionDelay:      epochInterval / 2,
		}
	}

	return ff, nil
}

// getTEEHardware returns the configured TEE hardware.
func (sc *runtimeImpl) getTEEHardware() (node.TEEHardware, error) {
	teeStr, _ := sc.Flags.GetString(cfgTEEHardware)
	var tee node.TEEHardware
	if err := tee.FromString(teeStr); err != nil {
		return node.TEEHardwareInvalid, err
	}
	return tee, nil
}

func (sc *runtimeImpl) resolveRuntimeBinaries(runtimeBinaries []string) map[node.TEEHardware][]string {
	binaries := make(map[node.TEEHardware][]string)
	for _, tee := range []node.TEEHardware{
		node.TEEHardwareInvalid,
		node.TEEHardwareIntelSGX,
	} {
		for _, binary := range runtimeBinaries {
			binaries[tee] = append(binaries[tee], sc.resolveRuntimeBinary(binary, tee))
		}
	}
	return binaries
}

func (sc *runtimeImpl) resolveRuntimeBinary(runtimeBinary string, tee node.TEEHardware) string {
	var runtimeExt, path string
	switch tee {
	case node.TEEHardwareInvalid:
		runtimeExt = ""
		path, _ = sc.Flags.GetString(cfgRuntimeBinaryDirDefault)
	case node.TEEHardwareIntelSGX:
		runtimeExt = ".sgxs"
		path, _ = sc.Flags.GetString(cfgRuntimeBinaryDirIntelSGX)
	}

	return filepath.Join(path, runtimeBinary+runtimeExt)
}

func (sc *runtimeImpl) startNetworkAndTestClient(ctx context.Context, childEnv *env.Env) error {
	// Start the network
	if err := sc.startNetworkAndWaitForClientSync(ctx); err != nil {
		return fmt.Errorf("failed to initialize network: %w", err)
	}

	return sc.startTestClientOnly(ctx, childEnv)
}

func (sc *runtimeImpl) startTestClientOnly(ctx context.Context, childEnv *env.Env) error {
	if err := sc.testClient.Init(sc); err != nil {
		return fmt.Errorf("failed to initialize test client: %w", err)
	}

	if err := sc.testClient.Start(ctx, childEnv); err != nil {
		return fmt.Errorf("failed to start test client: %w", err)
	}

	return nil
}

func (sc *runtimeImpl) waitTestClientOnly() error {
	return sc.testClient.Wait()
}

func (sc *runtimeImpl) checkTestClientLogs() error {
	// Wait for logs to be fully processed before checking them. When
	// the client exits very quickly the log watchers may not have
	// processed the relevant logs yet.
	//
	// TODO: Find a better way to synchronize log watchers.
	time.Sleep(1 * time.Second)

	return sc.Net.CheckLogWatchers()
}

func (sc *runtimeImpl) waitTestClient() error {
	if err := sc.waitTestClientOnly(); err != nil {
		return err
	}
	return sc.checkTestClientLogs()
}

func (sc *runtimeImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()
	if err := sc.startNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	return sc.waitTestClient()
}

func (sc *runtimeImpl) submitRuntimeTx(ctx context.Context, id common.Namespace, method string, args interface{}) (cbor.RawMessage, error) {
	// Submit a transaction and check the result.
	metaResp, err := sc.submitRuntimeTxMeta(ctx, id, method, args)
	if err != nil {
		return nil, err
	}
	rsp, err := unpackRawTxResp(metaResp.Output)
	if err != nil {
		return nil, err
	}
	return rsp, nil
}

func (sc *runtimeImpl) submitRuntimeTxMeta(
	ctx context.Context,
	id common.Namespace,
	method string,
	args interface{},
) (*runtimeClient.SubmitTxMetaResponse, error) {
	ctrl := sc.Net.ClientController()
	if ctrl == nil {
		return nil, fmt.Errorf("client controller not available")
	}
	c := ctrl.RuntimeClient

	resp, err := c.SubmitTxMeta(ctx, &runtimeClient.SubmitTxRequest{
		RuntimeID: id,
		Data: cbor.Marshal(&TxnCall{
			Method: method,
			Args:   args,
		}),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit runtime meta tx: %w", err)
	}

	return resp, nil
}

func unpackRawTxResp(rawRsp []byte) (cbor.RawMessage, error) {
	var rsp TxnOutput
	if err := cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return nil, fmt.Errorf("malformed tx output from runtime: %w", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("runtime tx failed: %s", *rsp.Error)
	}
	return rsp.Success, nil
}

func (sc *runtimeImpl) submitConsensusXferTx(
	ctx context.Context,
	id common.Namespace,
	xfer staking.Transfer,
	nonce uint64,
) error {
	_, err := sc.submitRuntimeTx(ctx, runtimeID, "consensus_transfer", struct {
		Transfer staking.Transfer `json:"transfer"`
		Nonce    uint64           `json:"nonce"`
	}{
		Transfer: xfer,
		Nonce:    nonce,
	})
	return err
}

func (sc *runtimeImpl) submitConsensusXferTxMeta(
	ctx context.Context,
	id common.Namespace,
	xfer staking.Transfer,
	nonce uint64,
) (*runtimeClient.SubmitTxMetaResponse, error) {
	return sc.submitRuntimeTxMeta(ctx, runtimeID, "consensus_transfer", struct {
		Transfer staking.Transfer `json:"transfer"`
		Nonce    uint64           `json:"nonce"`
	}{
		Transfer: xfer,
		Nonce:    nonce,
	})
}

func (sc *runtimeImpl) submitRuntimeInMsg(ctx context.Context, id common.Namespace, method string, args interface{}) error {
	ctrl := sc.Net.ClientController()
	if ctrl == nil {
		return fmt.Errorf("client controller not available")
	}

	// Queue a runtime message and wait for it to be processed.
	tx := roothash.NewSubmitMsgTx(0, &transaction.Fee{Gas: 10_000}, &roothash.SubmitMsg{
		ID:  id,
		Tag: 42,
		Data: cbor.Marshal(&TxnCall{
			Method: method,
			Args:   args,
		}),
	})
	signer := memorySigner.NewTestSigner("oasis in msg test signer: " + time.Now().String())
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		return fmt.Errorf("failed to sign SubmitMsg transaction: %w", err)
	}

	// Start watching roothash events.
	ch, sub, err := ctrl.Roothash.WatchEvents(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to watch events: %w", err)
	}
	defer sub.Close()

	err = ctrl.Consensus.SubmitTx(ctx, sigTx)
	if err != nil {
		return fmt.Errorf("failed to submit SubmitMsg transaction: %w", err)
	}

	// Wait for processed event.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	sc.Logger.Info("waiting for incoming message processed event")
	callerAddr := staking.NewAddress(signer.Public())
	for {
		select {
		case ev := <-ch:
			if ev.InMsgProcessed == nil {
				continue
			}

			if !ev.InMsgProcessed.Caller.Equal(callerAddr) {
				return fmt.Errorf("unexpected caller address (got: %s expected: %s)", ev.InMsgProcessed.Caller, callerAddr)
			}
			if ev.InMsgProcessed.Tag != 42 {
				return fmt.Errorf("unexpected tag (got: %d expected: %d)", ev.InMsgProcessed.Tag, 42)
			}
		case <-ctx.Done():
			return ctx.Err()
		}

		break
	}

	return nil
}

func (sc *runtimeImpl) waitForClientSync(ctx context.Context) error {
	clients := sc.Net.Clients()
	if len(clients) == 0 {
		return fmt.Errorf("scenario/e2e: network has no client nodes")
	}

	sc.Logger.Info("ensuring client node is synced")
	ctrl, err := oasis.NewController(clients[0].SocketPath())
	if err != nil {
		return fmt.Errorf("failed to create controller for client: %w", err)
	}
	if err = ctrl.WaitSync(ctx); err != nil {
		return fmt.Errorf("client-0 failed to sync: %w", err)
	}

	return nil
}

func (sc *runtimeImpl) startNetworkAndWaitForClientSync(ctx context.Context) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	return sc.waitForClientSync(ctx)
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

	sc.Logger.Info("waiting for all nodes to be synced")

	for _, n := range sc.Net.Validators() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.Net.ComputeWorkers() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}
	for _, n := range sc.Net.Clients() {
		if err := checkSynced(n.Node); err != nil {
			return err
		}
	}

	sc.Logger.Info("nodes synced")
	return nil
}

func (sc *runtimeImpl) initialEpochTransitions(fixture *oasis.NetworkFixture) (beacon.EpochTime, error) {
	return sc.initialEpochTransitionsWith(fixture, 0)
}

func (sc *runtimeImpl) initialEpochTransitionsWith(fixture *oasis.NetworkFixture, baseEpoch beacon.EpochTime) (beacon.EpochTime, error) {
	ctx := context.Background()

	epoch := baseEpoch + 1
	advanceEpoch := func() error {
		sc.Logger.Info("triggering epoch transition",
			"epoch", epoch,
		)
		if err := sc.Net.Controller().SetEpoch(ctx, epoch); err != nil {
			return fmt.Errorf("failed to set epoch: %w", err)
		}
		sc.Logger.Info("epoch transition done",
			"epoch", epoch,
		)

		epoch++

		return nil
	}

	if len(sc.Net.Keymanagers()) > 0 {
		// First wait for validator and key manager nodes to register. Then perform an epoch
		// transition which will cause the compute and storage nodes to register.
		sc.Logger.Info("waiting for validators to initialize",
			"num_validators", len(sc.Net.Validators()),
		)
		for i, n := range sc.Net.Validators() {
			if fixture.Validators[i].NoAutoStart {
				// Skip nodes that don't auto start.
				continue
			}
			if err := n.WaitReady(ctx); err != nil {
				return epoch, fmt.Errorf("failed to wait for a validator: %w", err)
			}
		}
		sc.Logger.Info("waiting for key managers to initialize",
			"num_keymanagers", len(sc.Net.Keymanagers()),
		)
		for i, n := range sc.Net.Keymanagers() {
			if fixture.Keymanagers[i].NoAutoStart {
				// Skip nodes that don't auto start.
				continue
			}
			if err := n.WaitReady(ctx); err != nil {
				return epoch, fmt.Errorf("failed to wait for a key manager: %w", err)
			}
		}
	}

	if err := advanceEpoch(); err != nil { // Epoch 1
		return epoch, err
	}

	// Wait for compute workers to become ready.
	sc.Logger.Info("waiting for compute workers to initialize",
		"num_compute_workers", len(sc.Net.ComputeWorkers()),
	)
	for i, n := range sc.Net.ComputeWorkers() {
		if fixture.ComputeWorkers[i].NoAutoStart {
			// Skip nodes that don't auto start.
			continue
		}
		if err := n.WaitReady(ctx); err != nil {
			return epoch, fmt.Errorf("failed to wait for a compute worker: %w", err)
		}
	}

	// Byzantine nodes can only registered. If defined, since we cannot control them directly, wait
	// for all nodes to become registered.
	if len(sc.Net.Byzantine()) > 0 {
		sc.Logger.Info("waiting for (all) nodes to register",
			"num_nodes", sc.Net.NumRegisterNodes(),
		)
		if err := sc.Net.Controller().WaitNodesRegistered(ctx, sc.Net.NumRegisterNodes()); err != nil {
			return epoch, fmt.Errorf("failed to wait for nodes: %w", err)
		}
	}

	// Then perform epoch transition(s) to elect the committees.
	if err := advanceEpoch(); err != nil { // Epoch 2
		return epoch, err
	}
	switch sc.Net.Config().Beacon.Backend {
	case "", beacon.BackendVRF:
		// The byzantine node gets jammed into a committee first thing, which
		// breaks everything because our test case failure detection log watcher
		// can't cope with expected failures.  So once we elect, if the byzantine
		// node is active, we need to immediately transition into doing interesting
		// things.
		if !sc.debugWeakAlphaOk {
			// Committee elections won't happen the first round.
			if err := advanceEpoch(); err != nil { // Epoch 3
				return epoch, err
			}
			// And nodes are ineligible to be elected till their registration
			// epoch + 2.
			if err := advanceEpoch(); err != nil { // Epoch 4 (or 3 if byzantine test)
				return epoch, err
			}
		}
		if !sc.debugNoRandomInitialEpoch {
			// To prevent people from writing tests that depend on very precicse
			// timekeeping by epoch, randomize the start epoch slightly.
			//
			// If this causes your test to fail, it is not this code that is
			// wrong, it is the test that is wrong.
			var randByte [1]byte
			_, _ = rand.Read(randByte[:])
			numSkips := (int)(randByte[0]&3) + 1
			sc.Logger.Info("advancing the epoch to prevent hardcoding time assumptions in tests",
				"num_advances", numSkips,
			)
			for i := 0; i < numSkips; i++ {
				if err := advanceEpoch(); err != nil {
					return epoch, err
				}
			}
		}
	}

	return epoch, nil
}

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(RuntimeParamsDummy.Name(), RuntimeParamsDummy.Parameters())

	// Register default scenarios which are executed, if no test names provided.
	for _, s := range []scenario.Scenario{
		// Runtime test.
		Runtime,
		RuntimeEncryption,
		RuntimeGovernance,
		RuntimeMessage,
		// Byzantine executor node.
		ByzantineExecutorHonest,
		ByzantineExecutorSchedulerHonest,
		ByzantineExecutorWrong,
		ByzantineExecutorSchedulerWrong,
		ByzantineExecutorSchedulerBogus,
		ByzantineExecutorStraggler,
		ByzantineExecutorSchedulerStraggler,
		ByzantineExecutorFailureIndicating,
		ByzantineExecutorSchedulerFailureIndicating,
		ByzantineExecutorCorruptGetDiff,
		// Storage sync test.
		StorageSync,
		StorageSyncFromRegistered,
		StorageSyncInconsistent,
		StorageEarlyStateSync,
		// Sentry test.
		Sentry,
		SentryEncryption,
		// Keymanager restart test.
		KeymanagerRestart,
		// Keymanager replicate test.
		KeymanagerReplicate,
		// Dump/restore test.
		DumpRestore,
		DumpRestoreRuntimeRoundAdvance,
		// Halt test.
		HaltRestore,
		HaltRestoreSuspended,
		// Consensus upgrade tests.
		GovernanceConsensusUpgrade,
		GovernanceConsensusFailUpgrade,
		GovernanceConsensusCancelUpgrade,
		// Multiple runtimes test.
		MultipleRuntimes,
		// Node shutdown test.
		NodeShutdown,
		OffsetRestart,
		// Gas fees tests.
		GasFeesRuntimes,
		// Runtime prune test.
		RuntimePrune,
		// Runtime dynamic registration test.
		RuntimeDynamic,
		// Transaction source test.
		TxSourceMultiShort,
		// Late start test.
		LateStart,
		// KeymanagerUpgrade test.
		KeymanagerUpgrade,
		// RuntimeUpgrade test.
		RuntimeUpgrade,
		// HistoryReindex test.
		HistoryReindex,
		// TrustRoot test.
		TrustRoot,
	} {
		if err := cmd.Register(s); err != nil {
			return err
		}
	}

	// Register non-default scenarios which are executed on-demand only.
	for _, s := range []scenario.Scenario{
		// Transaction source test. Non-default, because it runs for ~6 hours.
		TxSourceMulti,
		// SGX version of the txsource-multi-short test. Non-default, because
		// it is identical to the txsource-multi-short, only using fewer nodes
		// due to SGX CI instance resource constrains.
		TxSourceMultiShortSGX,
	} {
		if err := cmd.RegisterNondefault(s); err != nil {
			return err
		}
	}

	return nil
}
