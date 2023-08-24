package runtime

import (
	"context"
	"fmt"
	"time"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/cmd"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/log"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario/e2e"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	runtimeConfig "github.com/oasisprotocol/oasis-core/go/runtime/config"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const (
	cfgRuntimeBinaryDirDefault  = "runtime.binary_dir.default"
	cfgRuntimeBinaryDirIntelSGX = "runtime.binary_dir.intel-sgx"
	cfgRuntimeSourceDir         = "runtime.source_dir"
	cfgRuntimeTargetDir         = "runtime.target_dir"
	cfgRuntimeLoader            = "runtime.loader"
	cfgRuntimeProvisioner       = "runtime.provisioner"
	cfgTEEHardware              = "tee_hardware"
	cfgIasMock                  = "ias.mock"
	cfgEpochInterval            = "epoch.interval"
)

var (
	// ParamsDummyScenario is a dummy instance of runtimeImpl used to register global e2e/runtime flags.
	ParamsDummyScenario = NewScenario("", nil)

	// Runtime is the basic network + client test case with runtime support.
	Runtime scenario.Scenario = NewScenario(
		"runtime",
		NewTestClient().WithScenario(SimpleKeyValueScenario),
	)

	// RuntimeEncryption is the basic network + client with encryption test case.
	RuntimeEncryption scenario.Scenario = NewScenario(
		"runtime-encryption",
		NewTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
	)

	// DefaultRuntimeLogWatcherHandlerFactories is a list of default log watcher
	// handler factories for the basic scenario.
	DefaultRuntimeLogWatcherHandlerFactories = []log.WatcherHandlerFactory{
		oasis.LogAssertNoTimeouts(),
		oasis.LogAssertNoRoundFailures(),
		oasis.LogAssertNoExecutionDiscrepancyDetected(),
	}
)

// Scenario is a base class for tests involving oasis-node with runtime.
type Scenario struct {
	e2e.Scenario

	TestClient *TestClient

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

// NewScenario creates a new base scenario for oasis-node runtime end-to-end tests.
func NewScenario(name string, testClient *TestClient) *Scenario {
	// Empty scenario name is used for registering global parameters only.
	fullName := "runtime"
	if name != "" {
		fullName += "/" + name
	}

	sc := &Scenario{
		Scenario:   *e2e.NewScenario(fullName),
		TestClient: testClient,
	}
	sc.Flags.String(cfgRuntimeBinaryDirDefault, "", "(no-TEE) path to the runtime binaries directory")
	sc.Flags.String(cfgRuntimeBinaryDirIntelSGX, "", "(Intel SGX) path to the runtime binaries directory")
	sc.Flags.String(cfgRuntimeSourceDir, "", "path to the runtime source base dir")
	sc.Flags.String(cfgRuntimeTargetDir, "", "path to the Cargo target dir (should be a parent of the runtime binary dir)")
	sc.Flags.String(cfgRuntimeLoader, "oasis-core-runtime-loader", "path to the runtime loader")
	sc.Flags.String(cfgRuntimeProvisioner, "sandboxed", "the runtime provisioner: mock, unconfined, or sandboxed")
	sc.Flags.String(cfgTEEHardware, "", "TEE hardware to use")
	sc.Flags.Bool(cfgIasMock, true, "if mock IAS service should be used")
	sc.Flags.Int64(cfgEpochInterval, 0, "epoch interval")

	return sc
}

func (sc *Scenario) Clone() scenario.Scenario {
	var testClient *TestClient
	if sc.TestClient != nil {
		testClient = sc.TestClient.Clone()
	}
	return &Scenario{
		Scenario:                  sc.Scenario.Clone(),
		TestClient:                testClient,
		debugNoRandomInitialEpoch: sc.debugNoRandomInitialEpoch,
		debugWeakAlphaOk:          sc.debugWeakAlphaOk,
	}
}

func (sc *Scenario) PreInit() error {
	return nil
}

func (sc *Scenario) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	tee, err := sc.TEEHardware()
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &sgx.FortanixDummyMrSigner
	}
	runtimeLoader, _ := sc.Flags.GetString(cfgRuntimeLoader)
	iasMock, _ := sc.Flags.GetBool(cfgIasMock)
	runtimeProvisionerRaw, _ := sc.Flags.GetString(cfgRuntimeProvisioner)
	var runtimeProvisioner runtimeConfig.RuntimeProvisioner
	if err = runtimeProvisioner.UnmarshalText([]byte(runtimeProvisionerRaw)); err != nil {
		return nil, fmt.Errorf("failed to parse runtime provisioner: %w", err)
	}

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
				ID:         KeyManagerRuntimeID,
				Kind:       registry.KindKeyManager,
				Entity:     0,
				Keymanager: -1,
				AdmissionPolicy: registry.RuntimeAdmissionPolicy{
					AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
				},
				GovernanceModel: registry.GovernanceEntity,
				Deployments: []oasis.DeploymentCfg{
					{
						Binaries: sc.ResolveRuntimeBinaries(KeyManagerRuntimeBinary),
					},
				},
			},
			// Compute runtime.
			{
				ID:         KeyValueRuntimeID,
				Kind:       registry.KindCompute,
				Entity:     0,
				Keymanager: 0,
				Executor: registry.ExecutorParameters{
					GroupSize:       2,
					GroupBackupSize: 1,
					RoundTimeout:    20,
					MaxMessages:     128,
				},
				TxnScheduler: registry.TxnSchedulerParameters{
					MaxBatchSize:      100,
					MaxBatchSizeBytes: 1024 * 1024,
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
				Deployments: []oasis.DeploymentCfg{
					{
						Binaries: sc.ResolveRuntimeBinaries(KeyValueRuntimeBinary),
					},
				},
			},
		},
		Validators: []oasis.ValidatorFixture{
			{Entity: 1, Consensus: oasis.ConsensusFixture{SupplementarySanityInterval: 1}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{}},
			{Entity: 1, Consensus: oasis.ConsensusFixture{}},
		},
		KeymanagerPolicies: []oasis.KeymanagerPolicyFixture{
			{Runtime: 0, Serial: 1, MasterSecretRotationInterval: 0},
		},
		Keymanagers: []oasis.KeymanagerFixture{
			{
				RuntimeProvisioner: runtimeProvisioner,
				Runtime:            0,
				Entity:             1,
				Policy:             0,
				SkipPolicy:         tee != node.TEEHardwareIntelSGX,
			},
		},
		ComputeWorkers: []oasis.ComputeWorkerFixture{
			{RuntimeProvisioner: runtimeProvisioner, Entity: 1, Runtimes: []int{1}},
			{
				RuntimeProvisioner: runtimeProvisioner,
				Entity:             1,
				Runtimes:           []int{1},
				RuntimeConfig: map[int]map[string]interface{}{
					1: {
						"core": map[string]interface{}{
							"min_gas_price": 1, // Just to test support for runtime configuration.
						},
					},
				},
			},
			{RuntimeProvisioner: runtimeProvisioner, Entity: 1, Runtimes: []int{1}},
		},
		Sentries: []oasis.SentryFixture{},
		Seeds:    []oasis.SeedFixture{{}},
		Clients: []oasis.ClientFixture{
			{RuntimeProvisioner: runtimeProvisioner, Runtimes: []int{1}},
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

func (sc *Scenario) Run(ctx context.Context, childEnv *env.Env) error {
	if err := sc.StartNetworkAndTestClient(ctx, childEnv); err != nil {
		return err
	}
	return sc.WaitTestClientAndCheckLogs()
}

// RegisterScenarios registers all end-to-end scenarios.
func RegisterScenarios() error {
	// Register non-scenario-specific parameters.
	cmd.RegisterScenarioParams(ParamsDummyScenario.Name(), ParamsDummyScenario.Parameters())

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
		ByzantineExecutorStragglerBackup,
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
		// Keymanager tests.
		KeymanagerMasterSecrets,
		KeymanagerEphemeralSecrets,
		KeymanagerDumpRestore,
		KeymanagerRestart,
		KeymanagerReplicate,
		KeymanagerReplicateMany,
		KeymanagerRotationFailure,
		KeymanagerUpgrade,
		// Dump/restore test.
		DumpRestore,
		DumpRestoreRuntimeRoundAdvance,
		// Halt test.
		HaltRestore,
		HaltRestoreSuspended,
		HaltRestoreNonMock,
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
		// RuntimeUpgrade test.
		RuntimeUpgrade,
		// HistoryReindex test.
		HistoryReindex,
		// TrustRoot test.
		TrustRoot,
		TrustRootChangeTest,
		TrustRootChangeFailsTest,
		// Archive node API test.
		ArchiveAPI,
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
