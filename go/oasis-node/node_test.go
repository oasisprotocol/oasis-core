package main

import (
	"context"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tendermintCommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	tendermintFull "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/full"
	tmTestGenesis "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/tests/genesis"
	consensusTests "github.com/oasisprotocol/oasis-core/go/consensus/tests"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	governanceTests "github.com/oasisprotocol/oasis-core/go/governance/tests"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdCommonFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	registryTests "github.com/oasisprotocol/oasis-core/go/registry/tests"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	roothashTests "github.com/oasisprotocol/oasis-core/go/roothash/tests"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	clientTests "github.com/oasisprotocol/oasis-core/go/runtime/client/tests"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	schedulerTests "github.com/oasisprotocol/oasis-core/go/scheduler/tests"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
	storageTests "github.com/oasisprotocol/oasis-core/go/storage/tests"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	commonCommittee "github.com/oasisprotocol/oasis-core/go/worker/common/committee"
	executorCommittee "github.com/oasisprotocol/oasis-core/go/worker/compute/executor/committee"
	executorWorkerTests "github.com/oasisprotocol/oasis-core/go/worker/compute/executor/tests"
	storageWorker "github.com/oasisprotocol/oasis-core/go/worker/storage"
	storageWorkerTests "github.com/oasisprotocol/oasis-core/go/worker/storage/tests"
)

const (
	workerClientPort = "9010"
)

var (
	// NOTE: Configuration option that can't be set statically will be
	// configured directly in newTestNode().
	testNodeStaticConfig = []struct {
		key   string
		value interface{}
	}{
		{"log.level.default", "DEBUG"},
		{"log.format", "JSON"},
		{cmdCommonFlags.CfgConsensusValidator, true},
		{cmdCommonFlags.CfgDebugDontBlameOasis, true},
		{cmdCommonFlags.CfgDebugAllowRoot, true},
		{storageWorker.CfgBackend, "badger"},
		{runtimeRegistry.CfgRuntimeMode, string(runtimeRegistry.RuntimeModeCompute)},
		{runtimeRegistry.CfgRuntimeProvisioner, runtimeRegistry.RuntimeProvisionerMock},
		{workerCommon.CfgClientPort, workerClientPort},
		{storageWorker.CfgWorkerPublicRPCEnabled, true},
		{tendermintCommon.CfgCoreListenAddress, "tcp://0.0.0.0:27565"},
		{tendermintFull.CfgSupplementarySanityEnabled, true},
		{tendermintFull.CfgSupplementarySanityInterval, 1},
		{cmdCommon.CfgDebugAllowTestKeys, true},
	}

	testRuntime = &registry.Runtime{
		Versioned: cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		// ID: default value,
		// EntityID: test entity,
		Kind: registry.KindCompute,
		Executor: registry.ExecutorParameters{
			GroupSize:       1,
			GroupBackupSize: 0,
			RoundTimeout:    20,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			BatchFlushTimeout: 20 * time.Second,
			ProposerTimeout:   20,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
		},
		Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
			scheduler.KindComputeExecutor: {
				scheduler.RoleWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 1,
					},
				},
			},
		},
		GovernanceModel: registry.GovernanceEntity,
		Deployments:     []*registry.VersionInfo{{}},
	}

	testRuntimeID common.Namespace

	initConfigOnce sync.Once
)

type testNode struct {
	*node.Node

	runtimeID common.Namespace

	commonCommitteeNode   *commonCommittee.Node
	executorCommitteeNode *executorCommittee.Node

	entity       *entity.Entity
	entitySigner signature.Signer

	dataDir string
	start   time.Time
}

func (n *testNode) Stop() {
	const waitTime = 1 * time.Second

	// HACK: The gRPC server will cause a segfault if it is torn down
	// while it is still in the process of being initialized.  There is
	// currently no way to wait for it to launch either.
	if elapsed := time.Since(n.start); elapsed < waitTime {
		time.Sleep(waitTime - elapsed)
	}

	n.Node.Stop()
	n.Node.Wait()
	n.Node.Cleanup()
}

func newTestNode(t *testing.T) *testNode {
	initConfigOnce.Do(func() {
		cmdCommon.InitConfig()
	})

	require := require.New(t)

	dataDir, err := ioutil.TempDir("", "oasis-node-test_")
	require.NoError(err, "create data dir")

	signerFactory, err := fileSigner.NewFactory(dataDir, signature.SignerEntity)
	require.NoError(err, "create file signer")
	entity, entitySigner, err := entity.Generate(dataDir, signerFactory, nil)
	require.NoError(err, "create test entity")

	viper.Set("datadir", dataDir)
	viper.Set("log.file", filepath.Join(dataDir, "test-node.log"))
	viper.Set(runtimeRegistry.CfgDebugMockIDs, []string{
		testRuntimeID.String(),
	})
	viper.Set("worker.registration.entity", filepath.Join(dataDir, "entity.json"))
	for _, kv := range testNodeStaticConfig {
		viper.Set(kv.key, kv.value)
	}

	// Generate the test node identity.
	nodeSignerFactory, err := fileSigner.NewFactory(dataDir, identity.RequiredSignerRoles...)
	require.NoError(err, "create node file signer")
	identity, err := identity.LoadOrGenerate(dataDir, nodeSignerFactory, false)
	require.NoError(err, "create test node identity")
	// Include node in entity.
	entity.Nodes = append(entity.Nodes, identity.NodeSigner.Public())

	// Generate genesis and save it to file.
	genesisPath := filepath.Join(dataDir, "genesis.json")
	genesis, err := tmTestGenesis.NewTestNodeGenesisProvider(identity, entity, entitySigner)
	require.NoError(err, "test genesis provision")
	doc, err := genesis.GetGenesisDocument()
	require.NoError(err, "test entity genesis document")
	require.NoError(doc.WriteFileJSON(genesisPath))
	viper.Set(cmdCommonFlags.CfgGenesisFile, genesisPath)

	n := &testNode{
		runtimeID:    testRuntime.ID,
		dataDir:      dataDir,
		entity:       entity,
		entitySigner: entitySigner,
		start:        time.Now(),
	}
	t.Logf("starting node, data directory: %v", dataDir)
	n.Node, err = node.NewNode()
	require.NoError(err, "start node")

	// Add the testNode to the newly generated entity's list of nodes
	// that can self-certify.
	n.entity.Nodes = []signature.PublicKey{
		n.Node.Identity.NodeSigner.Public(),
	}

	return n
}

type testCase struct {
	name string
	fn   func(*testing.T, *testNode)
}

func (tc *testCase) Run(t *testing.T, node *testNode) {
	t.Run(tc.name, func(t *testing.T) {
		tc.fn(t, node)
	})
}

func TestNode(t *testing.T) {
	node := newTestNode(t)
	defer func() {
		node.Stop()
		switch t.Failed() {
		case true:
			t.Logf("one or more tests failed, preserving data directory: %v", node.dataDir)
		case false:
			os.RemoveAll(node.dataDir)
		}
	}()

	// Wait for consensus to become ready before proceeding.
	select {
	case <-node.Consensus.Synced():
	case <-time.After(5 * time.Second):
		t.Fatalf("failed to wait for consensus to become ready")
	}

	// NOTE: Order of test cases is important.
	testCases := []*testCase{
		// Register the test entity and runtime used by every single test,
		// including the worker tests.
		{"RegisterTestEntityRuntime", testRegisterEntityRuntime},

		{"ExecutorWorker", testExecutorWorker},

		// StorageWorker test case
		{"StorageWorker", testStorageWorker},

		// Runtime client tests also need a functional runtime.
		{"RuntimeClient", testRuntimeClient},

		// Governance requires a registered node that is a validator that was not slashed.
		{"Governance", testGovernance},

		// Staking requires a registered node that is a validator.
		{"Staking", testStaking},
		{"StakingClient", testStakingClient},

		{"Consensus", testConsensus},
		{"ConsensusClient", testConsensusClient},

		{"Beacon", testBeacon},
		{"Storage", testStorage},
		{"Registry", testRegistry},
		{"Scheduler", testScheduler},
		{"SchedulerClient", testSchedulerClient},
		{"RootHash", testRootHash},
	}

	for _, tc := range testCases {
		tc.Run(t, node)
	}
}

func testRegisterEntityRuntime(t *testing.T, node *testNode) {
	require := require.New(t)

	// Register node entity.
	signedEnt, err := entity.SignEntity(node.entitySigner, registry.RegisterEntitySignatureContext, node.entity)
	require.NoError(err, "sign node entity")
	tx := registry.NewRegisterEntityTx(0, nil, signedEnt)
	err = consensusAPI.SignAndSubmitTx(context.Background(), node.Consensus, node.entitySigner, tx)
	require.NoError(err, "register node entity")

	// Register the test entity.
	testEntity, testEntitySigner, _ := entity.TestEntity()
	signedEnt, err = entity.SignEntity(testEntitySigner, registry.RegisterEntitySignatureContext, testEntity)
	require.NoError(err, "sign test entity")
	tx = registry.NewRegisterEntityTx(0, nil, signedEnt)
	err = consensusAPI.SignAndSubmitTx(context.Background(), node.Consensus, testEntitySigner, tx)
	require.NoError(err, "register test entity")

	// Register the test runtime.
	tx = registry.NewRegisterRuntimeTx(0, nil, testRuntime)
	err = consensusAPI.SignAndSubmitTx(context.Background(), node.Consensus, testEntitySigner, tx)
	require.NoError(err, "register test entity")

	// Get the runtime and the corresponding committee node instances.
	node.executorCommitteeNode = node.ExecutorWorker.GetRuntime(testRuntime.ID)
	node.commonCommitteeNode = node.CommonWorker.GetRuntime(testRuntime.ID)
	require.NotNil(t, node.executorCommitteeNode)
	require.NotNil(t, node.commonCommitteeNode)
}

func testConsensus(t *testing.T, node *testNode) {
	consensusTests.ConsensusImplementationTests(t, node.Consensus)
}

func testConsensusClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "Dial")

	client := consensusAPI.NewConsensusClient(conn)
	consensusTests.ConsensusImplementationTests(t, client)
}

func testBeacon(t *testing.T, node *testNode) {
	beaconTests.EpochtimeSetableImplementationTest(t, node.Consensus.Beacon())

	timeSource := (node.Consensus.Beacon()).(beacon.SetableBackend)
	beaconTests.BeaconImplementationTests(t, timeSource)
}

func testStorage(t *testing.T, node *testNode) {
	dataDir, err := ioutil.TempDir("", "oasis-storage-test_")
	require.NoError(t, err, "TempDir")
	defer os.RemoveAll(dataDir)

	backend, err := storageWorker.NewLocalBackend(dataDir, testRuntimeID, node.Identity)
	require.NoError(t, err, "storage.New")
	defer backend.Cleanup()

	storageTests.StorageImplementationTests(t, backend, backend, testRuntimeID, 0)
}

func testRegistry(t *testing.T, node *testNode) {
	registryTests.RegistryImplementationTests(t, node.Consensus.Registry(), node.Consensus, node.entity.ID)
}

func testScheduler(t *testing.T, node *testNode) {
	schedulerTests.SchedulerImplementationTests(t, "", node.Identity, node.Consensus.Scheduler(), node.Consensus)
}

func testSchedulerClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "Dial")
	defer conn.Close()

	client := scheduler.NewSchedulerClient(conn)
	schedulerTests.SchedulerImplementationTests(t, "client", node.Identity, client, node.Consensus)
}

func testStaking(t *testing.T, node *testNode) {
	stakingTests.StakingImplementationTests(t, node.Consensus.Staking(), node.Consensus, node.Identity, node.entity, node.entitySigner, testRuntimeID)
}

func testStakingClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err, "Dial")
	defer conn.Close()

	client := staking.NewStakingClient(conn)
	stakingTests.StakingClientImplementationTests(t, client, node.Consensus)
}

func testRootHash(t *testing.T, node *testNode) {
	// Directly.
	t.Run("Direct", func(t *testing.T) {
		roothashTests.RootHashImplementationTests(t, node.Consensus.RootHash(), node.Consensus, node.Identity)
	})

	// Over gRPC.
	t.Run("OverGrpc", func(t *testing.T) {
		// Create a client backend connected to the local node's internal socket.
		conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err, "Dial")
		defer conn.Close()

		client := roothash.NewRootHashClient(conn)
		roothashTests.RootHashImplementationTests(t, client, node.Consensus, node.Identity)
	})
}

func testGovernance(t *testing.T, node *testNode) {
	// Directly.
	t.Run("Direct", func(t *testing.T) {
		governanceTests.GovernanceImplementationTests(t, node.Consensus.Governance(), node.Consensus, node.entity, node.entitySigner)
	})

	// Over gRPC.
	t.Run("OverGrpc", func(t *testing.T) {
		// Create a client backend connected to the local node's internal socket.
		conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err, "Dial")
		defer conn.Close()

		client := governance.NewGovernanceClient(conn)
		governanceTests.GovernanceImplementationTests(t, client, node.Consensus, node.entity, node.entitySigner)
	})
}

func testExecutorWorker(t *testing.T, node *testNode) {
	timeSource := (node.Consensus.Beacon()).(beacon.SetableBackend)

	rt, err := node.RuntimeRegistry.GetRuntime(node.runtimeID)
	require.NoError(t, err, "runtimeRegistry.GetRuntime")

	require.NotNil(t, node.executorCommitteeNode)
	executorWorkerTests.WorkerImplementationTests(
		t,
		node.ExecutorWorker,
		node.runtimeID,
		node.commonCommitteeNode,
		node.executorCommitteeNode,
		timeSource,
		node.Consensus.RootHash(),
		rt.Storage(),
	)
}

func testStorageWorker(t *testing.T, node *testNode) {
	storageWorkerTests.WorkerImplementationTests(t, node.StorageWorker)
}

func testRuntimeClient(t *testing.T, node *testNode) {
	// Over gRPC.
	t.Run("OverGrpc", func(t *testing.T) {
		// Create a client backend connected to the local node's internal socket.
		conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"),
			grpc.WithTransportCredentials(insecure.NewCredentials()))
		require.NoError(t, err, "Dial")
		defer conn.Close()

		cli := runtimeClient.NewRuntimeClient(conn)
		clientTests.ClientImplementationTests(t, cli, node.runtimeID)
	})
}

func init() {
	testEntity, _, _ := entity.TestEntity()

	testRuntimeID = common.NewTestNamespaceFromSeed([]byte("oasis node test namespace"), 0)
	testRuntime.ID = testRuntimeID
	testRuntime.EntityID = testEntity.ID

	testRuntime.Genesis.StateRoot.Empty()
}
