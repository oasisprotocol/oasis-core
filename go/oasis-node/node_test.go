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

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	cmnGrpc "github.com/oasisprotocol/oasis-core/go/common/grpc"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	tendermintCommon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/common"
	tendermintFull "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/full"
	consensusTests "github.com/oasisprotocol/oasis-core/go/consensus/tests"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	governanceTests "github.com/oasisprotocol/oasis-core/go/governance/tests"
	cmdCommon "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	cmdCommonFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/node"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	registryTests "github.com/oasisprotocol/oasis-core/go/registry/tests"
	roothashTests "github.com/oasisprotocol/oasis-core/go/roothash/tests"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	clientTests "github.com/oasisprotocol/oasis-core/go/runtime/client/tests"
	runtimeRegistry "github.com/oasisprotocol/oasis-core/go/runtime/registry"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	schedulerTests "github.com/oasisprotocol/oasis-core/go/scheduler/tests"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	storageClient "github.com/oasisprotocol/oasis-core/go/storage/client"
	storageClientTests "github.com/oasisprotocol/oasis-core/go/storage/client/tests"
	storageTests "github.com/oasisprotocol/oasis-core/go/storage/tests"
	workerCommon "github.com/oasisprotocol/oasis-core/go/worker/common"
	"github.com/oasisprotocol/oasis-core/go/worker/compute"
	"github.com/oasisprotocol/oasis-core/go/worker/compute/executor"
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
		{storageWorker.CfgBackend, "badger"},
		{compute.CfgWorkerEnabled, true},
		{runtimeRegistry.CfgRuntimeProvisioner, runtimeRegistry.RuntimeProvisionerMock},
		{workerCommon.CfgClientPort, workerClientPort},
		{storageWorker.CfgWorkerEnabled, true},
		{executor.CfgScheduleCheckTxEnabled, false},
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
			MinPoolSize:     1,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			Algorithm:         registry.TxnSchedulerSimple,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			BatchFlushTimeout: 20 * time.Second,
			ProposerTimeout:   20,
		},
		Storage: registry.StorageParameters{
			GroupSize:               1,
			MinWriteReplication:     1,
			MaxApplyWriteLogEntries: 100_000,
			MaxApplyOps:             2,
			MinPoolSize:             1,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
		},
		GovernanceModel: registry.GovernanceEntity,
	}

	testRuntimeID common.Namespace

	initConfigOnce sync.Once
)

type testNode struct {
	*node.Node

	runtimeID             common.Namespace
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
	viper.Set(runtimeRegistry.CfgSupported, testRuntimeID.String())
	viper.Set(runtimeRegistry.CfgTagIndexerBackend, "bleve")
	viper.Set(runtimeRegistry.CfgRuntimePaths, map[string]string{
		testRuntimeID.String(): "mock-runtime",
	})
	viper.Set("worker.registration.entity", filepath.Join(dataDir, "entity.json"))
	for _, kv := range testNodeStaticConfig {
		viper.Set(kv.key, kv.value)
	}

	n := &testNode{
		runtimeID:    testRuntime.ID,
		dataDir:      dataDir,
		entity:       entity,
		entitySigner: entitySigner,
		start:        time.Now(),
	}
	t.Logf("starting node, data directory: %v", dataDir)
	n.Node, err = node.NewTestNode()
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

		// Governance requires a registered node that is a validator and was
		// not slashed.
		{"Governance", testGovernance},

		// Staking requires a registered node that is a validator.
		{"Staking", testStaking},
		{"StakingClient", testStakingClient},

		// TestStorageClientWithNode runs storage tests against a storage client
		// connected to this node.
		{"TestStorageClientWithNode", testStorageClientWithNode},

		// Clean up and ensure the registry is empty for the following tests.
		{"DeregisterTestEntityRuntime", testDeregisterEntityRuntime},

		{"Consensus", testConsensus},
		{"ConsensusClient", testConsensusClient},
		{"Beacon", testBeacon},
		{"Storage", testStorage},
		{"Registry", testRegistry},
		{"Scheduler", testScheduler},
		{"SchedulerClient", testSchedulerClient},
		{"RootHash", testRootHash},

		// TestStorageClientWithoutNode runs client tests that use a mock storage
		// node and mock committees.
		{"TestStorageClientWithoutNode", testStorageClientWithoutNode},
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

	// Get the runtime and the corresponding executor committee node instance.
	executorRT := node.ExecutorWorker.GetRuntime(testRuntime.ID)
	require.NotNil(t, executorRT)
	node.executorCommitteeNode = executorRT
}

func testDeregisterEntityRuntime(t *testing.T, node *testNode) {
	// Stop the registration service and wait for it to fully stop. This is required
	// as otherwise it will re-register the node on each epoch transition.
	node.RegistrationWorker.Stop()
	<-node.RegistrationWorker.Quit()

	// Subscribe to node deregistration event.
	nodeCh, sub, err := node.Node.Consensus.Registry().WatchNodes(context.Background())
	require.NoError(t, err, "WatchNodes")
	defer sub.Close()

	// Perform an epoch transition to expire the node as otherwise there is no way
	// to deregister the entity.
	require.Implements(t, (*beacon.SetableBackend)(nil), node.Consensus.Beacon(), "epoch time backend is mock")
	timeSource := (node.Consensus.Beacon()).(beacon.SetableBackend)
	_ = beaconTests.MustAdvanceEpoch(t, timeSource, 2+1+1) // 2 epochs for expiry, 1 for debonding, 1 for removal.

WaitLoop:
	for {
		select {
		case ev := <-nodeCh:
			// NOTE: There can be in-flight registrations from before the registration worker
			//       was stopped. Make sure to skip them.
			if ev.IsRegistration {
				continue
			}

			require.Equal(t, ev.Node.ID, node.Identity.NodeSigner.Public(), "expected node deregistration event")
			break WaitLoop
		case <-time.After(1 * time.Second):
			t.Fatalf("Failed to receive node deregistration event")
		}
	}

	// Subscribe to entity deregistration event.
	entityCh, sub, err := node.Node.Consensus.Registry().WatchEntities(context.Background())
	require.NoError(t, err, "WatchEntities")
	defer sub.Close()

	tx := registry.NewDeregisterEntityTx(0, nil)
	err = consensusAPI.SignAndSubmitTx(context.Background(), node.Consensus, node.entitySigner, tx)
	require.NoError(t, err, "deregister test entity")

	select {
	case ev := <-entityCh:
		require.False(t, ev.IsRegistration, "expected entity deregistration event")
	case <-time.After(1 * time.Second):
		t.Fatalf("Failed to receive entity deregistration event")
	}

	// Deregistering the test entity should fail as it has runtimes.
	_, testEntitySigner, _ := entity.TestEntity()
	tx = registry.NewDeregisterEntityTx(0, nil)
	err = consensusAPI.SignAndSubmitTx(context.Background(), node.Consensus, testEntitySigner, tx)
	require.Error(t, err, "deregister should fail when an entity has runtimes")
	require.Equal(t, err, registry.ErrEntityHasRuntimes)

	registryTests.EnsureRegistryEmpty(t, node.Node.Consensus.Registry())
}

func testConsensus(t *testing.T, node *testNode) {
	consensusTests.ConsensusImplementationTests(t, node.Consensus)
}

func testConsensusClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"), grpc.WithInsecure())
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
	// We are always testing a local storage backend here.
	localBackend := backend.(storageAPI.LocalBackend)

	storageTests.StorageImplementationTests(t, localBackend, backend, testRuntimeID, 0)
}

func testRegistry(t *testing.T, node *testNode) {
	registryTests.RegistryImplementationTests(t, node.Consensus.Registry(), node.Consensus)
}

func testScheduler(t *testing.T, node *testNode) {
	schedulerTests.SchedulerImplementationTests(t, "", node.Consensus.Scheduler(), node.Consensus)
}

func testSchedulerClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"), grpc.WithInsecure())
	require.NoError(t, err, "Dial")
	defer conn.Close()

	client := scheduler.NewSchedulerClient(conn)
	schedulerTests.SchedulerImplementationTests(t, "client", client, node.Consensus)
}

func testStaking(t *testing.T, node *testNode) {
	stakingTests.StakingImplementationTests(t, node.Consensus.Staking(), node.Consensus, node.Identity, node.entity, node.entitySigner, testRuntimeID)
}

func testStakingClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"), grpc.WithInsecure())
	require.NoError(t, err, "Dial")
	defer conn.Close()

	client := staking.NewStakingClient(conn)
	stakingTests.StakingClientImplementationTests(t, client, node.Consensus)
}

func testRootHash(t *testing.T, node *testNode) {
	roothashTests.RootHashImplementationTests(t, node.Consensus.RootHash(), node.Consensus, node.Identity)
}

func testGovernance(t *testing.T, node *testNode) {
	// Directly.
	t.Run("Direct", func(t *testing.T) {
		governanceTests.GovernanceImplementationTests(t, node.Consensus.Governance(), node.Consensus, node.entity, node.entitySigner)
	})

	// Over gRPC.
	t.Run("OverGrpc", func(t *testing.T) {
		// Create a client backend connected to the local node's internal socket.
		conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"), grpc.WithInsecure())
		require.NoError(t, err, "Dial")
		defer conn.Close()

		client := governance.NewGovernanceClient(conn)
		governanceTests.GovernanceImplementationTests(t, client, node.Consensus, node.entity, node.entitySigner)
	})
}

func testExecutorWorker(t *testing.T, node *testNode) {
	timeSource := (node.Consensus.Beacon()).(beacon.SetableBackend)

	require.NotNil(t, node.executorCommitteeNode)
	executorWorkerTests.WorkerImplementationTests(
		t,
		node.ExecutorWorker,
		node.runtimeID,
		node.executorCommitteeNode,
		timeSource,
		node.Consensus.RootHash(),
		node.RuntimeRegistry.StorageRouter(),
	)
}

func testStorageWorker(t *testing.T, node *testNode) {
	storageWorkerTests.WorkerImplementationTests(t, node.StorageWorker)
}

func testRuntimeClient(t *testing.T, node *testNode) {
	// Directly.
	t.Run("Direct", func(t *testing.T) {
		clientTests.ClientImplementationTests(t, node.RuntimeClient, node.runtimeID)
	})

	// Over gRPC.
	t.Run("OverGrpc", func(t *testing.T) {
		// Create a client backend connected to the local node's internal socket.
		conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"), grpc.WithInsecure())
		require.NoError(t, err, "Dial")
		defer conn.Close()

		cli := runtimeClient.NewRuntimeClient(conn)
		clientTests.ClientImplementationTests(t, cli, node.runtimeID)
	})
}

func testStorageClientWithNode(t *testing.T, node *testNode) {
	ctx := context.Background()

	// Get the local storage backend (the one that the client is connecting to).
	rt, err := node.RuntimeRegistry.GetRuntime(testRuntimeID)
	require.NoError(t, err, "GetRuntime")
	localBackend := rt.Storage().(storageAPI.LocalBackend)

	client, err := storageClient.NewStatic(ctx, node.Identity, node.Consensus.Registry(), node.Identity.NodeSigner.Public())
	require.NoError(t, err, "NewStatic")

	// Determine the current round. This is required so that we can commit into
	// storage at the next (non-finalized) round.
	blk, err := node.Consensus.RootHash().GetLatestBlock(ctx, testRuntimeID, consensusAPI.HeightLatest)
	require.NoError(t, err, "GetLatestBlock")

	storageTests.StorageImplementationTests(t, localBackend, client, testRuntimeID, blk.Header.Round+1)
}

func testStorageClientWithoutNode(t *testing.T, node *testNode) {
	// Storage client tests without node.
	storageClientTests.ClientWorkerTests(t, node.Identity, node.Consensus)
}

func init() {
	testEntity, _, _ := entity.TestEntity()

	testRuntimeID = common.NewTestNamespaceFromSeed([]byte("oasis node test namespace"), 0)
	testRuntime.ID = testRuntimeID
	testRuntime.EntityID = testEntity.ID

	testRuntime.Genesis.StateRoot.Empty()
}
