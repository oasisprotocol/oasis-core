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

	beaconTests "github.com/oasislabs/oasis-core/go/beacon/tests"
	clientTests "github.com/oasislabs/oasis-core/go/client/tests"
	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasislabs/oasis-core/go/common/entity"
	cmnGrpc "github.com/oasislabs/oasis-core/go/common/grpc"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	tendermintAPI "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	"github.com/oasislabs/oasis-core/go/consensus/tendermint/roothash"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	cmdCommon "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common"
	cmdCommonFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasislabs/oasis-core/go/oasis-node/cmd/node"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	registryTests "github.com/oasislabs/oasis-core/go/registry/tests"
	roothashTests "github.com/oasislabs/oasis-core/go/roothash/tests"
	schedulerTests "github.com/oasislabs/oasis-core/go/scheduler/tests"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	stakingTests "github.com/oasislabs/oasis-core/go/staking/tests"
	"github.com/oasislabs/oasis-core/go/storage"
	storageClient "github.com/oasislabs/oasis-core/go/storage/client"
	storageClientTests "github.com/oasislabs/oasis-core/go/storage/client/tests"
	storageTests "github.com/oasislabs/oasis-core/go/storage/tests"
	workerCommon "github.com/oasislabs/oasis-core/go/worker/common"
	computeWorker "github.com/oasislabs/oasis-core/go/worker/compute"
	computeCommittee "github.com/oasislabs/oasis-core/go/worker/compute/committee"
	computeWorkerTests "github.com/oasislabs/oasis-core/go/worker/compute/tests"
	mergeWorker "github.com/oasislabs/oasis-core/go/worker/merge"
	storageWorker "github.com/oasislabs/oasis-core/go/worker/storage"
	storageWorkerTests "github.com/oasislabs/oasis-core/go/worker/storage/tests"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler"
	txnschedulerCommittee "github.com/oasislabs/oasis-core/go/worker/txnscheduler/committee"
	txnschedulerWorkerTests "github.com/oasislabs/oasis-core/go/worker/txnscheduler/tests"
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
		{cmdCommonFlags.CfgConsensusValidator, true},
		{cmdCommonFlags.CfgDebugDontBlameOasis, true},
		{roothash.CfgIndexBlocks, true},
		{storage.CfgBackend, "badger"},
		{computeWorker.CfgWorkerEnabled, true},
		{workerCommon.CfgRuntimeBackend, "mock"},
		{workerCommon.CfgRuntimeLoader, "mock-runtime"},
		{workerCommon.CfgRuntimeBinary, "mock-runtime"},
		{workerCommon.CfgClientPort, workerClientPort},
		{storageWorker.CfgWorkerEnabled, true},
		{txnscheduler.CfgWorkerEnabled, true},
		{mergeWorker.CfgWorkerEnabled, true},
		{cmdCommon.CfgDebugAllowTestKeys, true},
	}

	testRuntime = &registry.Runtime{
		// ID: default value,
		Compute: registry.ComputeParameters{
			GroupSize:       1,
			GroupBackupSize: 0,
			RoundTimeout:    20 * time.Second,
		},
		Merge: registry.MergeParameters{
			GroupSize:       1,
			GroupBackupSize: 0,
			RoundTimeout:    20 * time.Second,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			Algorithm:         registry.TxnSchedulerAlgorithmBatching,
			GroupSize:         1,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1000,
			BatchFlushTimeout: 20 * time.Second,
		},
		Storage: registry.StorageParameters{GroupSize: 1},
	}

	testNamespace common.Namespace
	testRuntimeID signature.PublicKey

	initConfigOnce sync.Once
)

type testNode struct {
	*node.Node

	runtimeID                 signature.PublicKey
	computeCommitteeNode      *computeCommittee.Node
	txnschedulerCommitteeNode *txnschedulerCommittee.Node

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

	signerFactory := fileSigner.NewFactory(dataDir, signature.SignerEntity)
	entity, entitySigner, err := entity.Generate(dataDir, signerFactory, nil)
	require.NoError(err, "create test entity")

	viper.Set("datadir", dataDir)
	viper.Set("log.file", filepath.Join(dataDir, "test-node.log"))
	viper.Set("worker.runtime.id", testRuntimeID.String())
	viper.Set("client.indexer.runtimes", []string{testRuntimeID.String()})
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

		{"ComputeWorker", testComputeWorker},
		{"TransactionSchedulerWorker", testTransactionSchedulerWorker},

		// StorageWorker test case
		{"StorageWorker", testStorageWorker},

		// Client tests also need a functional runtime.
		{"Client", testClient},

		// Staking requires a registered node that is a validator.
		{"Staking", testStaking},
		{"StakingClient", testStakingClient},

		// TestStorageClientWithNode runs storage tests against a storage client
		// connected to this node.
		{"TestStorageClientWithNode", testStorageClientWithNode},

		// Clean up and ensure the registry is empty for the following tests.
		{"DeregisterTestEntityRuntime", testDeregisterEntityRuntime},

		{"EpochTime", testEpochTime},
		{"Beacon", testBeacon},
		{"Storage", testStorage},
		{"Registry", testRegistry},
		{"Scheduler", testScheduler},
		{"Scheduler/GetValidators", testSchedulerGetValidators},
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
	require.NoError(err, "register test entity")

	// Register the test runtime.
	signedRt, err := registry.SignRuntime(node.entitySigner, registry.RegisterRuntimeSignatureContext, testRuntime)
	require.NoError(err, "sign runtime descriptor")
	tx = registry.NewRegisterRuntimeTx(0, nil, signedRt)
	err = consensusAPI.SignAndSubmitTx(context.Background(), node.Consensus, node.entitySigner, tx)
	require.NoError(err, "register test entity")

	// Get the runtime and the corresponding compute committee node instance.
	computeRT := node.ComputeWorker.GetRuntime(testRuntime.ID)
	require.NotNil(t, computeRT)
	node.computeCommitteeNode = computeRT.GetNode()

	// Get the runtime and the corresponding transaction scheduler committee node instance.
	require.Equal(node.TransactionSchedulerWorker.GetConfig().Runtimes[0].ID, testRuntime.ID)
	txnschedulerRT := node.TransactionSchedulerWorker.GetRuntime(testRuntime.ID)
	require.NotNil(t, txnschedulerRT)
	node.txnschedulerCommitteeNode = txnschedulerRT.GetNode()
}

func testDeregisterEntityRuntime(t *testing.T, node *testNode) {
	// Stop the registration service and wait for it to fully stop. This is required
	// as otherwise it will re-register the node on each epoch transition.
	node.RegistrationWorker.Stop()
	<-node.RegistrationWorker.Quit()

	// Subscribe to node deregistration event.
	nodeCh, sub, err := node.Node.Registry.WatchNodes(context.Background())
	require.NoError(t, err, "WatchNodes")
	defer sub.Close()

	// Perform an epoch transition to expire the node as otherwise there is no way
	// to deregister the entity.
	require.Implements(t, (*epochtime.SetableBackend)(nil), node.Epochtime, "epoch time backend is mock")
	timeSource := (node.Epochtime).(epochtime.SetableBackend)
	_ = epochtimeTests.MustAdvanceEpoch(t, timeSource, 2+1+1) // 2 epochs for expiry, 1 for debonding, 1 for removal.

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
	entityCh, sub, err := node.Node.Registry.WatchEntities(context.Background())
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

	registryTests.EnsureRegistryEmpty(t, node.Node.Registry)
}

func testEpochTime(t *testing.T, node *testNode) {
	epochtimeTests.EpochtimeSetableImplementationTest(t, node.Epochtime)
}

func testBeacon(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	beaconTests.BeaconImplementationTests(t, node.Beacon, timeSource)
}

func testStorage(t *testing.T, node *testNode) {
	// Determine the current round. This is required so that we can commit into
	// storage at the next (non-finalized) round.
	blk, err := node.RootHash.GetLatestBlock(context.Background(), testRuntimeID, consensusAPI.HeightLatest)
	require.NoError(t, err, "GetLatestBlock")

	storageTests.StorageImplementationTests(t, node.Storage, testNamespace, blk.Header.Round+1)
}

func testRegistry(t *testing.T, node *testNode) {
	registryTests.RegistryImplementationTests(t, node.Registry, node.Consensus)
}

func testScheduler(t *testing.T, node *testNode) {
	schedulerTests.SchedulerImplementationTests(t, node.Scheduler, node.Consensus)
}

func testSchedulerGetValidators(t *testing.T, node *testNode) {
	// Since the integration tests run with validator elections disabled,
	// just ensure that the GetValidators query returns the node's identity.
	validators, err := node.Scheduler.GetValidators(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetValidators")

	require.Len(t, validators, 1, "should be only one static validator")
	require.Equal(t, node.Identity.ConsensusSigner.Public(), validators[0].ID)
	require.EqualValues(t, tendermintAPI.VotingPower, validators[0].VotingPower)
}

func testStaking(t *testing.T, node *testNode) {
	stakingTests.StakingImplementationTests(t, node.Staking, node.Consensus, node.Identity, node.entity, node.entitySigner, testRuntimeID)
}

func testStakingClient(t *testing.T, node *testNode) {
	// Create a client backend connected to the local node's internal socket.
	conn, err := cmnGrpc.Dial("unix:"+filepath.Join(node.dataDir, "internal.sock"), grpc.WithInsecure())
	require.NoError(t, err, "Dial")

	client := staking.NewStakingClient(conn)
	stakingTests.StakingClientImplementationTests(t, client, node.Consensus)
}

func testRootHash(t *testing.T, node *testNode) {
	roothashTests.RootHashImplementationTests(t, node.RootHash, node.Consensus, node.Storage)
}

func testComputeWorker(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	require.NotNil(t, node.computeCommitteeNode)
	computeWorkerTests.WorkerImplementationTests(t, node.ComputeWorker, node.runtimeID, node.computeCommitteeNode, timeSource)
}

func testStorageWorker(t *testing.T, node *testNode) {
	storageWorkerTests.WorkerImplementationTests(t, node.StorageWorker)
}

func testTransactionSchedulerWorker(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	require.NotNil(t, node.txnschedulerCommitteeNode)
	txnschedulerWorkerTests.WorkerImplementationTests(t, node.TransactionSchedulerWorker, node.runtimeID, node.txnschedulerCommitteeNode, timeSource, node.RootHash, node.Storage)
}

func testClient(t *testing.T, node *testNode) {
	clientTests.ClientImplementationTests(t, node.RuntimeClient, node.runtimeID)
}

func testStorageClientWithNode(t *testing.T, node *testNode) {
	ctx := context.Background()

	// Client storage implementation tests.
	config := []struct {
		key   string
		value interface{}
	}{
		{storageClient.CfgDebugClientAddress, "localhost:" + workerClientPort},
		{storageClient.CfgDebugClientCert, node.dataDir + "/tls_identity_cert.pem"},
	}
	for _, kv := range config {
		viper.Set(kv.key, kv.value)
	}
	debugClient, err := storageClient.New(ctx, node.Identity, nil, nil)
	require.NoError(t, err, "NewDebugStorageClient")

	// Determine the current round. This is required so that we can commit into
	// storage at the next (non-finalized) round.
	blk, err := node.RootHash.GetLatestBlock(ctx, testRuntimeID, consensusAPI.HeightLatest)
	require.NoError(t, err, "GetLatestBlock")

	storageTests.StorageImplementationTests(t, debugClient, testNamespace, blk.Header.Round+1)

	// Reset configuration flags.
	for _, kv := range config {
		viper.Set(kv.key, "")
	}
}

func testStorageClientWithoutNode(t *testing.T, node *testNode) {
	// Storage client tests without node.
	storageClientTests.ClientWorkerTests(t, node.Identity, node.Consensus)
}

func init() {
	var ns hash.Hash
	ns.FromBytes([]byte("oasis node test namespace"))
	copy(testNamespace[:], ns[:])

	var err error
	testRuntimeID, err = testNamespace.ToRuntimeID()
	if err != nil {
		panic("Unable to convert namespace to runtime ID")
	}
	testRuntime.ID = testRuntimeID

	testRuntime.Genesis.StateRoot.Empty()
}
