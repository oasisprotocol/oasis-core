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

	beaconTests "github.com/oasislabs/ekiden/go/beacon/tests"
	clientTests "github.com/oasislabs/ekiden/go/client/tests"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/entity"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	roothashTests "github.com/oasislabs/ekiden/go/roothash/tests"
	schedulerTests "github.com/oasislabs/ekiden/go/scheduler/tests"
	stakingTests "github.com/oasislabs/ekiden/go/staking/tests"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	storageTests "github.com/oasislabs/ekiden/go/storage/tests"
	"github.com/oasislabs/ekiden/go/worker/committee"
	workerTests "github.com/oasislabs/ekiden/go/worker/tests"
)

const testRuntimeID = "0000000000000000000000000000000000000000000000000000000000000000"

var (
	testNodeConfig = []struct {
		key   string
		value interface{}
	}{
		{"log.level.default", "DEBUG"},
		{"epochtime.backend", "tendermint_mock"},
		{"beacon.backend", "tendermint"},
		{"registry.backend", "tendermint"},
		{"roothash.backend", "tendermint"},
		{"scheduler.backend", "trivial"},
		{"storage.backend", "leveldb"},
		{"storage.debug.mock_signing_key", true},
		{"staking.backend", "tendermint"},
		{"staking.debug.genesis_state", stakingTests.InitialBalancesArg},
		{"tendermint.consensus.skip_timeout_commit", true},
		{"tendermint.debug.block_time_iota", 1 * time.Millisecond},
		{"worker.backend", "mock"},
		{"worker.runtime.binary", "mock-runtime"},
		{"worker.runtime.id", testRuntimeID},
	}

	testRuntime = &registry.Runtime{
		// ID: default value,
		ReplicaGroupSize: 1,
		StorageGroupSize: 1,
	}

	initConfigOnce sync.Once
)

type testNode struct {
	*node.Node

	runtimeID     signature.PublicKey
	committeeNode *committee.Node

	entity        *entity.Entity
	entityPrivKey *signature.PrivateKey

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

	dataDir, err := ioutil.TempDir("", "ekiden-node-test_")
	require.NoError(err, "create data dir")

	entity, entityPriv, err := entity.LoadOrGenerate(dataDir)
	require.NoError(err, "create test entity")

	viper.Set("datadir", dataDir)
	viper.Set("log.file", filepath.Join(dataDir, "test-node.log"))
	for _, kv := range testNodeConfig {
		viper.Set(kv.key, kv.value)
	}

	n := &testNode{
		dataDir:       dataDir,
		entity:        entity,
		entityPrivKey: entityPriv,
		start:         time.Now(),
	}
	t.Logf("starting node, data directory: %v", dataDir)
	n.Node, err = node.NewNode()
	require.NoError(err, "start node")

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

	// NOTE: Order of test cases is important.
	testCases := []*testCase{
		// Register the test entity and runtime used by every single test,
		// including the worker tests.
		{"RegisterTestEntityRuntime", testRegisterEntityRuntime},

		// Worker test case must run second as starting the worker will
		// register the node.
		{"Worker", testWorker},

		// Client tests also need a functional runtime.
		{"Client", testClient},

		// Clean up and ensure the registry is empty for the following tests.
		{"DeregisterTestEntityRuntime", testDeregisterEntityRuntime},

		{"EpochTime", testEpochTime},
		{"Beacon", testBeacon},
		{"Storage", testStorage},
		{"Registry", testRegistry},
		{"Scheduler", testScheduler},
		{"Staking", testStaking},
		{"RootHash", testRootHash},
	}

	for _, tc := range testCases {
		tc.Run(t, node)
	}
}

func testRegisterEntityRuntime(t *testing.T, node *testNode) {
	require := require.New(t)

	// Register node entity.
	node.entity.RegistrationTime = uint64(time.Now().Unix())
	signedEnt, err := entity.SignEntity(*node.entityPrivKey, registry.RegisterEntitySignatureContext, node.entity)
	require.NoError(err, "sign node entity")
	err = node.Node.Registry.RegisterEntity(context.Background(), signedEnt)
	require.NoError(err, "register test entity")

	// Register the test runtime.
	testRuntime.RegistrationTime = uint64(time.Now().Unix())
	signedRt, err := registry.SignRuntime(*node.entityPrivKey, registry.RegisterRuntimeSignatureContext, testRuntime)
	require.NoError(err, "sign runtime descriptor")
	err = node.Node.Registry.RegisterRuntime(context.Background(), signedRt)
	require.NoError(err, "register test runtime")

	// Get the runtime and the corresponding committee node instance.
	node.runtimeID = node.Worker.GetConfig().Runtimes[0].ID
	rt := node.Worker.GetRuntime(node.runtimeID)
	require.NotNil(t, rt)
	node.committeeNode = rt.GetNode()
}

func testDeregisterEntityRuntime(t *testing.T, node *testNode) {
	// Stop the node and wait for it to fully stop. This is required
	// as otherwise the node will re-register itself on each epoch
	// transition.
	node.committeeNode.Stop()
	<-node.committeeNode.Quit()
	node.committeeNode = nil

	// Deregister the entity which should also deregister the node.
	ts := registry.Timestamp(uint64(time.Now().Unix()))
	signed, err := signature.SignSigned(*node.entityPrivKey, registry.DeregisterEntitySignatureContext, &ts)
	require.NoError(t, err, "SignSigned")

	err = node.Node.Registry.DeregisterEntity(context.Background(), signed)
	require.NoError(t, err, "DeregisterEntity")

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
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	_, supportsExpiry := (node.Storage).(storage.SweepableBackend)

	storageTests.StorageImplementationTests(t, node.Storage, timeSource, supportsExpiry)
}

func testRegistry(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	registryTests.RegistryImplementationTests(t, node.Registry, timeSource)
}

func testScheduler(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	schedulerTests.SchedulerImplementationTests(t, node.Scheduler, timeSource, node.Registry)
}

func testStaking(t *testing.T, node *testNode) {
	stakingTests.StakingImplementationTests(t, node.Staking)
}

func testRootHash(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	roothashTests.RootHashImplementationTests(t, node.RootHash, timeSource, node.Scheduler, node.Storage, node.Registry)
}

func testWorker(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	workerTests.WorkerImplementationTests(t, node.Worker, node.runtimeID, node.committeeNode, timeSource, node.RootHash)
}

func testClient(t *testing.T, node *testNode) {
	clientTests.ClientImplementationTests(t, node.Client, node.runtimeID, node.committeeNode)
}

func init() {
	_ = testRuntime.ID.UnmarshalHex(testRuntimeID)
}
