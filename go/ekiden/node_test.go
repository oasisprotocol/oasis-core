package main

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	beaconTests "github.com/oasislabs/ekiden/go/beacon/tests"
	cmdCommon "github.com/oasislabs/ekiden/go/ekiden/cmd/common"
	"github.com/oasislabs/ekiden/go/ekiden/cmd/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	roothashTests "github.com/oasislabs/ekiden/go/roothash/tests"
	schedulerTests "github.com/oasislabs/ekiden/go/scheduler/tests"
	storage "github.com/oasislabs/ekiden/go/storage/api"
	storageTests "github.com/oasislabs/ekiden/go/storage/tests"
	workerTests "github.com/oasislabs/ekiden/go/worker/tests"
)

var (
	testNodeConfig = []struct {
		key   string
		value interface{}
	}{
		{"log.level", "DEBUG"},
		{"epochtime.backend", "tendermint_mock"},
		{"beacon.backend", "tendermint"},
		{"registry.backend", "tendermint"},
		{"roothash.backend", "tendermint"},
		{"scheduler.backend", "trivial"},
		{"storage.backend", "leveldb"},
		{"tendermint.consensus.skip_timeout_commit", true},
		{"tendermint.debug.block_time_iota", 10 * time.Millisecond},
		{"worker.backend", "mock"},
		{"worker.runtime.binary", "mock-runtime"},
		{"worker.runtime.id", "0000000000000000000000000000000000000000000000000000000000000000"},
	}

	initConfigOnce sync.Once
)

type testNode struct {
	*node.Node

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

	viper.Set("datadir", dataDir)
	viper.Set("log.file", filepath.Join(dataDir, "test-node.log"))
	for _, kv := range testNodeConfig {
		viper.Set(kv.key, kv.value)
	}

	n := &testNode{
		dataDir: dataDir,
		start:   time.Now(),
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
		// Worker test case must run first as starting the worker will
		// automatically register the runtime and node.
		{"Worker", testWorker},

		{"EpochTime", testEpochTime},
		{"Beacon", testBeacon},
		{"Storage", testStorage},
		{"Registry", testRegistry},
		{"Scheduler", testScheduler},
		{"RootHash", testRootHash},
	}

	for _, tc := range testCases {
		tc.Run(t, node)
	}
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

func testRootHash(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	roothashTests.RootHashImplementationTests(t, node.RootHash, timeSource, node.Scheduler, node.Storage, node.Registry)
}

func testWorker(t *testing.T, node *testNode) {
	timeSource := (node.Epochtime).(epochtime.SetableBackend)

	workerTests.WorkerImplementationTests(t, node.Worker, timeSource, node.Registry, node.RootHash, node.Identity)
}
