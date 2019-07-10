package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	storageClient "github.com/oasislabs/ekiden/go/storage/client"
)

// ClientWorkerTests implements tests for client worker.
func ClientWorkerTests(t *testing.T, beacon beacon.Backend, timeSource epochtime.SetableBackend, registry registry.Backend, scheduler scheduler.Backend) {
	ctx := context.Background()
	require := require.New(t)
	seed := []byte("StorageClientTests")

	// Populate registry.
	rt, err := registryTests.NewTestRuntime(seed, nil)
	require.NoError(err, "NewTestRuntime")
	// Populate the registry with an entity and nodes.
	nodes := rt.Populate(t, registry, rt, seed)

	rt.MustRegister(t, registry)
	// Initialize storage client
	client, err := storageClient.New(ctx, scheduler, registry)
	require.NoError(err, "NewStorageClient")
	// Create mock root hash and id hash for GetValue().
	var ns common.Namespace
	var rootHash, id hash.Hash
	rootHash.FromBytes([]byte("non-existing"))
	id.FromBytes([]byte("key"))

	root := api.Root{
		Namespace: ns,
		Round:     0,
		Hash:      rootHash,
	}

	// Storage should not yet be available.
	r, err := client.GetPath(ctx, root, id, 0)
	require.EqualError(err, storageClient.ErrStorageNotAvailable.Error(), "storage client get before initialization")
	require.Nil(r, "result should be nil")

	// Advance the epoch.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for initialization.
	<-client.Initialized()

	// Need to wait a bit for client to update with newly populated nodes.
	time.Sleep(5 * time.Second)

	connectedNodes := client.(api.ClientBackend).GetConnectedNodes()
	// NOTE: This number will change if the StorageGroupSize in
	/// registryTests.NewTestRuntime() changes.
	require.Equal(len(connectedNodes), 3, "storage client should be connected to all storage nodes")

	// TimeOut is expected, as test nodes do not actually start storage worker.
	r, err = client.GetPath(ctx, root, id, 0)
	require.Error(err, "storage client should error")
	require.Equal(codes.Unavailable, status.Code(err), "storage client should timeout")
	require.Nil(r, "result should be nil")

	// Check that all schedules storage nodes are connected to.
	scheduledStorageNodes := []*node.Node{}
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) {
			scheduledStorageNodes = append(scheduledStorageNodes, n)
		}
	}
	require.ElementsMatch(scheduledStorageNodes, connectedNodes, "storage client should be connected to all scheduled storage nodes (and only to them)")

	rt.Cleanup(t, registry)
}
