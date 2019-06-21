package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	"github.com/oasislabs/ekiden/go/registry/memory"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	"github.com/oasislabs/ekiden/go/scheduler/trivial"
)

func TestClientWorker(t *testing.T) {
	ctx := context.Background()
	require := require.New(t)
	seed := []byte("StorageClientTests")

	timeSource := mock.New()
	beacon := insecure.New(ctx, timeSource)
	registry := memory.New(ctx, timeSource)
	scheduler := trivial.New(ctx, timeSource, registry, beacon, nil)
	// Populate registry
	rt, err := registryTests.NewTestRuntime(seed, nil)
	require.NoError(err, "NewTestRuntime")
	// Populate the registry with an entity and nodes.
	nodes := rt.Populate(t, registry, rt, seed)
	rt.MustRegister(t, registry)
	// Initialize storage client
	client, err := New(ctx, timeSource, scheduler, registry)
	require.NoError(err, "NewStorageClient")
	// Create mock root hash and id hash for GetValue().
	var root, id hash.Hash
	root.FromBytes([]byte("non-existing"))
	id.FromBytes([]byte("key"))

	// Storage should not yet be available
	r, err := client.GetValue(ctx, root, id)
	require.EqualError(err, ErrStorageNotAvailable.Error(), "storage client get before initialization")
	require.Nil(r, "result should be nil")

	// Advance the epoch.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for initialization
	<-client.Initialized()

	connectedNodes := client.(*storageClientBackend).GetConnectedNodes()
	// NOTE: This number will change if the StorageGroupSize in
	/// registryTests.NewTestRuntime() changes.
	require.Equal(len(connectedNodes), 3, "storage client should be connected to all storage nodes")

	// TimeOut is expected, as test nodes do not actually start storage worker.
	r, err = client.GetValue(ctx, root, id)
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
}
