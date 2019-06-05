package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	"github.com/oasislabs/ekiden/go/registry/memory"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	"github.com/oasislabs/ekiden/go/scheduler/trivial"
	"github.com/oasislabs/ekiden/go/storage/api"
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
	_ = rt.Populate(t, registry, rt, seed)
	rt.MustRegister(t, registry)
	// Initialize storage client
	client, err := New(ctx, timeSource, scheduler, registry)
	require.NoError(err, "NewStorageClient")

	// Storage should not yet be available
	r, err := client.Get(ctx, api.HashStorageKey([]byte("key")))
	require.EqualError(err, ErrStorageNotAvailable.Error(), "storage client get before initialisation")
	require.Nil(r, "result should be nil")

	// Advance the epoch.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for initialization
	<-client.Initialized()

	connectedNode := client.(*storageClientBackend).GetConnectedNode()

	require.NotNil(connectedNode, "storage node should be connected")
	// TimeOut is expected, as test nodes do not actually start storage worker.
	r, err = client.Get(ctx, api.HashStorageKey([]byte("key")))
	require.Error(err, "storage client should error")
	require.Equal(codes.Unavailable, status.Code(err), "storage client should timeout")
	require.Nil(r, "result should be nil")

	// Confirm one of the registered nodes was assigned.
	var connectedTestNode *registryTests.TestNode
	for _, nt := range rt.TestNodes() {
		if nt.Node.HasRoles(node.RoleStorageWorker) && nt.Node.ID.ToMapKey() == connectedNode.ID.ToMapKey() {
			connectedTestNode = nt
			break
		}
	}
	require.NotNil(connectedTestNode, "connected storage node not found in storage committee")
	require.EqualValues(connectedTestNode.Node, connectedNode, "connected storage node belongs to storage committee")

	// Re-register storage node with changed address
	addr := connectedTestNode.Node.Addresses[0]
	newAddr, err := node.NewAddress(addr.Family, addr.Tuple.IP, addr.Tuple.Port+1)
	require.NoError(err, "node.NewAddress()")
	connectedTestNode.Node.Addresses[0] = *newAddr
	connectedTestNode = rt.RegisterNode(t, registry, *connectedTestNode)

	// TODO: avoid sleeping - might actually work without sleeping but would probably be race prone
	time.Sleep(100 * time.Microsecond)
	newConnectedNode := client.(*storageClientBackend).GetConnectedNode()
	require.EqualValues(newConnectedNode, connectedTestNode.Node, "connected storage address was updated mid epoch")
}
