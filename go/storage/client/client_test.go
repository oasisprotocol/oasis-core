package client

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"github.com/spf13/viper"

	"github.com/oasislabs/ekiden/go/beacon/insecure"
	"github.com/oasislabs/ekiden/go/common/node"
	"github.com/oasislabs/ekiden/go/epochtime/mock"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	"github.com/oasislabs/ekiden/go/registry/memory"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	"github.com/oasislabs/ekiden/go/scheduler/trivial"
	"github.com/oasislabs/ekiden/go/storage/api"
	"github.com/oasislabs/ekiden/go/storage/tests"
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
	var connectedCommitteeNode *node.Node
	for _, n := range nodes {
		if n.HasRoles(node.RoleStorageWorker) && n.ID.String() == connectedNode.ID.String() {
			connectedCommitteeNode = n
			break
		}
	}
	require.NotNil(connectedCommitteeNode, "connected storage node not found in storage committee")
	require.EqualValues(connectedCommitteeNode, connectedNode, "connected storage node belongs to storage committee")
}
