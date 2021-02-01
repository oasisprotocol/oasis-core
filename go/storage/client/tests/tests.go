package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registryTests "github.com/oasisprotocol/oasis-core/go/registry/tests"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/storage/api"
	storageClient "github.com/oasisprotocol/oasis-core/go/storage/client"
)

const recvTimeout = 5 * time.Second

// ClientWorkerTests implements tests for client worker.
func ClientWorkerTests(
	t *testing.T,
	identity *identity.Identity,
	consensus consensusAPI.Backend,
) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require := require.New(t)
	seed := []byte("StorageClientTests")

	// Populate registry.
	rt, err := registryTests.NewTestRuntime(seed, nil, false)
	require.NoError(err, "NewTestRuntime")
	// Populate the registry with an entity and nodes.
	nodes := rt.Populate(t, consensus.Registry(), consensus, seed)

	ns := rt.Runtime.ID

	// Initialize storage client.
	client, err := storageClient.New(ctx, ns, identity, consensus.Scheduler(), consensus.Registry(), nil)
	require.NoError(err, "NewStorageClient")

	// Create mock root hash.
	rootHash := hash.NewFromBytes([]byte("non-existing"))

	root := api.Root{
		Namespace: ns,
		Version:   0,
		Hash:      rootHash,
	}

	// Storage should not yet be available.
	r, err := client.SyncGet(ctx, &api.GetRequest{
		Tree: api.TreeID{
			Root:     root,
			Position: root.Hash,
		},
	})
	require.EqualError(err, storageClient.ErrStorageNotAvailable.Error(), "storage client get before initialization")
	require.Nil(r, "result should be nil")

	// Advance the epoch.
	timeSource := consensus.Beacon().(beacon.SetableBackend)
	beaconTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for initialization.
	select {
	case <-client.Initialized():
	case <-time.After(recvTimeout):
		t.Fatalf("failed to wait for client initialization")
	}

	// Get scheduled storage nodes.
	scheduledStorageNodes := []*node.Node{}
	ch, sub, err := consensus.Scheduler().WatchCommittees(ctx)
	require.NoError(err, "WatchCommittees")
	defer sub.Close()
recvLoop:
	for {
		select {
		case cm := <-ch:
			if cm.Kind != scheduler.KindStorage {
				continue
			}
			if cm.RuntimeID != rt.Runtime.ID {
				continue
			}
			for _, cn := range cm.Members {
				for _, n := range nodes {
					if n.ID == cn.PublicKey {
						scheduledStorageNodes = append(scheduledStorageNodes, n)
					}
				}
			}
			break recvLoop
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive Storage Committee")
		}
	}

	// Get connected nodes.
	connectedNodes := client.(api.ClientBackend).GetConnectedNodes()

	// Check that all scheduled storage nodes are connected to.
	require.ElementsMatch(scheduledStorageNodes, connectedNodes, "storage client should be connected to scheduled storage nodes")

	// Try getting path.
	// TimeOut is expected, as test nodes do not actually start storage worker.
	ctx, cancel = context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	r, err = client.SyncGet(ctx, &api.GetRequest{
		Tree: api.TreeID{
			Root:     root,
			Position: root.Hash,
		},
	})
	require.Error(err, "storage client should error")
	require.Nil(r, "result should be nil")

	rt.Cleanup(t, consensus.Registry(), consensus)
}
