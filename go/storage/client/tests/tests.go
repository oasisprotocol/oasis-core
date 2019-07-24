package tests

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	beacon "github.com/oasislabs/ekiden/go/beacon/api"
	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/storage/api"
	storageClient "github.com/oasislabs/ekiden/go/storage/client"
)

const recvTimeout = 5 * time.Second

func runtimeIDToNamespace(t *testing.T, runtimeID signature.PublicKey) (ns common.Namespace) {
	err := ns.UnmarshalBinary(runtimeID[:])
	require.NoError(t, err, "runtimeIDToNamespace")
	return
}

// ClientWorkerTests implements tests for client worker.
func ClientWorkerTests(
	t *testing.T,
	tlsCertificate *tls.Certificate,
	beacon beacon.Backend,
	timeSource epochtime.SetableBackend,
	registry registry.Backend,
	schedulerBackend scheduler.Backend,
) {
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
	client, err := storageClient.New(ctx, tlsCertificate, schedulerBackend, registry)
	require.NoError(err, "NewStorageClient")
	err = client.(api.ClientBackend).WatchRuntime(rt.Runtime.ID)
	require.NoError(err, "NewStorageClient")

	// Create mock root hash and id hash for GetValue().
	var rootHash hash.Hash
	rootHash.FromBytes([]byte("non-existing"))
	id := api.Key("key")

	root := api.Root{
		Namespace: runtimeIDToNamespace(t, rt.Runtime.ID),
		Round:     0,
		Hash:      rootHash,
	}

	// Storage should not yet be available
	r, err := client.GetPath(ctx, root, id, 0)
	require.EqualError(err, storageClient.ErrStorageNotAvailable.Error(), "storage client get before initialization")
	require.Nil(r, "result should be nil")

	// Advance the epoch.
	epochtimeTests.MustAdvanceEpoch(t, timeSource, 1)

	// Wait for initialization.
	<-client.Initialized()

	// Get scheduled storage nodes.
	scheduledStorageNodes := []*node.Node{}
	ch, sub := schedulerBackend.WatchCommittees()
	defer sub.Close()
recvLoop:
	for {
		select {
		case cm := <-ch:
			if cm.Kind != scheduler.KindStorage {
				continue
			}
			if cm.RuntimeID.ToMapKey() != rt.Runtime.ID.ToMapKey() {
				continue
			}
			for _, cn := range cm.Members {
				for _, n := range nodes {
					if n.ID.ToMapKey() == cn.PublicKey.ToMapKey() {
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
	r, err = client.GetPath(ctx, root, id, 0)
	require.Error(err, "storage client should error")
	require.Equal(codes.Unavailable, status.Code(err), "storage client should timeout")
	require.Nil(r, "result should be nil")

	rt.Cleanup(t, registry)
}
