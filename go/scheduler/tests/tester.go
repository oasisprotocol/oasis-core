// Package tests is a collection of scheduler implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	"github.com/oasislabs/ekiden/go/scheduler/api"
)

const recvTimeout = 1 * time.Second

// SchedulerImplementationTests exercises the basic functionality of a
// scheduler backend.
func SchedulerImplementationTests(t *testing.T, backend api.Backend, epochtime epochtime.SetableBackend, registry registry.Backend) {
	seed := []byte("SchedulerImplementationTests")

	require := require.New(t)

	rt, err := registryTests.NewTestRuntime(seed, nil)
	require.NoError(err, "NewTestRuntime")

	// Populate the registry with an entity and nodes.
	nodes := rt.Populate(t, registry, rt, seed)
	rt.MustRegister(t, registry)

	ch, sub := backend.WatchCommittees()
	defer sub.Close()

	// Advance the epoch.
	epoch := epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	ensureValidCommittees := func(expectedCompute, expectedStorage, expectedTransactionScheduler int) {
		var compute, storage, transactionScheduler *api.Committee
		var seen int
		for seen < 3 {
			select {
			case committee := <-ch:
				if committee.ValidFor < epoch {
					continue
				}
				if !rt.Runtime.ID.Equal(committee.RuntimeID) {
					continue
				}

				switch committee.Kind {
				case api.Compute:
					require.Nil(compute, "haven't seen a compute committee yet")
					compute = committee
					require.Len(committee.Members, expectedCompute, "committee has all compute nodes")
				case api.Storage:
					require.Nil(storage, "haven't seen a storage committee yet")
					require.Len(committee.Members, expectedStorage, "committee has all storage nodes")
					storage = committee
				case api.TransactionScheduler:
					require.Nil(transactionScheduler, "haven't seen a transaction scheduler committee yet")
					require.Len(committee.Members, expectedTransactionScheduler, "committee has all transaction scheduler nodes")
					transactionScheduler = committee
				}

				requireValidCommitteeMembers(t, committee, rt.Runtime, nodes)
				require.Equal(rt.Runtime.ID, committee.RuntimeID, "committee is for the correct runtime") // Redundant
				require.Equal(epoch, committee.ValidFor, "committee is for current epoch")

				seen++
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive committee event")
			}
		}

		committees, err := backend.GetCommittees(context.Background(), rt.Runtime.ID)
		require.NoError(err, "GetCommittees")
		for _, committee := range committees {
			switch committee.Kind {
			case api.Compute:
				require.EqualValues(compute, committee, "fetched compute committee is identical")
				compute = nil
			case api.Storage:
				require.EqualValues(storage, committee, "fetched storage committee is identical")
				storage = nil
			case api.TransactionScheduler:
				require.EqualValues(transactionScheduler, committee, "fetched transaction scheduler committee is identical")
				transactionScheduler = nil
			}
		}

		require.Nil(compute, "fetched a compute committee")
		require.Nil(storage, "fetched a storage committee")
		require.Nil(transactionScheduler, "fetched a transaction scheduler committee")
	}

	var nCompute, nStorage int
	for _, n := range nodes {
		if n.HasRoles(node.ComputeWorker) {
			nCompute++
		}
		if n.HasRoles(node.StorageWorker) {
			nStorage++
		}
	}
	ensureValidCommittees(nCompute, nStorage, int(rt.Runtime.TransactionSchedulerGroupSize))

	// Re-register the runtime with less nodes.
	rt.Runtime.ReplicaGroupSize = 2
	rt.Runtime.ReplicaGroupBackupSize = 1
	rt.Runtime.StorageGroupSize = 1
	rt.MustRegister(t, registry)

	epoch = epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	ensureValidCommittees(3, 1, int(rt.Runtime.TransactionSchedulerGroupSize))

	// Cleanup the registry.
	rt.Cleanup(t, registry)
}

func requireValidCommitteeMembers(t *testing.T, committee *api.Committee, runtime *registry.Runtime, nodes []*node.Node) {
	require := require.New(t)

	nodeMap := make(map[signature.MapKey]*node.Node)
	for _, node := range nodes {
		nodeMap[node.ID.ToMapKey()] = node
	}

	var leaders, workers, backups int
	seenMap := make(map[signature.MapKey]bool)
	for _, member := range committee.Members {
		id := member.PublicKey.ToMapKey()
		require.NotNil(nodeMap[id], "member is a node")
		require.False(seenMap[id], "member is unique")
		seenMap[id] = true

		switch member.Role {
		case api.Worker:
			workers++
		case api.BackupWorker:
			backups++
		case api.Leader:
			leaders++
		}
	}

	require.Equal(1, leaders, "committee has a leader")
	if committee.Kind == api.Compute {
		require.EqualValues(runtime.ReplicaGroupSize, leaders+workers, "committee has correct number of workers")
		require.EqualValues(runtime.ReplicaGroupBackupSize, backups, "committe has correct number of backups")
	}
}
