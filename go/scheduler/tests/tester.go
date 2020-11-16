// Package tests is a collection of scheduler implementation test cases.
package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	epochtime "github.com/oasisprotocol/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasisprotocol/oasis-core/go/epochtime/tests"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	registryTests "github.com/oasisprotocol/oasis-core/go/registry/tests"
	"github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

const recvTimeout = 5 * time.Second

// SchedulerImplementationTests exercises the basic functionality of a
// scheduler backend.
func SchedulerImplementationTests(t *testing.T, name string, backend api.Backend, consensus consensusAPI.Backend) {
	ctx := context.Background()
	seed := []byte("SchedulerImplementationTests/" + name)

	require := require.New(t)

	rt, err := registryTests.NewTestRuntime(seed, nil, false)
	require.NoError(err, "NewTestRuntime")

	// Populate the registry with an entity and nodes.
	nodes := rt.Populate(t, consensus.Registry(), consensus, seed)

	// Query genesis parameters.
	_, err = backend.ConsensusParameters(ctx, consensusAPI.HeightLatest)

	ch, sub, err := backend.WatchCommittees(ctx)
	require.NoError(err, "WatchCommittees")
	defer sub.Close()

	// Advance the epoch.
	epochtime := consensus.EpochTime().(epochtime.SetableBackend)
	epoch := epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	ensureValidCommittees := func(expectedExecutor, expectedStorage int) {
		var executor, storage *api.Committee
		var seen int
		for seen < 2 {
			select {
			case committee := <-ch:
				if committee.ValidFor < epoch {
					continue
				}
				if !rt.Runtime.ID.Equal(&committee.RuntimeID) {
					continue
				}

				switch committee.Kind {
				case api.KindComputeExecutor:
					require.Nil(executor, "haven't seen an executor committee yet")
					executor = committee
					require.Len(committee.Members, expectedExecutor, "committee has all executor nodes")
				case api.KindStorage:
					require.Nil(storage, "haven't seen a storage committee yet")
					require.Len(committee.Members, expectedStorage, "committee has all storage nodes")
					storage = committee
				}

				requireValidCommitteeMembers(t, committee, rt.Runtime, nodes)
				require.Equal(rt.Runtime.ID, committee.RuntimeID, "committee is for the correct runtime") // Redundant
				require.Equal(epoch, committee.ValidFor, "committee is for current epoch")

				seen++
			case <-time.After(recvTimeout):
				t.Fatalf("failed to receive committee event")
			}
		}

		var committees []*api.Committee
		committees, err = backend.GetCommittees(context.Background(), &api.GetCommitteesRequest{
			RuntimeID: rt.Runtime.ID,
			Height:    consensusAPI.HeightLatest,
		})
		require.NoError(err, "GetCommittees")
		for _, committee := range committees {
			switch committee.Kind {
			case api.KindComputeExecutor:
				require.EqualValues(executor, committee, "fetched executor committee is identical")
				executor = nil
			case api.KindStorage:
				require.EqualValues(storage, committee, "fetched storage committee is identical")
				storage = nil
			}
		}

		require.Nil(executor, "fetched an executor committee")
		require.Nil(storage, "fetched a storage committee")
	}

	var nExecutor, nStorage int
	for _, n := range nodes {
		if n.HasRoles(node.RoleComputeWorker) {
			nExecutor++
		}
		if n.HasRoles(node.RoleStorageWorker) {
			nStorage++
		}
	}
	ensureValidCommittees(
		nExecutor,
		nStorage,
	)

	// Re-register the runtime with less nodes.
	rt.Runtime.Executor.GroupSize = 2
	rt.Runtime.Executor.GroupBackupSize = 1
	rt.Runtime.Executor.MinPoolSize = 3
	rt.Runtime.Storage.GroupSize = 1
	rt.Runtime.Storage.MinPoolSize = 1
	rt.Runtime.Storage.MinWriteReplication = 1
	rt.MustRegister(t, consensus.Registry(), consensus)

	epoch = epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	ensureValidCommittees(
		3,
		1,
	)

	// Cleanup the registry.
	rt.Cleanup(t, consensus.Registry(), consensus)

	// Since the integration tests run with validator elections disabled,
	// the GetValidator query is special cased to return the node's consensus
	// identity instead of node identities.
	validators, err := backend.GetValidators(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetValidators")

	require.Len(validators, 1, "should be only one static validator")
	require.Equal(consensus.ConsensusKey(), validators[0].ID)
	require.EqualValues(1, validators[0].VotingPower)
}

func requireValidCommitteeMembers(t *testing.T, committee *api.Committee, runtime *registry.Runtime, nodes []*node.Node) {
	require := require.New(t)

	nodeMap := make(map[signature.PublicKey]*node.Node)
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}

	var workers, backups int
	seenMap := make(map[signature.PublicKey]bool)
	for _, member := range committee.Members {
		id := member.PublicKey
		require.NotNil(nodeMap[id], "member is a node")
		require.False(seenMap[id], "member is unique")
		seenMap[id] = true

		switch member.Role {
		case api.RoleWorker:
			workers++
		case api.RoleBackupWorker:
			backups++
		}
	}

	switch committee.Kind {
	case api.KindComputeExecutor:
		require.EqualValues(runtime.Executor.GroupSize, workers, "executor committee should have the correct number of workers")
		require.EqualValues(runtime.Executor.GroupBackupSize, backups, "executor committee should have the correct number of backup workers")
	case api.KindStorage:
		require.EqualValues(runtime.Storage.GroupSize, workers, "storage committee should have the correct number of workers")
		require.EqualValues(0, backups, "storage committee shouldn't have a backup workers")
	default:
		require.FailNow(fmt.Sprintf("unknown committee kind: %s", committee.Kind))
	}
}
