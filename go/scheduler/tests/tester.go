// Package tests is a collection of scheduler implementation test cases.
package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensusAPI "github.com/oasislabs/oasis-core/go/consensus/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	registryTests "github.com/oasislabs/oasis-core/go/registry/tests"
	"github.com/oasislabs/oasis-core/go/scheduler/api"
)

const recvTimeout = 5 * time.Second

// SchedulerImplementationTests exercises the basic functionality of a
// scheduler backend.
func SchedulerImplementationTests(t *testing.T, name string, backend api.Backend, consensus consensusAPI.Backend) {
	seed := []byte("SchedulerImplementationTests/" + name)

	require := require.New(t)

	rt, err := registryTests.NewTestRuntime(seed, nil)
	require.NoError(err, "NewTestRuntime")

	// Populate the registry with an entity and nodes.
	nodes := rt.Populate(t, consensus.Registry(), consensus, seed)

	ch, sub, err := backend.WatchCommittees(context.Background())
	require.NoError(err, "WatchCommittees")
	defer sub.Close()

	// Advance the epoch.
	epochtime := consensus.EpochTime().(epochtime.SetableBackend)
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
				case api.KindCompute:
					require.Nil(compute, "haven't seen a compute committee yet")
					compute = committee
					require.Len(committee.Members, expectedCompute, "committee has all compute nodes")
				case api.KindStorage:
					require.Nil(storage, "haven't seen a storage committee yet")
					require.Len(committee.Members, expectedStorage, "committee has all storage nodes")
					storage = committee
				case api.KindTransactionScheduler:
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

		var committees []*api.Committee
		committees, err = backend.GetCommittees(context.Background(), &api.GetCommitteesRequest{
			RuntimeID: rt.Runtime.ID,
			Height:    consensusAPI.HeightLatest,
		})
		require.NoError(err, "GetCommittees")
		for _, committee := range committees {
			switch committee.Kind {
			case api.KindCompute:
				require.EqualValues(compute, committee, "fetched compute committee is identical")
				compute = nil
			case api.KindStorage:
				require.EqualValues(storage, committee, "fetched storage committee is identical")
				storage = nil
			case api.KindTransactionScheduler:
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
		if n.HasRoles(node.RoleComputeWorker) {
			nCompute++
		}
		if n.HasRoles(node.RoleStorageWorker) {
			nStorage++
		}
	}
	ensureValidCommittees(nCompute, nStorage, int(rt.Runtime.TxnScheduler.GroupSize))

	// Re-register the runtime with less nodes.
	rt.Runtime.Compute.GroupSize = 2
	rt.Runtime.Compute.GroupBackupSize = 1
	rt.Runtime.Storage.GroupSize = 1
	rt.MustRegister(t, consensus.Registry(), consensus)

	epoch = epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	ensureValidCommittees(3, 1, int(rt.Runtime.TxnScheduler.GroupSize))

	// Cleanup the registry.
	rt.Cleanup(t, consensus.Registry(), consensus)

	// Since the integration tests run with validator elections disabled,
	// just ensure that the GetValidators query returns the node's identity.
	validators, err := backend.GetValidators(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetValidators")

	require.Len(validators, 1, "should be only one static validator")
	require.Equal(consensus.ConsensusKey(), validators[0].ID)
	require.EqualValues(consensusAPI.VotingPower, validators[0].VotingPower)
}

func requireValidCommitteeMembers(t *testing.T, committee *api.Committee, runtime *registry.Runtime, nodes []*node.Node) {
	require := require.New(t)

	nodeMap := make(map[signature.PublicKey]*node.Node)
	for _, node := range nodes {
		nodeMap[node.ID] = node
	}

	var leaders, workers, backups int
	seenMap := make(map[signature.PublicKey]bool)
	for _, member := range committee.Members {
		id := member.PublicKey
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

	if committee.Kind.NeedsLeader() {
		require.Equal(1, leaders, fmt.Sprintf("%s committee should have a leader", committee.Kind))
	} else {
		require.Equal(0, leaders, fmt.Sprintf("%s committee shouldn't have a leader", committee.Kind))
	}
	switch committee.Kind {
	case api.KindCompute:
		require.EqualValues(runtime.Compute.GroupSize, workers, "compute committee should have the correct number of workers")
		require.EqualValues(runtime.Compute.GroupBackupSize, backups, "compute committee should have the correct number of backup workers")
	case api.KindMerge:
		require.EqualValues(runtime.Merge.GroupSize, workers, "merge committee should have the correct number of workers")
		require.EqualValues(runtime.Merge.GroupBackupSize, backups, "merge committee should have the correct number of backup workers")
	case api.KindStorage, api.KindTransactionScheduler:
		numCommitteeMembersWithoutLeader := len(committee.Members)
		if committee.Kind.NeedsLeader() {
			numCommitteeMembersWithoutLeader--
		}
		require.EqualValues(numCommitteeMembersWithoutLeader, workers, fmt.Sprintf("all %s committee members except for the leader (if present) should be workers", committee.Kind))
		require.Equal(0, backups, fmt.Sprintf("%s committee shouldn't have a backup workers", committee.Kind))
	default:
		require.FailNow(fmt.Sprintf("unknown committee kind: %s", committee.Kind))
	}
}
