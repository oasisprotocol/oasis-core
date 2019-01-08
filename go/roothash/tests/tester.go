// Package tests si a collection of roothash implementation test cases.
package tests

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	registryTests "github.com/oasislabs/ekiden/go/registry/tests"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

const (
	recvTimeout = 2 * time.Second
	nrRuntimes  = 3
)

type runtimeState struct {
	id           string
	rt           *registryTests.TestRuntime
	genesisBlock *block.Block
	committee    *testCommittee
}

// RootHashImplementationTests exercises the basic functionality of a
// roothash backend.
func RootHashImplementationTests(t *testing.T, backend api.Backend, epochtime epochtime.SetableBackend, scheduler scheduler.Backend, storage storage.Backend, registry registry.Backend) {
	seedBase := []byte("RootHashImplementationTests")

	require := require.New(t)

	// Ensure that we leave the registry empty when we are done.
	rtStates := make([]*runtimeState, 0, nrRuntimes)
	defer func() {
		if len(rtStates) > 0 {
			// This is entity deregistration based, and all of the
			// runtimes used in this test share the entity.
			rtStates[0].rt.Cleanup(t, registry)
		}

		registryTests.EnsureRegistryEmpty(t, registry)
	}()

	// Populate the registry.
	runtimes := make([]*registryTests.TestRuntime, 0, nrRuntimes)
	for i := 0; i < nrRuntimes; i++ {
		t.Logf("Generating runtime: %d", i)
		seed := append([]byte{}, seedBase...)
		seed = append(seed, byte(i))

		rt, err := registryTests.NewTestRuntime(seed)
		require.NoError(err, "NewTestRuntime")
		rt.MustRegister(t, registry)

		rtStates = append(rtStates, &runtimeState{
			id: strconv.Itoa(i),
			rt: rt,
		})
		runtimes = append(runtimes, rt)
	}
	registryTests.BulkPopulate(t, registry, runtimes, seedBase)

	// Run the various tests. (Ordering matters)
	for _, v := range rtStates {
		t.Run("GenesisBlock/"+v.id, func(t *testing.T) {
			testGenesisBlock(t, backend, v)
		})
	}
	t.Run("EpochTransitionBlock", func(t *testing.T) {
		testEpochTransitionBlock(t, backend, epochtime, scheduler, rtStates)
	})
	t.Run("SucessfulRound", func(t *testing.T) {
		testSucessfulRound(t, backend, storage, rtStates)
	})

	// TODO: Test the various failures.

	// TODO: Test WatchBlocksSince (though it will be deprecated via #1009...)
}

func testGenesisBlock(t *testing.T, backend api.Backend, state *runtimeState) {
	require := require.New(t)

	id := state.rt.Runtime.ID
	ch, sub, err := backend.WatchBlocks(id)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	var genesisBlock *block.Block
	select {
	case blk := <-ch:
		header := blk.Header

		require.EqualValues(header.Version, 0, "block version")
		var round uint64
		round, err = header.Round.ToU64()
		require.NoError(err, "header.Round.ToU64")
		require.EqualValues(0, round, "block round")
		require.Equal(block.Normal, header.HeaderType, "block header type")
		require.True(header.InputHash.IsEmpty(), "block input hash empty")
		require.True(header.OutputHash.IsEmpty(), "block output hash empty")
		require.True(header.StateRoot.IsEmpty(), "block root hash empty")
		genesisBlock = blk
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive block")
	}

	blk, err := backend.GetLatestBlock(context.Background(), id)
	require.NoError(err, "GetLatestBlock")
	require.EqualValues(genesisBlock, blk, "retreived block is genesis block")
}

func testEpochTransitionBlock(t *testing.T, backend api.Backend, epochtime epochtime.SetableBackend, scheduler scheduler.Backend, states []*runtimeState) {
	require := require.New(t)

	// Before an epoch transition there should just be a genesis block.
	for _, v := range states {
		genesisBlock, err := backend.GetLatestBlock(context.Background(), v.rt.Runtime.ID)
		require.NoError(err, "GetLatestBlock")
		var round uint64
		round, err = genesisBlock.Header.Round.ToU64()
		require.NoError(err, "header.Round.ToU64")
		require.EqualValues(0, round, "genesis block round")

		v.genesisBlock = genesisBlock
	}

	// Advance the epoch, get the committee.
	epoch, _, err := epochtime.GetEpoch(context.Background())
	require.NoError(err, "GetEpoch")

	// Subscribe to blocks for all of the runtimes.
	var blkChannels []<-chan *block.Block
	for i := range states {
		v := states[i]
		ch, sub, err := backend.WatchBlocks(v.rt.Runtime.ID)
		require.NoError(err, "WatchBlocks")
		defer sub.Close()

		blkChannels = append(blkChannels, ch)
	}

	// Advance the epoch.
	epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	// Check for the expected post-epoch transition events.
	for i, state := range states {
		blkCh := blkChannels[i]
		state.testEpochTransitionBlock(t, scheduler, epoch, blkCh)
	}
}

func (s *runtimeState) testEpochTransitionBlock(t *testing.T, scheduler scheduler.Backend, epoch epochtime.EpochTime, ch <-chan *block.Block) {
	require := require.New(t)

	nodes := make(map[signature.MapKey]*registryTests.TestNode)
	for _, node := range s.rt.TestNodes() {
		nodes[node.Node.ID.ToMapKey()] = node
	}

	s.committee = mustGetCommittee(t, s.rt, epoch+1, scheduler, nodes)

	// Wait to receive an epoch transition block.
	for {
		select {
		case blk := <-ch:
			header := blk.Header

			if header.HeaderType != block.EpochTransition {
				continue
			}

			require.True(header.IsParentOf(&s.genesisBlock.Header), "parent is parent of genesis block")
			require.True(header.InputHash.IsEmpty(), "block input hash empty")
			require.True(header.OutputHash.IsEmpty(), "block output hash empty")
			require.EqualValues(s.genesisBlock.Header.StateRoot, header.StateRoot, "state root preserved")

			// Nothing more to do after the epoch transition block was received.
			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive block")
		}
	}
}

func testSucessfulRound(t *testing.T, backend api.Backend, storage storage.Backend, states []*runtimeState) {
	for _, state := range states {
		state.testSuccessfulRound(t, backend, storage)
	}
}

func (s *runtimeState) testSuccessfulRound(t *testing.T, backend api.Backend, storage storage.Backend) {
	require := require.New(t)

	rt, committee := s.rt, s.committee

	child, err := backend.GetLatestBlock(context.Background(), rt.Runtime.ID)
	require.NoError(err, "GetLatestBlock")

	ch, sub, err := backend.WatchBlocks(rt.Runtime.ID)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	// Create the new block header that the leader and nodes will commit to.
	parent := &block.Block{
		Header: block.Header{
			Version:      0,
			Namespace:    child.Header.Namespace,
			Round:        child.Header.Round.Increment(),
			Timestamp:    uint64(time.Now().Unix()),
			HeaderType:   block.Normal,
			PreviousHash: child.Header.EncodedHash(),
			InputHash:    mustStore(t, storage, []byte("testInputSet")),
			OutputHash:   mustStore(t, storage, []byte("testOutputSet")),
			StateRoot:    mustStore(t, storage, []byte("testStateRoot")),
		},
	}
	parent.Header.GroupHash.From(committee.committee.Members)
	require.True(parent.Header.IsParentOf(&child.Header), "parent is parent of child")

	// Send all the commitments.
	var toCommit []*registryTests.TestNode
	var commitments []*api.OpaqueCommitment
	toCommit = append(toCommit, committee.leader)
	toCommit = append(toCommit, committee.workers...)
	for _, node := range toCommit {
		commit, err := commitment.SignCommitment(node.PrivateKey, &parent.Header) // nolint: govet
		require.NoError(err, "SignSigned")
		opaque := commit.ToOpaqueCommitment()
		err = backend.Commit(context.Background(), rt.Runtime.ID, opaque)
		require.NoError(err, "Commit")

		commitments = append(commitments, opaque)
	}

	parent.Header.CommitmentsHash.From(commitments) // For comparison.

	var childRound uint64
	childRound, err = child.Header.Round.ToU64()
	require.NoError(err, "child.Header.Round.ToU64")

	// Ensure that the round was finalized.
	for {
		select {
		case blk := <-ch:
			header := blk.Header

			var round uint64
			round, err = header.Round.ToU64()
			require.NoError(err, "header.Round.ToU64")

			// Ensure that WatchBlocks uses the correct latest block.
			require.True(round >= childRound, "WatchBlocks must start at child block")

			if round == childRound {
				require.EqualValues(child.Header, header, "old block is equal")
				continue
			}

			// Can't direcly compare headers, some backends rewrite the timestamp.
			require.EqualValues(parent.Header.Version, header.Version, "block version")
			require.EqualValues(parent.Header.Namespace, header.Namespace, "block namespace")
			require.EqualValues(parent.Header.Round, header.Round, "block round")
			// Timestamp
			require.EqualValues(parent.Header.HeaderType, header.HeaderType, "block header type")
			require.EqualValues(parent.Header.PreviousHash, header.PreviousHash, "block previous hash")
			require.EqualValues(parent.Header.GroupHash, header.GroupHash, "block group hash")
			require.EqualValues(parent.Header.InputHash, header.InputHash, "block input hash")
			require.EqualValues(parent.Header.OutputHash, header.OutputHash, "block output hash")
			require.EqualValues(parent.Header.StateRoot, header.StateRoot, "block root hash")
			require.EqualValues(parent.Header.CommitmentsHash, header.CommitmentsHash, "block commitments hash")

			// Nothing more to do after the block was received.
			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive block")
		}
	}
}

type testCommittee struct {
	committee     *scheduler.Committee
	leader        *registryTests.TestNode
	workers       []*registryTests.TestNode
	backupWorkers []*registryTests.TestNode
}

func mustGetCommittee(t *testing.T, rt *registryTests.TestRuntime, epoch epochtime.EpochTime, sched scheduler.Backend, nodes map[signature.MapKey]*registryTests.TestNode) *testCommittee {
	require := require.New(t)

	ch, sub := sched.WatchCommittees()
	defer sub.Close()

	for {
		select {
		case committee := <-ch:
			if committee.ValidFor < epoch {
				continue
			}
			if !rt.Runtime.ID.Equal(committee.RuntimeID) {
				continue
			}
			if committee.Kind != scheduler.Compute {
				continue
			}

			var ret testCommittee
			ret.committee = committee
			for _, member := range committee.Members {
				node := nodes[member.PublicKey.ToMapKey()]
				require.NotNil(node, "member is one of the nodes")

				switch member.Role {
				case scheduler.Worker:
					ret.workers = append(ret.workers, node)
				case scheduler.BackupWorker:
					ret.backupWorkers = append(ret.backupWorkers, node)
				case scheduler.Leader:
					ret.leader = node
				}
			}

			require.NotNil(ret.leader, "leader exists")
			require.Len(ret.workers, int(rt.Runtime.ReplicaGroupSize)-1, "workers exist")
			require.Len(ret.backupWorkers, int(rt.Runtime.ReplicaGroupBackupSize), "workers exist")

			return &ret
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive committee event")
		}
	}
}

func mustStore(t *testing.T, store storage.Backend, value []byte) hash.Hash {
	require := require.New(t)

	err := store.Insert(context.Background(), value, uint64(1)<<63)
	require.NoError(err, "Insert")

	key := storage.HashStorageKey(value)
	var h hash.Hash
	copy(h[:], key[:])
	return h
}
