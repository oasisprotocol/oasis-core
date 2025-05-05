// Package tests is a collection of roothash implementation test cases.
package tests

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beaconAPI "github.com/oasisprotocol/oasis-core/go/beacon/api"
	beaconTests "github.com/oasisprotocol/oasis-core/go/beacon/tests"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registryTests "github.com/oasisprotocol/oasis-core/go/registry/tests"
	"github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	"github.com/oasisprotocol/oasis-core/go/runtime/transaction"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
	storageAPI "github.com/oasisprotocol/oasis-core/go/storage/api"
	"github.com/oasisprotocol/oasis-core/go/worker/storage"
)

const (
	recvTimeout = 10 * time.Second
	nrRuntimes  = 3
)

type runtimeState struct {
	id           string
	rt           *registryTests.TestRuntime
	genesisBlock *block.Block

	executorCommittee *testCommittee
}

type commitmentEvent struct {
	commits []commitment.ExecutorCommitment
}

type discrepancyEvent struct {
	timeout bool
	rank    uint64
	round   uint64
}

type finalizedEvent struct {
	round uint64
}

// RootHashImplementationTests exercises the basic functionality of a
// roothash backend.
func RootHashImplementationTests(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, identity *identity.Identity) {
	seedBase := []byte(fmt.Sprintf("RootHashImplementationTests: %T", roothash))

	require := require.New(t)

	// Ensure that we leave the registry empty when we are done.
	rtStates := make([]*runtimeState, 0, nrRuntimes)
	defer func() {
		if len(rtStates) > 0 {
			// This is entity deregistration based, and all of the
			// runtimes used in this test share the entity.
			rtStates[0].rt.Cleanup(t, consensus.Registry(), consensus)
		}

		registryTests.EnsureRegistryClean(t, consensus.Registry())
	}()

	// Populate the registry.
	runtimes := make([]*registryTests.TestRuntime, 0, nrRuntimes)
	for i := 0; i < nrRuntimes; i++ {
		seed := append([]byte{}, seedBase...)
		seed = append(seed, byte(i))

		rt, err := registryTests.NewTestRuntime(seed, nil, false)
		require.NoError(err, "NewTestRuntime")

		rtStates = append(rtStates, &runtimeState{
			id: strconv.Itoa(i),
			rt: rt,
		})
		runtimes = append(runtimes, rt)
	}
	registryTests.BulkPopulate(t, consensus.Registry(), consensus, runtimes, seedBase)

	t.Run("ConsensusParameters", func(t *testing.T) {
		testConsensusParameters(t, roothash)
	})

	// Run the various tests. (Ordering matters)
	for _, v := range rtStates {
		t.Run("GenesisBlock/"+v.id, func(t *testing.T) {
			testGenesisBlock(t, roothash, v)
		})
	}
	success := t.Run("EpochTransitionBlock", func(t *testing.T) {
		testEpochTransitionBlock(t, roothash, consensus, rtStates)
	})
	if !success {
		return
	}

	// It only makes sense to run the following tests in case the
	// EpochTransitionBlock was successful. Otherwise this may leave the
	// committees set to nil and cause a crash.
	t.Run("SuccessfulRound", func(t *testing.T) {
		testSuccessfulRound(t, roothash, consensus, rtStates)
	})

	t.Run("RoundTimeout", func(t *testing.T) {
		testRoundTimeout(t, roothash, consensus, rtStates)
	})

	t.Run("RoundTimeoutWithEpochTransition", func(t *testing.T) {
		testRoundTimeoutWithEpochTransition(t, roothash, consensus, rtStates)
	})

	t.Run("EquivocationEvidence", func(t *testing.T) {
		testSubmitEquivocationEvidence(t, roothash, consensus, identity, rtStates)
	})
}

func testConsensusParameters(t *testing.T, roothash api.Backend) {
	ctx := context.Background()

	params, err := roothash.ConsensusParameters(ctx, consensusAPI.HeightLatest)
	require.NoError(t, err, "ConsensusParameters")
	require.EqualValues(t, 32, params.MaxRuntimeMessages, "expected max runtime messages value")
}

func testGenesisBlock(t *testing.T, roothash api.Backend, state *runtimeState) {
	require := require.New(t)

	id := state.rt.Runtime.ID
	ch, sub, err := roothash.WatchBlocks(context.Background(), id)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	var genesisBlock *block.Block
	select {
	case blk := <-ch:
		header := blk.Block.Header

		require.EqualValues(header.Version, 0, "block version")
		require.EqualValues(0, header.Round, "block round")
		require.Equal(block.Normal, header.HeaderType, "block header type")
		require.True(header.IORoot.IsEmpty(), "block I/O root empty")
		require.True(header.StateRoot.IsEmpty(), "block root hash empty")
		genesisBlock = blk.Block
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive block")
	}

	blk, err := roothash.GetLatestBlock(context.Background(), &api.RuntimeRequest{
		RuntimeID: id,
		Height:    consensusAPI.HeightLatest,
	})
	require.NoError(err, "GetLatestBlock")
	require.EqualValues(genesisBlock, blk, "retreived block is genesis block")

	// We need to wait for the indexer to index the block. We could have a channel
	// to subscribe to these updates and this would not be needed.
	time.Sleep(1 * time.Second)

	blk, err = roothash.GetGenesisBlock(context.Background(), &api.RuntimeRequest{
		RuntimeID: id,
		Height:    consensusAPI.HeightLatest,
	})
	require.NoError(err, "GetGenesisBlock")
	require.EqualValues(genesisBlock, blk, "retrieved block is genesis block")
}

func testEpochTransitionBlock(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, states []*runtimeState) {
	require := require.New(t)

	// Before an epoch transition there should just be a genesis block.
	for _, v := range states {
		genesisBlock, err := roothash.GetLatestBlock(context.Background(), &api.RuntimeRequest{
			RuntimeID: v.rt.Runtime.ID,
			Height:    consensusAPI.HeightLatest,
		})
		require.NoError(err, "GetLatestBlock")
		require.EqualValues(0, genesisBlock.Header.Round, "genesis block round")

		v.genesisBlock = genesisBlock
	}

	// Subscribe to blocks for all of the runtimes.
	var blkChannels []<-chan *api.AnnotatedBlock
	for i := range states {
		v := states[i]
		ch, sub, err := roothash.WatchBlocks(context.Background(), v.rt.Runtime.ID)
		require.NoError(err, "WatchBlocks")
		defer sub.Close()

		blkChannels = append(blkChannels, ch)
	}

	// Advance the epoch.
	beaconTests.MustAdvanceEpoch(t, consensus)

	// Check for the expected post-epoch transition events.
	for i, state := range states {
		blkCh := blkChannels[i]
		state.testEpochTransitionBlock(t, consensus, blkCh)
	}

	// Check if GetGenesisBlock still returns the correct genesis block.
	for i := range states {
		blk, err := roothash.GetGenesisBlock(context.Background(), &api.RuntimeRequest{
			RuntimeID: states[i].rt.Runtime.ID,
			Height:    consensusAPI.HeightLatest,
		})
		require.NoError(err, "GetGenesisBlock")
		require.EqualValues(0, blk.Header.Round, "retrieved block is genesis block")
	}
}

func (s *runtimeState) refreshCommittees(t *testing.T, consensus consensusAPI.Service) {
	nodes := make(map[signature.PublicKey]*registryTests.TestNode)
	for _, node := range s.rt.TestNodes() {
		nodes[node.Node.ID] = node
	}

	epoch, err := consensus.Beacon().GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(t, err, "GetEpoch")

	s.executorCommittee = mustGetCommittee(t, s.rt, epoch, consensus.Scheduler(), nodes)
}

func (s *runtimeState) testEpochTransitionBlock(t *testing.T, consensus consensusAPI.Service, ch <-chan *api.AnnotatedBlock) {
	require := require.New(t)

	s.refreshCommittees(t, consensus)

	// Wait to receive an epoch transition block.
	for {
		select {
		case blk := <-ch:
			header := blk.Block.Header

			if header.HeaderType != block.EpochTransition {
				continue
			}

			require.True(header.IsParentOf(&s.genesisBlock.Header), "parent is parent of genesis block")
			require.True(header.IORoot.IsEmpty(), "block I/O root empty")
			require.EqualValues(s.genesisBlock.Header.StateRoot, header.StateRoot, "state root preserved")

			// Nothing more to do after the epoch transition block was received.
			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive block")
		}
	}
}

func testSuccessfulRound(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, states []*runtimeState) {
	for _, state := range states {
		state.testSuccessfulRound(t, roothash, consensus)
	}
}

func (s *runtimeState) generateExecutorCommitments(t *testing.T, consensus consensusAPI.Service, child *block.Block, rank uint64) (
	*block.Block,
	[]commitment.ExecutorCommitment,
	[]*registryTests.TestNode,
) {
	require := require.New(t)

	s.refreshCommittees(t, consensus)
	rt, executorCommittee := s.rt, s.executorCommittee

	dataDir, err := os.MkdirTemp("", "oasis-storage-test_")
	require.NoError(err, "TempDir")
	defer os.RemoveAll(dataDir)

	var ns common.Namespace
	copy(ns[:], rt.Runtime.ID[:])

	storageBackend, err := storage.NewLocalBackend(dataDir, ns)
	require.NoError(err, "storage.New")
	defer storageBackend.Cleanup()

	// Generate a dummy I/O root.
	ioRoot := storageAPI.Root{
		Namespace: child.Header.Namespace,
		Version:   child.Header.Round + 1,
		Type:      storageAPI.RootTypeIO,
	}
	ioRoot.Hash.Empty()

	ctx := context.Background()
	tree := transaction.NewTree(nil, ioRoot)
	defer tree.Close()
	err = tree.AddTransaction(ctx, transaction.Transaction{Input: []byte("testInput"), Output: []byte("testOutput")}, nil)
	require.NoError(err, "tree.AddTransaction")
	_, ioRootHash, err := tree.Commit(ctx)
	require.NoError(err, "tree.Commit")

	// Create the new block header that the nodes will commit to.
	parent := &block.Block{
		Header: block.Header{
			Version:      0,
			Namespace:    child.Header.Namespace,
			Round:        child.Header.Round + 1,
			Timestamp:    block.Timestamp(time.Now().Unix()),
			HeaderType:   block.Normal,
			PreviousHash: child.Header.EncodedHash(),
			IORoot:       ioRootHash,
			StateRoot:    ioRootHash,
		},
	}
	require.True(parent.Header.IsParentOf(&child.Header), "parent is parent of child")

	var msgsHash, inMsgsHash hash.Hash
	msgsHash.Empty()
	inMsgsHash.Empty()

	// Gather executor nodes, starting with the scheduler.
	schedulerIdx, ok := executorCommittee.committee.SchedulerIdx(parent.Header.Round, rank)
	require.True(ok, "SchedulerIdx")
	schedulerID := executorCommittee.workers[schedulerIdx].Signer.Public()

	executorNodes := make([]*registryTests.TestNode, 0, len(executorCommittee.workers))
	executorNodes = append(executorNodes, executorCommittee.workers[schedulerIdx:]...)
	executorNodes = append(executorNodes, executorCommittee.workers[:schedulerIdx]...)

	// Generate all the executor commitments.
	executorCommits := make([]commitment.ExecutorCommitment, 0, len(executorNodes))
	for _, node := range executorNodes {
		ec := commitment.ExecutorCommitment{
			NodeID: node.Signer.Public(),
			Header: commitment.ExecutorCommitmentHeader{
				SchedulerID: schedulerID,
				Header: commitment.ComputeResultsHeader{
					Round:           parent.Header.Round,
					PreviousHash:    parent.Header.PreviousHash,
					IORoot:          &parent.Header.IORoot,
					StateRoot:       &parent.Header.StateRoot,
					MessagesHash:    &msgsHash,
					InMessagesHash:  &inMsgsHash,
					InMessagesCount: 0,
				},
			},
		}

		err = ec.Sign(node.Signer, s.rt.Runtime.ID)
		require.NoError(err, "ec.Sign")

		executorCommits = append(executorCommits, ec)
	}

	return parent, executorCommits, executorNodes
}

// getEvents returns runtime events at specified block height.
func (s *runtimeState) getEvents(ctx context.Context, roothash api.Backend, height int64) ([]*api.Event, error) {
	evs, err := roothash.GetEvents(ctx, height)
	if err != nil {
		return nil, err
	}

	filtered := make([]*api.Event, 0, len(evs))
	for _, ev := range evs {
		if ev.RuntimeID != s.rt.Runtime.ID {
			continue
		}
		filtered = append(filtered, ev)
	}

	return filtered, nil
}

// verifyEvents verifies that executor commitment, discrepancy detection and round finalized events
// were emitted at the given height.
func (s *runtimeState) verifyEvents(t *testing.T, ctx context.Context, roothash api.Backend, height int64, ce *commitmentEvent, de *discrepancyEvent, fe *finalizedEvent) {
	require := require.New(t)

	numEvents := 0
	if ce != nil {
		numEvents += len(ce.commits)
	}
	if de != nil {
		numEvents++
	}
	if fe != nil {
		numEvents++
	}

	evts, err := s.getEvents(ctx, roothash, height)
	require.NoError(err, "getEvents")
	require.Len(evts, numEvents, "should have all events")

	if ce != nil {
		for _, commit := range ce.commits {
			ev := evts[0]
			evts = evts[1:]
			require.NotNil(ev.ExecutorCommitted, fmt.Sprintf("unexpected event: %+v", ev))
			require.EqualValues(commit, ev.ExecutorCommitted.Commit, "executor commitment should match")
		}
	}

	if de != nil {
		ev := evts[0]
		evts = evts[1:]
		require.NotNil(ev.ExecutionDiscrepancyDetected, fmt.Sprintf("unexpected event: %+v", ev))
		require.Equal(de.timeout, ev.ExecutionDiscrepancyDetected.Timeout, "timeout should match")
		require.Equal(de.rank, ev.ExecutionDiscrepancyDetected.Rank, "rank should match")
		require.Equal(de.round, ev.ExecutionDiscrepancyDetected.Round, "round should match")
	}

	if fe != nil {
		ev := evts[0]
		require.NotNil(ev.Finalized, fmt.Sprintf("unexpected event: %+v", ev))
		require.Equal(fe.round, ev.Finalized.Round, "round should match")
	}
}

// livenessStatistics fetches liveness statistics at the specified height.
func (s *runtimeState) livenessStatistics(t *testing.T, ctx context.Context, roothash api.Backend, height int64) *api.LivenessStatistics {
	require := require.New(t)

	state, err := roothash.GetRuntimeState(ctx, &api.RuntimeRequest{
		RuntimeID: s.rt.Runtime.ID,
		Height:    height,
	})
	require.NoError(err, "GetRuntimeState")

	numNodes := len(s.executorCommittee.workers) + len(s.executorCommittee.backupWorkers)
	if state.LivenessStatistics == nil {
		return api.NewLivenessStatistics(numNodes)
	}

	require.Len(state.LivenessStatistics.LiveRounds, numNodes)
	require.Len(state.LivenessStatistics.FinalizedProposals, numNodes)
	require.Len(state.LivenessStatistics.MissedProposals, numNodes)

	return state.LivenessStatistics
}

// livenessStatisticsDiff returns the differences in liveness statistics caused by a block
// at the specified height.
func (s *runtimeState) livenessStatisticsDiff(t *testing.T, ctx context.Context, roothash api.Backend, height int64) *api.LivenessStatistics {
	before := s.livenessStatistics(t, ctx, roothash, height-1)
	after := s.livenessStatistics(t, ctx, roothash, height)

	after.TotalRounds -= before.TotalRounds
	for i, v := range before.FinalizedProposals {
		after.FinalizedProposals[i] -= v
	}
	for i, v := range before.LiveRounds {
		after.LiveRounds[i] -= v
	}
	for i, v := range before.MissedProposals {
		after.MissedProposals[i] -= v
	}

	return after
}

func (s *runtimeState) testSuccessfulRound(t *testing.T, roothash api.Backend, consensus consensusAPI.Service) {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*recvTimeout)
	defer cancel()

	ch, sub, err := roothash.WatchBlocks(ctx, s.rt.Runtime.ID)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	// Fetch the last block.
	child, err := nextRuntimeBlock(ch, nil)
	require.NoError(err, "nextRuntimeBlock")

	// Generate and submit all executor commitments.
	blk, executorCommits, executorNodes := s.generateExecutorCommitments(t, consensus, child.Block, 0)
	tx := api.NewExecutorCommitTx(0, nil, s.rt.Runtime.ID, executorCommits)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, executorNodes[0].Signer, tx)
	require.NoError(err, "ExecutorCommit")

	// Ensure that the round was finalized.
	parent, err := nextRuntimeBlock(ch, nil)
	require.NoError(err, "nextRuntimeBlock")

	require.EqualValues(child.Block.Header.Round+1, parent.Block.Header.Round, "block round")
	require.EqualValues(block.Normal, parent.Block.Header.HeaderType, "block header type must be Normal")

	// Can't directly compare headers, some backends rewrite the timestamp.
	require.EqualValues(blk.Header.Version, parent.Block.Header.Version, "block version")
	require.EqualValues(blk.Header.Namespace, parent.Block.Header.Namespace, "block namespace")
	require.EqualValues(blk.Header.Round, parent.Block.Header.Round, "block round")
	// Timestamp
	require.EqualValues(blk.Header.HeaderType, parent.Block.Header.HeaderType, "block header type")
	require.EqualValues(blk.Header.PreviousHash, parent.Block.Header.PreviousHash, "block previous hash")
	require.EqualValues(blk.Header.IORoot, parent.Block.Header.IORoot, "block I/O root")
	require.EqualValues(blk.Header.StateRoot, parent.Block.Header.StateRoot, "block root hash")

	// There should be executor commitment events for all commitments and one finalized event.
	height := parent.Height
	s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits}, nil, &finalizedEvent{parent.Block.Header.Round})

	// Check that the liveness statistics were computed correctly.
	livenessStatistics := s.livenessStatisticsDiff(t, ctx, roothash, parent.Height)

	liveRounds := make([]uint64, len(livenessStatistics.LiveRounds))
	finalizedProposals := make([]uint64, len(livenessStatistics.FinalizedProposals))
	missedProposals := make([]uint64, len(livenessStatistics.MissedProposals))

	// All workers and none backup workers should be considered live as every worker submitted
	// a commitment and there were no discrepancies.
	for i := range s.executorCommittee.workers {
		liveRounds[i] = 1
	}

	schedulerIdx, ok := s.executorCommittee.committee.SchedulerIdx(parent.Block.Header.Round, 0)
	require.True(ok, "SchedulerIdx")
	finalizedProposals[schedulerIdx]++

	require.Equal(uint64(1), livenessStatistics.TotalRounds, "there should be one finalized round")
	require.EqualValues(liveRounds, livenessStatistics.LiveRounds, "there should be no live members")
	require.EqualValues(finalizedProposals, livenessStatistics.FinalizedProposals, "there should be one finalized proposal")
	require.EqualValues(missedProposals, livenessStatistics.MissedProposals, "there should be no failed proposals")
}

func testRoundTimeout(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, states []*runtimeState) {
	for _, state := range states {
		for _, rank := range []uint64{0, 1, 2} {
			state.testRoundTimeout(t, roothash, consensus, rank)
		}
	}
}

func (s *runtimeState) testRoundTimeout(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, rank uint64) {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*recvTimeout)
	defer cancel()

	ch, sub, err := roothash.WatchBlocks(ctx, s.rt.Runtime.ID)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	// Fetch the last block.
	child, err := nextRuntimeBlock(ch, nil)
	require.NoError(err, "nextRuntimeBlock")

	// verifyLivenessStatistics verifies liveness statistics, i.e. that the scheduler missed
	// a proposal because of the round timeout.
	verifyLivenessStatistics := func(blk *api.AnnotatedBlock) {
		livenessStatistics := s.livenessStatisticsDiff(t, ctx, roothash, blk.Height)

		liveRounds := make([]uint64, len(livenessStatistics.LiveRounds))
		finalizedProposals := make([]uint64, len(livenessStatistics.FinalizedProposals))
		missedProposals := make([]uint64, len(livenessStatistics.MissedProposals))

		var schedulerIdx int
		schedulerIdx, ok := s.executorCommittee.committee.SchedulerIdx(blk.Block.Header.Round, 0)
		require.True(ok, "SchedulerIdx")
		missedProposals[schedulerIdx]++

		require.Zero(livenessStatistics.TotalRounds, "there should be no finalized rounds")
		require.EqualValues(liveRounds, livenessStatistics.LiveRounds, "there should be no live members")
		require.EqualValues(finalizedProposals, livenessStatistics.FinalizedProposals, "there should be no new finalized proposals")
		require.EqualValues(missedProposals, livenessStatistics.MissedProposals, "there should be one extra missed proposal")
	}

	var parent *api.AnnotatedBlock

	t.Run(fmt.Sprintf("Single commitment, scheduler rank %d", rank), func(t *testing.T) {
		// Submit one commitment and wait for a double timeout (worker + backup worker timeout).
		_, executorCommits, executorNodes := s.generateExecutorCommitments(t, consensus, child.Block, rank)
		require.Equal(executorCommits[0].NodeID, executorCommits[0].Header.SchedulerID)

		tx := api.NewExecutorCommitTx(0, nil, s.rt.Runtime.ID, executorCommits[:1])
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, executorNodes[0].Signer, tx)
		require.NoError(err, "ExecutorCommit")

		// Ensure that the round failed.
		parent, err = nextRuntimeBlock(ch, nil)
		require.NoError(err, "nextRuntimeBlock")

		round := child.Block.Header.Round + 1
		require.EqualValues(round, parent.Block.Header.Round, "block round")
		require.EqualValues(block.RoundFailed, parent.Block.Header.HeaderType, "block header type must be RoundFailed")

		// Check that round was finalized after 2.5*RoundTimeout blocks.
		height := parent.Height - 25*s.rt.Runtime.Executor.RoundTimeout/10
		s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits[:1]}, nil, nil)

		// Check that discrepancy resolution started after RoundTimeout blocks.
		height = parent.Height - 15*s.rt.Runtime.Executor.RoundTimeout/10
		s.verifyEvents(t, ctx, roothash, height, nil, &discrepancyEvent{true, rank, round}, nil)

		// Check that the liveness statistics were computed correctly.
		verifyLivenessStatistics(parent)

		child = parent
	})

	t.Run(fmt.Sprintf("Discrepant commitments, scheduler rank %d", rank), func(t *testing.T) {
		// Submit two discrepant commitments to immediately trigger discrepancy resolution
		// and wait for a single timeout (backup worker timeout).
		_, executorCommits, executorNodes := s.generateExecutorCommitments(t, consensus, child.Block, rank)
		require.Equal(executorCommits[0].NodeID, executorCommits[0].Header.SchedulerID)

		// Corrupt one commitment.
		executorCommits[0].Header.Header.InMessagesCount++
		err = executorCommits[0].Sign(executorNodes[0].Signer, s.rt.Runtime.ID)
		require.NoError(err, "ec.Sign")

		tx := api.NewExecutorCommitTx(0, nil, s.rt.Runtime.ID, executorCommits[:2])
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, executorNodes[0].Signer, tx)
		require.NoError(err, "ExecutorCommit")

		// Ensure that the round failed.
		parent, err = nextRuntimeBlock(ch, nil)
		require.NoError(err, "nextRuntimeBlock")

		round := child.Block.Header.Round + 1
		require.EqualValues(round, parent.Block.Header.Round, "block round")
		require.EqualValues(block.RoundFailed, parent.Block.Header.HeaderType, "block header type must be RoundFailed")

		// Backup schedulers should wait for a double timeout.
		switch rank {
		case 0:
			// Check that round was finalized after 1.5*RoundTimeout blocks and that discrepancy
			// resolution started immediately.
			height := parent.Height - 15*s.rt.Runtime.Executor.RoundTimeout/10
			s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits[:2]}, &discrepancyEvent{false, rank, round}, nil)
		default:
			// Check that round was finalized after 2.5*RoundTimeout blocks.
			height := parent.Height - 25*s.rt.Runtime.Executor.RoundTimeout/10
			s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits[:2]}, nil, nil)

			// Check that discrepancy resolution started after RoundTimeout blocks.
			height = parent.Height - 15*s.rt.Runtime.Executor.RoundTimeout/10
			s.verifyEvents(t, ctx, roothash, height, nil, &discrepancyEvent{true, rank, round}, nil)

		}

		// Check that the liveness statistics were updated correctly.
		verifyLivenessStatistics(parent)

		child = parent
	})

	t.Run(fmt.Sprintf("Single failure, scheduler rank %d", rank), func(t *testing.T) {
		// Submit one failure based on a proposal from the primary scheduler and wait for
		// a double timeout (worker timeout + backup worker timeout).
		_, executorCommits, executorNodes := s.generateExecutorCommitments(t, consensus, child.Block, rank)
		require.Equal(executorCommits[0].NodeID, executorCommits[0].Header.SchedulerID)

		// Change one commitment to a failure.
		commitmentToFailure(&executorCommits[1])
		err = executorCommits[1].Sign(executorNodes[1].Signer, s.rt.Runtime.ID)
		require.NoError(err, "ec.Sign")

		tx := api.NewExecutorCommitTx(0, nil, s.rt.Runtime.ID, executorCommits[:2])
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, executorNodes[0].Signer, tx)
		require.NoError(err, "ExecutorCommit")

		// Ensure that the round failed.
		parent, err = nextRuntimeBlock(ch, nil)
		require.NoError(err, "nextRuntimeBlock")

		round := child.Block.Header.Round + 1
		require.EqualValues(round, parent.Block.Header.Round, "block round")
		require.EqualValues(block.RoundFailed, parent.Block.Header.HeaderType, "block header type must be RoundFailed")

		// Check that round was finalized after 2.5*RoundTimeout blocks.
		height := parent.Height - 25*s.rt.Runtime.Executor.RoundTimeout/10
		s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits[:2]}, nil, nil)

		// Check that discrepancy resolution started after RoundTimeout blocks.
		height = parent.Height - 15*s.rt.Runtime.Executor.RoundTimeout/10
		s.verifyEvents(t, ctx, roothash, height, nil, &discrepancyEvent{true, rank, round}, nil)

		// Check that the liveness statistics were computed correctly.
		verifyLivenessStatistics(parent)

		child = parent
	})

	t.Run(fmt.Sprintf("Numerous failures, scheduler rank %d", rank), func(t *testing.T) {
		// Submit enough failures based on a proposal from the primary scheduler to immediately
		// trigger discrepancy resolution and wait for a single timeout (backup worker timeout).
		_, executorCommits, executorNodes := s.generateExecutorCommitments(t, consensus, child.Block, rank)
		require.Equal(executorCommits[0].NodeID, executorCommits[0].Header.SchedulerID)

		// Change commitments to failures.
		commitmentToFailure(&executorCommits[1])
		err = executorCommits[1].Sign(executorNodes[1].Signer, s.rt.Runtime.ID)
		require.NoError(err, "ec.Sign")

		commitmentToFailure(&executorCommits[2])
		err = executorCommits[2].Sign(executorNodes[2].Signer, s.rt.Runtime.ID)
		require.NoError(err, "ec.Sign")

		tx := api.NewExecutorCommitTx(0, nil, s.rt.Runtime.ID, executorCommits[:3])
		err = consensusAPI.SignAndSubmitTx(ctx, consensus, executorNodes[0].Signer, tx)
		require.NoError(err, "ExecutorCommit")

		// Ensure that the round failed.
		parent, err = nextRuntimeBlock(ch, nil)
		require.NoError(err, "nextRuntimeBlock")

		round := child.Block.Header.Round + 1
		require.EqualValues(round, parent.Block.Header.Round, "block round")
		require.EqualValues(block.RoundFailed, parent.Block.Header.HeaderType, "block header type must be RoundFailed")

		// Backup schedulers should wait for a double timeout.
		switch rank {
		case 0:
			// Check that round was finalized after 1.5*RoundTimeout blocks and that discrepancy
			// resolution started immediately.
			height := parent.Height - 15*s.rt.Runtime.Executor.RoundTimeout/10
			s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits[:3]}, &discrepancyEvent{false, rank, round}, nil)
		default:
			// Check that round was finalized after 2.5*RoundTimeout blocks.
			height := parent.Height - 25*s.rt.Runtime.Executor.RoundTimeout/10
			s.verifyEvents(t, ctx, roothash, height, &commitmentEvent{executorCommits[:3]}, nil, nil)

			// Check that discrepancy resolution started after RoundTimeout blocks.
			height = parent.Height - 15*s.rt.Runtime.Executor.RoundTimeout/10
			s.verifyEvents(t, ctx, roothash, height, nil, &discrepancyEvent{true, rank, round}, nil)

		}

		// Check that the liveness statistics were updated correctly.
		verifyLivenessStatistics(parent)

		child = parent
	})
}

func testRoundTimeoutWithEpochTransition(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, states []*runtimeState) {
	for _, state := range states {
		state.testRoundTimeoutWithEpochTransition(t, roothash, consensus)
	}
}

func (s *runtimeState) testRoundTimeoutWithEpochTransition(t *testing.T, roothash api.Backend, consensus consensusAPI.Service) {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*recvTimeout)
	defer cancel()

	ch, sub, err := roothash.WatchBlocks(ctx, s.rt.Runtime.ID)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	blk, err := roothash.GetLatestBlock(ctx, &api.RuntimeRequest{
		RuntimeID: s.rt.Runtime.ID,
		Height:    consensusAPI.HeightLatest,
	})
	require.NoError(err, "GetLatestBlock")

	// Fetch the last block.
	child, err := nextRuntimeBlock(ch, blk) // WatchBlocks has latency, so wait for the last epoch transition block to be sent to the channel.
	require.NoError(err, "nextRuntimeBlock")

	// Only submit a single commitment to cause a timeout.
	_, executorCommits, executorNodes := s.generateExecutorCommitments(t, consensus, child.Block, 0)
	tx := api.NewExecutorCommitTx(0, nil, s.rt.Runtime.ID, executorCommits[:1])
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, executorNodes[0].Signer, tx)
	require.NoError(err, "ExecutorCommit")

	// Wait few consensus blocks.
	consCh, consSub, err := consensus.Core().WatchBlocks(ctx)
	require.NoError(err, "WatchBlocks")
	defer consSub.Close()

	for i := 0; i < int(s.rt.Runtime.Executor.RoundTimeout/2); i++ {
		_, err = nextConsensusBlock(consCh)
		require.NoError(err, "nextConsensusBlock")
	}

	// Trigger an epoch transition while the timeout is armed.
	beaconTests.MustAdvanceEpoch(t, consensus)

	// Next round must be an epoch transition.
	parent, err := nextRuntimeBlock(ch, nil)
	require.NoError(err, "nextRuntimeBlock")

	require.EqualValues(child.Block.Header.Round+1, parent.Block.Header.Round, "block round")
	require.EqualValues(block.EpochTransition, parent.Block.Header.HeaderType, "block header type must be EpochTransition")
}

type testCommittee struct {
	committee     *scheduler.Committee
	workers       []*registryTests.TestNode
	backupWorkers []*registryTests.TestNode
}

func mustGetCommittee(
	t *testing.T,
	rt *registryTests.TestRuntime,
	epoch beaconAPI.EpochTime,
	sched scheduler.Backend,
	nodes map[signature.PublicKey]*registryTests.TestNode,
) (
	executorCommittee *testCommittee,
) {
	require := require.New(t)

	ch, sub, err := sched.WatchCommittees(context.Background())
	require.NoError(err, "WatchCommittees")
	defer sub.Close()

	for {
		select {
		case committee := <-ch:
			if committee.ValidFor < epoch {
				continue
			}
			if !rt.Runtime.ID.Equal(&committee.RuntimeID) {
				continue
			}

			var ret testCommittee
			ret.committee = committee
			for _, member := range committee.Members {
				node := nodes[member.PublicKey]
				require.NotNil(node, "member is one of the nodes")
				switch member.Role {
				case scheduler.RoleWorker:
					ret.workers = append(ret.workers, node)
				case scheduler.RoleBackupWorker:
					ret.backupWorkers = append(ret.backupWorkers, node)
				}
			}

			var groupSize, groupBackupSize int
			switch committee.Kind {
			case scheduler.KindComputeExecutor:
				groupSize = int(rt.Runtime.Executor.GroupSize)
				groupBackupSize = int(rt.Runtime.Executor.GroupBackupSize)
			}

			require.Len(ret.workers, groupSize, "workers exist")
			require.Len(ret.backupWorkers, groupBackupSize, "backup workers exist")

			switch committee.Kind {
			case scheduler.KindComputeExecutor:
				executorCommittee = &ret
			}

			if executorCommittee == nil {
				continue
			}

			return
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive committee event")
		}
	}
}

// MustTransitionEpoch waits till the roothash's view is past the epoch
// transition for a given epoch.
func MustTransitionEpoch(
	t *testing.T,
	runtimeID common.Namespace,
	roothash api.Backend,
	beacon beaconAPI.Backend,
	epoch beaconAPI.EpochTime,
) {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	ch, sub, err := roothash.WatchBlocks(ctx, runtimeID)
	require.NoError(err, "WatchBlocks")
	defer sub.Close()

	// Wait for any block that's in the required epoch.  This is done
	// instead of specifically waiting for the epoch transition block
	// on the off chance that we are already past the epoch transition
	// block being broadcast.
	for {
		blk, err := nextRuntimeBlock(ch, nil)
		require.NoError(err, "nextRuntimeBlock")

		blkEpoch, err := beacon.GetEpoch(ctx, blk.Height)
		require.NoError(err, "GetEpoch")

		if blkEpoch >= epoch {
			return
		}
	}
}

func testSubmitEquivocationEvidence(t *testing.T, roothash api.Backend, consensus consensusAPI.Service, _ *identity.Identity, states []*runtimeState) {
	require := require.New(t)

	ctx := context.Background()

	s := states[0]
	child, err := roothash.GetLatestBlock(ctx, &api.RuntimeRequest{
		RuntimeID: s.rt.Runtime.ID,
		Height:    consensusAPI.HeightLatest,
	})
	require.NoError(err, "GetLatestBlock")

	// Generate and submit evidence of executor equivocation.
	if len(s.executorCommittee.workers) < 2 {
		t.Fatal("not enough executor nodes for running runtime misbehaviour evidence test")
	}

	// Generate evidence of executor equivocation.
	node := s.executorCommittee.workers[0]
	signedBatch1 := commitment.Proposal{
		NodeID: node.Signer.Public(),
		Header: commitment.ProposalHeader{
			Round:        child.Header.Round + 1,
			BatchHash:    child.Header.IORoot,
			PreviousHash: child.Header.EncodedHash(),
		},
	}
	err = signedBatch1.Sign(node.Signer, s.rt.Runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")

	signedBatch2 := commitment.Proposal{
		NodeID: node.Signer.Public(),
		Header: commitment.ProposalHeader{
			Round:        child.Header.Round + 1,
			BatchHash:    hash.NewFromBytes([]byte("different root")),
			PreviousHash: child.Header.EncodedHash(),
		},
	}
	err = signedBatch2.Sign(node.Signer, s.rt.Runtime.ID)
	require.NoError(err, "ProposalHeader.Sign")

	ch, sub, err := consensus.Staking().WatchEvents(ctx)
	require.NoError(err, "staking.WatchEvents")
	defer sub.Close()

	// Ensure misbehaving node entity has some stake.
	entityAddress := staking.NewAddress(node.Node.EntityID)
	escrow := &staking.Escrow{
		Account: entityAddress,
		Amount:  *quantity.NewFromUint64(100),
	}
	tx := staking.NewAddEscrowTx(0, nil, escrow)
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, stakingTests.Accounts.GetSigner(1), tx)
	require.NoError(err, "AddEscrow")

	// Submit evidence of executor equivocation.
	tx = api.NewEvidenceTx(0, nil, &api.Evidence{
		ID: s.rt.Runtime.ID,
		EquivocationProposal: &api.EquivocationProposalEvidence{
			ProposalA: signedBatch1,
			ProposalB: signedBatch2,
		},
	})
	submitter := s.executorCommittee.workers[1]
	err = consensusAPI.SignAndSubmitTx(ctx, consensus, submitter.Signer, tx)
	require.NoError(err, "SignAndSubmitTx(EvidenceTx)")

	// Wait for the node to get slashed.
WaitLoop:
	for {
		select {
		case ev := <-ch:
			if ev.Escrow == nil {
				continue
			}

			if e := ev.Escrow.Take; e != nil {
				require.EqualValues(entityAddress, e.Owner, "TakeEscrowEvent - owner must be entity's address")
				// All stake must be slashed as defined in debugGenesisState.
				require.EqualValues(escrow.Amount, e.Amount, "TakeEscrowEvent - all stake slashed")
				break WaitLoop
			}
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive slash event")
		}
	}

	// Ensure runtime acc got the slashed funds.
	runtimeAcc, err := consensus.Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensusAPI.HeightLatest,
		Owner:  staking.NewRuntimeAddress(s.rt.Runtime.ID),
	})
	require.NoError(err, "staking.Account(runtimeAddr)")
	require.EqualValues(escrow.Amount, runtimeAcc.General.Balance, "Runtime account expected salshed balance")
}

// nextRuntimeBlock return the next runtime block starting at the given block.
func nextRuntimeBlock(ch <-chan *api.AnnotatedBlock, start *block.Block) (*api.AnnotatedBlock, error) {
	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("runtime block channel closed")
			}
			if start != nil && blk.Block.Header.Round < start.Header.Round {
				continue
			}
			return blk, nil
		case <-time.After(recvTimeout):
			return nil, fmt.Errorf("failed to receive runtime block")
		}
	}
}

// nextConsensusBlock return the next consensus block.
func nextConsensusBlock(ch <-chan *consensusAPI.Block) (*consensusAPI.Block, error) {
	for {
		select {
		case blk, ok := <-ch:
			if !ok {
				return nil, fmt.Errorf("consensus block channel closed")
			}
			return blk, nil
		case <-time.After(recvTimeout):
			return nil, fmt.Errorf("failed to receive consensus block")
		}
	}
}

// commitmentToFailure transforms the given executor commitment to a failure.
func commitmentToFailure(commit *commitment.ExecutorCommitment) {
	commit.Header.Failure = commitment.FailureUnknown
	commit.Header.Header.IORoot = nil
	commit.Header.Header.StateRoot = nil
	commit.Header.Header.MessagesHash = nil
	commit.Header.Header.InMessagesHash = nil
}
