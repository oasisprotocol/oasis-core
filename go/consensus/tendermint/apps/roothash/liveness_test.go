package roothash

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	roothashState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/roothash/state"
	schedulerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/scheduler/state"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/commitment"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
)

func TestLivenessProcessing(t *testing.T) {
	require := require.New(t)

	now := time.Unix(1580461674, 0)
	appState := abciAPI.NewMockApplicationState(&abciAPI.MockApplicationStateConfig{})
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()

	// Generate a private key for the single node in this test.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(err, "NewSigner")

	// Initialize registry state.
	registryState := registryState.NewMutableState(ctx.State())
	err = registryState.SetNodeStatus(ctx, sk.Public(), &registry.NodeStatus{})
	require.NoError(err, "SetNodeStatus")

	runtime := registry.Runtime{
		Executor: registry.ExecutorParameters{
			MinLiveRoundsForEvaluation: 10,
			MinLiveRoundsPercent:       90,
			MaxLivenessFailures:        4,
		},
	}

	// Initialize scheduler state.
	schedulerState := schedulerState.NewMutableState(ctx.State())
	executorCommittee := scheduler.Committee{
		RuntimeID: runtime.ID,
		Kind:      scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.RoleWorker,
				PublicKey: sk.Public(),
			},
		},
	}
	err = schedulerState.PutCommittee(ctx, &executorCommittee)
	require.NoError(err, "PutCommittee")

	// Initialize roothash state.
	roothashState := roothashState.NewMutableState(ctx.State())
	blk := block.NewGenesisBlock(runtime.ID, 0)
	rtState := &roothash.RuntimeState{
		Runtime:            &runtime,
		GenesisBlock:       blk,
		CurrentBlock:       blk,
		CurrentBlockHeight: 1,
		LastNormalRound:    0,
		LastNormalHeight:   1,
		ExecutorPool: &commitment.Pool{
			Runtime:   &runtime,
			Committee: &executorCommittee,
			Round:     0,
		},
		LivenessStatistics: &roothash.LivenessStatistics{
			TotalRounds: 100,
			LiveRounds:  []uint64{91},
		},
	}
	err = roothashState.SetRuntimeState(ctx, rtState)
	require.NoError(err, "SetRuntimeState")

	epoch := beacon.EpochTime(0)

	// When the node is live, everything should be left as is, no faults should be recorded.
	err = processLivenessStatistics(ctx, epoch, rtState)
	require.NoError(err, "processLivenessStatistics")
	status, err := registryState.NodeStatus(ctx, sk.Public())
	require.NoError(err, "NodeStatus")
	require.False(status.IsSuspended(runtime.ID, epoch), "node should not be suspended")

	// When node is not live, it should be suspended, there should be one fault.
	rtState.LivenessStatistics.LiveRounds[0] = 89 // At least 90 required.
	err = processLivenessStatistics(ctx, epoch, rtState)
	require.NoError(err, "processLivenessStatistics")
	status, err = registryState.NodeStatus(ctx, sk.Public())
	require.NoError(err, "NodeStatus")
	require.True(status.IsSuspended(runtime.ID, epoch), "node should be suspended")
	require.EqualValues(1, status.Faults[runtime.ID].Failures, "there should be one fault")
	require.EqualValues(epoch+2, status.Faults[runtime.ID].SuspendedUntil, "suspension time should be set")

	// Bump epoch so the node is no longer suspended.
	epoch = 2

	// When node is not live again, fault counter should increase.
	rtState.LivenessStatistics.LiveRounds[0] = 89 // At least 90 required.
	err = processLivenessStatistics(ctx, epoch, rtState)
	require.NoError(err, "processLivenessStatistics")
	status, err = registryState.NodeStatus(ctx, sk.Public())
	require.NoError(err, "NodeStatus")
	require.True(status.IsSuspended(runtime.ID, epoch), "node should be suspended")
	require.EqualValues(2, status.Faults[runtime.ID].Failures, "there should be two faults")
	require.EqualValues(epoch+4, status.Faults[runtime.ID].SuspendedUntil, "suspension time should be set")

	// Bump epoch so the node is no longer suspended.
	epoch += 4

	// When node is live again, fault counter should decrease.
	rtState.LivenessStatistics.LiveRounds[0] = 91 // At least 90 required.
	err = processLivenessStatistics(ctx, epoch, rtState)
	require.NoError(err, "processLivenessStatistics")
	status, err = registryState.NodeStatus(ctx, sk.Public())
	require.NoError(err, "NodeStatus")
	require.True(status.IsSuspended(runtime.ID, epoch), "node should be suspended")
	require.EqualValues(1, status.Faults[runtime.ID].Failures, "there should be one fault")
	require.EqualValues(epoch+2, status.Faults[runtime.ID].SuspendedUntil, "suspension time should be set")

	// Bump epoch so the node is no longer suspended.
	epoch += 2

	// When node is live again, fault counter should decrease.
	rtState.LivenessStatistics.LiveRounds[0] = 91 // At least 90 required.
	err = processLivenessStatistics(ctx, epoch, rtState)
	require.NoError(err, "processLivenessStatistics")
	status, err = registryState.NodeStatus(ctx, sk.Public())
	require.NoError(err, "NodeStatus")
	require.False(status.IsSuspended(runtime.ID, epoch), "node should not be suspended")
	require.Len(status.Faults, 0, "there should be no faults")
}
