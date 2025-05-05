// Package tests is a collection of beacon implementation test cases.
package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensusAPI "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

const recvTimeout = 5 * time.Second

// TestSigner is a test signer used for setting epochs in tests.
var TestSigner = memorySigner.NewTestSigner("oasis-core epochtime mock key seed")

// BeaconImplementationTests exercises the basic functionality of a
// beacon backend.
func BeaconImplementationTests(t *testing.T, consensus consensusAPI.Service) {
	require := require.New(t)

	timeSource := consensus.Beacon()

	beacon, err := timeSource.GetBeacon(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetBeacon")
	require.Len(beacon, api.BeaconSize, "GetBeacon - length")

	_ = MustAdvanceEpoch(t, consensus)

	newBeacon, err := timeSource.GetBeacon(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetBeacon")
	require.Len(newBeacon, api.BeaconSize, "GetBeacon - length")
	require.NotEqual(beacon, newBeacon, "After epoch transition, new beacon should be generated.")

	latestEpoch, err := timeSource.GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	// Querying epoch for a non-existing height should fail.
	_, err = timeSource.GetEpoch(context.Background(), 100000000000)
	require.ErrorIs(err, consensusAPI.ErrVersionNotFound, "GetEpoch should fail for non-existing height")

	var lastHeight int64
	for epoch := api.EpochTime(0); epoch <= latestEpoch; epoch++ {
		height, err := timeSource.GetEpochBlock(context.Background(), epoch)
		require.NoError(err, "GetEpochBlock")
		require.True(height > lastHeight)
		lastHeight = height
	}
}

// EpochtimeSetableImplementationTest exercises the basic functionality of
// a setable (mock) epochtime backend.
func EpochtimeSetableImplementationTest(t *testing.T, consensus consensusAPI.Service) {
	require := require.New(t)

	timeSource := consensus.Beacon()

	parameters, err := timeSource.ConsensusParameters(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "ConsensusParameters")
	require.True(parameters.DebugMockBackend, "expected debug backend")

	epoch, err := timeSource.GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	var e api.EpochTime

	ch, sub, err := timeSource.WatchEpochs(context.Background())
	require.NoError(err, "WatchEpochs")
	defer sub.Close()
	select {
	case e = <-ch:
		require.Equal(epoch, e, "WatchEpochs initial")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive current epoch on WatchEpochs")
	}

	latestCh, subCh, err := timeSource.WatchLatestEpoch(context.Background())
	require.NoError(err, "WatchLatestEpoch")
	defer subCh.Close()
	select {
	case e = <-latestCh:
		require.Equal(epoch, e, "WatchLatestEpoch initial")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive current epoch on WatchLatestEpoch")
	}

	epoch++
	err = SetEpoch(context.Background(), epoch, consensus)
	require.NoError(err, "SetEpoch")

	select {
	case e = <-ch:
		require.Equal(epoch, e, "WatchEpochs after set")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive epoch notification after transition")
	}

	select {
	case e = <-latestCh:
		require.Equal(epoch, e, "WatchLatestEpoch after set")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive latest epoch after transition")
	}

	e, err = timeSource.GetEpoch(context.Background(), consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch after set")
	require.Equal(epoch, e, "GetEpoch after set, epoch")
}

// MustAdvanceEpoch advances the epoch and returns the new epoch.
func MustAdvanceEpoch(t *testing.T, consensus consensusAPI.Service) api.EpochTime {
	require := require.New(t)

	timeSource := consensus.Beacon()

	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	epoch, err := timeSource.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	// While using a timeout here would be nice, the correct timeout value
	// depends on the block interval and all the various internal timekeeping
	// periods so it's not easy to set one.
	epoch++
	err = SetEpoch(context.Background(), epoch, consensus)
	require.NoError(err, "SetEpoch")

	return epoch
}

// MustAdvanceEpochMulti advances the epoch by the specified increment, and returns
// the new epoch.
// Between each epoch increment the method ensures that the consensus validator is re-registered
// so that epochs are not advanced too fast, which could cause a consensus error due to no
// validators being registered for the epoch.
func MustAdvanceEpochMulti(t *testing.T, consensus consensusAPI.Service, increment uint64) api.EpochTime {
	require := require.New(t)

	timeSource := consensus.Beacon()
	registry := consensus.Registry()

	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	epoch, err := timeSource.GetEpoch(ctx, consensusAPI.HeightLatest)
	require.NoError(err, "GetEpoch")

	// While using a timeout here would be nice, the correct timeout value
	// depends on the block interval and all the various internal timekeeping
	// periods so it's not easy to set one.
	for i := uint64(0); i < increment; i++ {
		epoch++

		// Used to ensure validator re-registers after the epoch transition.
		ch, sub, err := registry.WatchNodes(context.Background())
		require.NoError(err, "WatchNodes")
		defer sub.Close()

		// While using a timeout here would be nice, the correct timeout value
		// depends on the block interval and all the various internal timekeeping
		// periods so it's not easy to set one.
		err = SetEpoch(context.Background(), epoch, consensus)
		require.NoError(err, "SetEpoch")

		// Ensure validator re-registers before transitioning to next epoch.
	EVENTS:
		for {
			select {
			case nd := <-ch:
				if !nd.IsRegistration {
					continue
				}
				if !nd.Node.HasRoles(node.RoleValidator) {
					continue
				}
				if nd.Node.Expiration > uint64(epoch+1) {
					break EVENTS
				}
			case <-time.After(recvTimeout):
				t.Fatal("failed to receive node registration event")
			}
		}
	}

	return epoch
}

// SetEpoch sets the current epoch.
func SetEpoch(ctx context.Context, epoch api.EpochTime, consensus consensusAPI.Service) error {
	ch, sub, err := consensus.Beacon().WatchEpochs(ctx)
	if err != nil {
		return fmt.Errorf("watch epochs failed: %w", err)
	}
	defer sub.Close()

	tx := transaction.NewTransaction(0, nil, api.MethodSetEpoch, epoch)
	if err := consensusAPI.SignAndSubmitTx(ctx, consensus, TestSigner, tx); err != nil {
		return fmt.Errorf("set epoch failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case newEpoch, ok := <-ch:
			if !ok {
				return context.Canceled
			}
			if newEpoch == epoch {
				return nil
			}
		}
	}
}
