// Package tests is a collection of beacon implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const recvTimeout = 5 * time.Second

// BeaconImplementationTests exercises the basic functionality of a
// beacon backend.
func BeaconImplementationTests(t *testing.T, backend api.SetableBackend) {
	require := require.New(t)

	beacon, err := backend.GetBeacon(context.Background(), consensus.HeightLatest)
	require.NoError(err, "GetBeacon")
	require.Len(beacon, api.BeaconSize, "GetBeacon - length")

	_ = MustAdvanceEpoch(t, backend)

	newBeacon, err := backend.GetBeacon(context.Background(), consensus.HeightLatest)
	require.NoError(err, "GetBeacon")
	require.Len(newBeacon, api.BeaconSize, "GetBeacon - length")
	require.NotEqual(beacon, newBeacon, "After epoch transition, new beacon should be generated.")
}

// EpochtimeSetableImplementationTest exercises the basic functionality of
// a setable (mock) epochtime backend.
func EpochtimeSetableImplementationTest(t *testing.T, backend api.Backend) {
	require := require.New(t)

	// Ensure that the backend is setable.
	require.Implements((*api.SetableBackend)(nil), backend, "epoch time backend is mock")
	timeSource := (backend).(api.SetableBackend)

	parameters, err := backend.ConsensusParameters(context.Background(), consensus.HeightLatest)
	require.NoError(err, "ConsensusParameters")
	require.True(parameters.DebugMockBackend, "expected debug backend")

	epoch, err := timeSource.GetEpoch(context.Background(), consensus.HeightLatest)
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
	err = timeSource.SetEpoch(context.Background(), epoch)
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

	e, err = timeSource.GetEpoch(context.Background(), consensus.HeightLatest)
	require.NoError(err, "GetEpoch after set")
	require.Equal(epoch, e, "GetEpoch after set, epoch")
}

// MustAdvanceEpoch advances the epoch and returns the new epoch.
func MustAdvanceEpoch(t *testing.T, backend api.SetableBackend) api.EpochTime {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	epoch, err := backend.GetEpoch(ctx, consensus.HeightLatest)
	require.NoError(err, "GetEpoch")

	// While using a timeout here would be nice, the correct timeout value
	// depends on the block interval and all the various internal timekeeping
	// periods so it's not easy to set one.
	epoch++
	err = backend.SetEpoch(context.Background(), epoch)
	require.NoError(err, "SetEpoch")

	return epoch
}

// MustAdvanceEpochMulti advances the epoch by the specified increment, and returns
// the new epoch.
// Between each epoch increment the method ensures that the consensus validator is re-registered
// so that epochs are not advanced too fast, which could cause a consensus error due to no
// validators being registered for the epoch.
func MustAdvanceEpochMulti(t *testing.T, backend api.SetableBackend, reg registry.Backend, increment uint64) api.EpochTime {
	require := require.New(t)

	ctx, cancel := context.WithTimeout(context.Background(), recvTimeout)
	defer cancel()

	epoch, err := backend.GetEpoch(ctx, consensus.HeightLatest)
	require.NoError(err, "GetEpoch")

	// While using a timeout here would be nice, the correct timeout value
	// depends on the block interval and all the various internal timekeeping
	// periods so it's not easy to set one.
	for i := uint64(0); i < increment; i++ {
		epoch++

		// Used to ensure validator re-registers after the epoch transition.
		ch, sub, err := reg.WatchNodes(context.Background())
		require.NoError(err, "WatchNodes")
		defer sub.Close()

		// While using a timeout here would be nice, the correct timeout value
		// depends on the block interval and all the various internal timekeeping
		// periods so it's not easy to set one.
		err = backend.SetEpoch(context.Background(), epoch)
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
