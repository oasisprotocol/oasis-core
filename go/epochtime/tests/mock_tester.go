// Package tests is a collection of epochtime implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/epochtime/api"
)

const recvTimeout = 5 * time.Second

// EpochtimeSetableImplementationTest exercises the basic functionality of
// a setable (mock) epochtime backend.
func EpochtimeSetableImplementationTest(t *testing.T, backend api.Backend) {
	require := require.New(t)

	// Ensure that the backend is setable.
	require.Implements((*api.SetableBackend)(nil), backend, "epoch time backend is mock")
	timeSource := (backend).(api.SetableBackend)

	epoch, err := timeSource.GetEpoch(context.Background(), 0)
	require.NoError(err, "GetEpoch")

	var e api.EpochTime

	ch, sub := timeSource.WatchEpochs()
	defer sub.Close()
	select {
	case e = <-ch:
		require.Equal(epoch, e, "WatchEpochs initial")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive current epoch on WatchEpochs")
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

	e, err = timeSource.GetEpoch(context.Background(), 0)
	require.NoError(err, "GetEpoch after set")
	require.Equal(epoch, e, "GetEpoch after set, epoch")
}

// MustAdvanceEpoch advances the epoch by the specified increment, and returns
// the new epoch.
func MustAdvanceEpoch(t *testing.T, backend api.SetableBackend, increment uint64) api.EpochTime {
	require := require.New(t)

	epoch, err := backend.GetEpoch(context.Background(), 0)
	require.NoError(err, "GetEpoch")

	epoch = epoch + api.EpochTime(increment)
	err = backend.SetEpoch(context.Background(), epoch)
	require.NoError(err, "SetEpoch")

	return epoch
}
