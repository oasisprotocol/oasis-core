// Package tests is a collection of epochtime implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	"github.com/oasislabs/ekiden/go/ticker/api"
)

const recvTimeout = 1 * time.Second

// TickerSetableImplementationTest exercises the basic functionality of
// a setable (mock) ticker backend.
func TickerSetableImplementationTest(t *testing.T, backend api.Backend) {
	require := require.New(t)

	// Ensure that the backend is setable.
	require.Implements((*api.SetableBackend)(nil), backend, "ticker time backend is mock")
	timeSource := (backend).(api.SetableBackend)

	tick, err := timeSource.GetTick(context.Background(), 0, 1)
	require.NoError(err, "GetTick")

	var e api.TickTime

	ch, sub := timeSource.WatchTicks(1)
	defer sub.Close()
	select {
	case e = <-ch:
		require.Equal(tick, e, "WatchTicks initial")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive current epoch on WatchTicks")
	}

	tick++
	MustAdvanceTicks(t, timeSource, 1)

	select {
	case e = <-ch:
		require.Equal(tick, e, "WatchTicks after advancing")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive epoch notification after transition")
	}

	e, err = timeSource.GetTick(context.Background(), 0, 1)
	require.NoError(err, "GetTick after set")
	require.Equal(tick, e, "GetTick after set, tick")
}

// MustAdvanceTicks advances the epoch, and returns
// the new epoch.
func MustAdvanceTicks(t *testing.T, backend api.SetableBackend, advance int) {
	require := require.New(t)

	for i := 0; i < advance; i++ {
		err := backend.DoTick(context.Background())
		require.NoError(err, "DoTick")
		_, err = backend.GetTick(context.Background(), 0, 1)
		require.NoError(err, "GetTick")
	}
}

// MustAdvanceEpoch advances the epoch, and returns the new epoch.
func MustAdvanceEpoch(t *testing.T, backend api.SetableBackend, scheduler scheduler.Backend) uint64 {
	require := require.New(t)
	ctx := context.Background()

	epoch, err := scheduler.GetEpoch(ctx, 0)
	require.NoError(err, "GetEpoch")
	// TODO: make it not get stuck
	for {
		err := backend.DoTick(ctx)
		require.NoError(err, "DoTick")

		newEpoch, nerr := scheduler.GetEpoch(ctx, 0)
		require.NoError(nerr, "GetEpoch")
		if epoch != newEpoch {
			// After epoch changed, do one more tick.
			err = backend.DoTick(ctx)
			require.NoError(err, "DoTick")
			return newEpoch
		}
	}
}
