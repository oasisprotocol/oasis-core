// Package tests is a collection of beacon implementation test cases.
package tests

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/beacon/api"
	epochtime "github.com/oasislabs/ekiden/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/ekiden/go/epochtime/tests"
)

const recvTimeout = 1 * time.Second

// BeaconImplementationTests exercises the basic functionality of a
// beacon backend.
func BeaconImplementationTests(t *testing.T, backend api.Backend, epochtime epochtime.SetableBackend) {
	require := require.New(t)

	epoch, err := epochtime.GetEpoch(context.Background(), 0)
	require.NoError(err, "GetEpoch")

	ch, sub := backend.WatchBeacons()
	defer sub.Close()

recvLoop:
	for {
		select {
		case ev := <-ch:
			// Skip the old beacon.
			if ev.Epoch < epoch {
				continue
			}
			require.Equal(epoch, ev.Epoch, "WatchBeacons - epoch")
			require.Len(ev.Beacon, api.BeaconSize, "WatchBeacons - length")

			var b []byte
			b, err = backend.GetBeacon(context.Background(), 0)
			require.NoError(err, "GetBeacon")
			require.Equal(b, ev.Beacon, "GetBeacon - beacon")
			break recvLoop
		case <-time.After(recvTimeout):
			t.Fatalf("failed to receive current beacon on WatchBeacons")
		}
	}

	epoch = epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	select {
	case ev := <-ch:
		require.Equal(epoch, ev.Epoch, "WatchBeacons - epoch")
		require.Len(ev.Beacon, api.BeaconSize, "WatchBeacons - length")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive current beacon after transition")
	}
}
