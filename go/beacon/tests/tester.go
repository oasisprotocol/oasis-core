// Package tests is a collection of beacon implementation test cases.
package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/beacon/api"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	ticker "github.com/oasislabs/ekiden/go/ticker/api"
	tickerTests "github.com/oasislabs/ekiden/go/ticker/tests"
)

// BeaconImplementationTests exercises the basic functionality of a
// beacon backend.
func BeaconImplementationTests(t *testing.T, backend api.Backend, ticker ticker.SetableBackend, scheduler scheduler.Backend) {
	require := require.New(t)

	beacon, err := backend.GetBeacon(context.Background(), 0)
	require.NoError(err, "GetBeacon")
	require.Len(beacon, api.BeaconSize, "GetBeacon - length")

	tickerTests.MustAdvanceEpoch(t, ticker, scheduler)

	newBeacon, err := backend.GetBeacon(context.Background(), 0)
	require.NoError(err, "GetBeacon")
	require.Len(newBeacon, api.BeaconSize, "GetBeacon - length")
	require.NotEqual(beacon, newBeacon, "After epoch transition, new beacon should be generated.")
}
