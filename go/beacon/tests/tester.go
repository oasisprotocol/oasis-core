// Package tests is a collection of beacon implementation test cases.
package tests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/beacon/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	epochtimeTests "github.com/oasislabs/oasis-core/go/epochtime/tests"
)

// BeaconImplementationTests exercises the basic functionality of a
// beacon backend.
func BeaconImplementationTests(t *testing.T, backend api.Backend, epochtime epochtime.SetableBackend) {
	require := require.New(t)

	beacon, err := backend.GetBeacon(context.Background(), 0)
	require.NoError(err, "GetBeacon")
	require.Len(beacon, api.BeaconSize, "GetBeacon - length")

	_ = epochtimeTests.MustAdvanceEpoch(t, epochtime, 1)

	newBeacon, err := backend.GetBeacon(context.Background(), 0)
	require.NoError(err, "GetBeacon")
	require.Len(newBeacon, api.BeaconSize, "GetBeacon - length")
	require.NotEqual(beacon, newBeacon, "After epoch transition, new beacon should be generated.")
}
