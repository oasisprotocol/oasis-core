// Packaget tests is a collection of epochtime implementation test cases.
package tests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/epochtime/api"
)

const recvTimeout = 1 * time.Second

// EpochtimeSetableImplementationTest exercises the basic functionality of
// a setable (mock) epochtime backend.
func EpochtimeSetableImplementationTest(t *testing.T, backend api.Backend) {
	require := require.New(t)

	// Ensure that the backend is setable.
	require.Implements((*api.SetableBackend)(nil), backend, "epoch time backend is mock")
	timeSource := (backend).(api.SetableBackend)

	// Note: The tendermint_mock backend does not return elapsed,
	// and the value is to be deprecated (#1079).
	epoch, _, err := timeSource.GetEpoch(context.Background())
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
	err = timeSource.SetEpoch(context.Background(), epoch, 0)
	require.NoError(err, "SetEpoch")

	select {
	case e = <-ch:
		require.Equal(epoch, e, "WatchEpochs after set")
	case <-time.After(recvTimeout):
		t.Fatalf("failed to receive epoch notification after transition")
	}

	e, _, err = timeSource.GetEpoch(context.Background())
	require.NoError(err, "GetEpoch after set")
	require.Equal(epoch, e, "GetEpoch after set, epoch")
}
