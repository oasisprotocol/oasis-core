package mock

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/epochtime/api"
)

func TestEpochtimeMock(t *testing.T) {
	const recvTimeout = 1 * time.Second

	timeSource := New()

	epoch, elapsed, err := timeSource.GetEpoch(context.Background())
	require.NoError(t, err, "GetEpoch()")
	require.Equal(t, api.EpochTime(0), epoch, "GetEpoch(), epoch")
	require.Equal(t, uint64(0), elapsed, "GetEpoch(), elapsed")

	ch, sub := timeSource.WatchEpochs()
	defer sub.Close()
	select {
	case epoch = <-ch:
		require.Equal(t, api.EpochTime(0), epoch, "WatchEpochs() initial")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive current epoch on WatchEpochs()")
	}

	err = timeSource.SetEpoch(context.Background(), 23, 17)
	require.NoError(t, err, "SetEpoch()")

	epoch, elapsed, err = timeSource.GetEpoch(context.Background())
	require.NoError(t, err, "GetEpoch()")
	require.Equal(t, api.EpochTime(23), epoch, "GetEpoch(), epoch")
	require.Equal(t, uint64(17), elapsed, "GetEpoch(), elapsed")

	select {
	case epoch = <-ch:
		require.Equal(t, api.EpochTime(23), epoch, "WatchEpochs()")
	case <-time.After(recvTimeout):
		t.Fatalf("Failed to receive epoch notification after transition")
	}
}
