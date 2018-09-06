package system

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"

	"github.com/oasislabs/ekiden/go/epochtime/api"
)

func TestEpochtimeSystem(t *testing.T) {
	t.Run("Internals", testInternals)
	t.Run("APIs", testAPIs)
}

func testInternals(t *testing.T) {
	// Ensure that EKIDEN_EPOCH is sensible, and in fact, represents the
	// instant in time that it should, relative to the UNIX epoch.
	dt, err := time.Parse(time.RFC3339, "2018-01-01T00:00:00+00:00")
	require.NoError(t, err, "Parse EkidenEpoch constant")
	require.Equal(t, dt.Unix(), api.EkidenEpoch, "EkidenEpoch value")

	// EpochTime for the epoch should be 0.
	epoch, since := getEpochAt(dt, api.EpochInterval)
	assert.EqualValues(t, 0, epoch, "Epoch at EkidenEpoch")
	assert.EqualValues(t, 0, since, "Since at EkidenEpoch")

	// Ensure the epoch transitions when expected, and increments.
	dt, err = time.Parse(time.RFC3339, "2018-01-01T23:59:59+00:00")
	require.NoError(t, err, "Parse pre-increment constant")
	epoch, since = getEpochAt(dt, api.EpochInterval)
	assert.EqualValues(t, 0, epoch, "Epoch at pre-increment")
	assert.EqualValues(t, api.EpochInterval-1, since, "Since at pre-increment")

	dt, err = time.Parse(time.RFC3339, "2018-01-02T00:00:00+00:00")
	require.NoError(t, err, "Parse post-increment constant")
	epoch, since = getEpochAt(dt, api.EpochInterval)
	assert.EqualValues(t, 1, epoch, "Epoch at post-increment")
	assert.EqualValues(t, 0, since, "Since at post-increment")

	// Forbid epochs that pre-date the base.
	dt, err = time.Parse(time.RFC3339, "1997-08-29T02:14:00-04:00")
	require.NoError(t, err, "Parse invalid constant")
	assert.Panics(t, func() { getEpochAt(dt, api.EpochInterval) }, "Epoch at invalid time")
}

func testAPIs(t *testing.T) {
	const epochInterval = 1 // Second.

	timeSource, err := New(epochInterval)
	require.NoError(t, err, "New()")

	currentEpoch, _ := getEpochAt(time.Now(), epochInterval)
	epoch, _, err := timeSource.GetEpoch(context.Background())
	require.NoError(t, err, "GetEpoch()")
	require.InDelta(t, uint64(currentEpoch), uint64(epoch), 1, "GetEpoch()")

	ch, sub := timeSource.WatchEpochs()
	defer sub.Close()
	select {
	case epoch = <-ch:
		require.InDelta(t, uint64(currentEpoch), uint64(epoch), 1, "WatchEpochs() initial")
	case <-time.After(3 * time.Second):
		t.Fatalf("Failed to receive current epoch on WatchEpochs()")
	}

	time.Sleep(epochInterval * time.Second)

	select {
	case epoch = <-ch:
		require.InDelta(t, uint64(currentEpoch)+1, uint64(epoch), 1, "WatchEpochs()")
	case <-time.After(1 * time.Second):
		t.Fatalf("Failed to receive epoch notification after expected transition")
	}
}
