package epochtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSystemTimeSourceInternal(t *testing.T) {
	// Ensure that EKIDEN_EPOCH is sensible, and in fact, represents the
	// instant in time that it should, relative to the UNIX epoch.
	dt, err := time.Parse(time.RFC3339, "2018-01-01T00:00:00+00:00")
	require.NoError(t, err, "Parse EkidenEpoch constant")
	require.Equal(t, dt.Unix(), EkidenEpoch, "EkidenEpoch value")

	// EpochTime for the epoch should be 0.
	epoch, since := getEpochAt(dt)
	assert.EqualValues(t, 0, epoch, "Epoch at EkidenEpoch")
	assert.EqualValues(t, 0, since, "Since at EkidenEpoch")

	// Ensure the epoch transitions when expected, and increments.
	dt, err = time.Parse(time.RFC3339, "2018-01-01T23:59:59+00:00")
	require.NoError(t, err, "Parse pre-increment constant")
	epoch, since = getEpochAt(dt)
	assert.EqualValues(t, 0, epoch, "Epoch at pre-increment")
	assert.EqualValues(t, EpochInterval-1, since, "Since at pre-increment")

	dt, err = time.Parse(time.RFC3339, "2018-01-02T00:00:00+00:00")
	require.NoError(t, err, "Parse post-increment constant")
	epoch, since = getEpochAt(dt)
	assert.EqualValues(t, 1, epoch, "Epoch at post-increment")
	assert.EqualValues(t, 0, since, "Since at post-increment")

	// Forbid epochs that pre-date the base.
	dt, err = time.Parse(time.RFC3339, "1997-08-29T02:14:00-04:00")
	require.NoError(t, err, "Parse invalid constant")
	assert.Panics(t, func() { getEpochAt(dt) }, "Epoch at invalid time")
}
