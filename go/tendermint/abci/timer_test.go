package abci

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSerializationRoundTripProblem(t *testing.T) {
	// WARNING: time.Unix uses local time, the test cases are in UTC.
	// The Equal method used will handle timezones for us.

	// First case: 2018-11-12 04:37:37.999999748 +0000. Serialization round trip
	// causes the timestamp to change due to loss of precision.
	//
	// The new codec library can store time as RFC 3339 strings (no loss of
	// precision), or second-granular UNIX timestamps.  We use the latter.
	//
	// This was due to go codec originally serializing to CBOR floats if
	// nanoseconds are present.
	timer := &timerState{
		ID:       "test",
		App:      "test",
		Armed:    true,
		Deadline: time.Date(2018, 11, 12, 4, 37, 37, 999999748, time.UTC),
	}

	data := timer.MarshalCBOR()

	var deserialized timerState
	require.NoError(t, deserialized.UnmarshalCBOR(data), "Unmarshal")
	require.False(t, timer.Deadline.Equal(deserialized.Deadline), "Deadline should differ")

	// Second case: 2018-11-12 04:37:37.000 +0000. Serialization round trip preserves
	// the timestamp.
	timer = &timerState{
		ID:       "test",
		App:      "test",
		Armed:    true,
		Deadline: time.Date(2018, 11, 12, 4, 37, 37, 0, time.UTC),
	}

	data = timer.MarshalCBOR()

	var deserialized2 timerState
	require.NoError(t, deserialized2.UnmarshalCBOR(data), "Unmarshal")
	require.True(t, timer.Deadline.Equal(deserialized2.Deadline), "Deadline should not differ")
}

func TestGetDeadlineMapKey(t *testing.T) {
	timer := &timerState{
		ID:       "test",
		App:      "test",
		Armed:    true,
		Deadline: time.Date(2018, 11, 12, 4, 37, 37, 999999748, time.UTC),
	}

	require.PanicsWithValue(
		t,
		"getDeadlineMapKey: deadline must be rounded to the nearest second",
		func() { timer.getDeadlineMapKey() },
	)

	timer = &timerState{
		ID:       "test",
		App:      "test",
		Armed:    true,
		Deadline: time.Date(2018, 11, 12, 4, 37, 37, 0, time.UTC),
	}

	require.EqualValues(t, timer.getDeadlineMapKey(), []byte("timers/deadline/1541997457/test"))
}
