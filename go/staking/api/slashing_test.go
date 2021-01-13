package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSlashReason(t *testing.T) {
	require := require.New(t)

	// Test valid SlashReasons.
	for _, k := range []SlashReason{
		SlashConsensusEquivocation,
		SlashRuntimeIncorrectResults,
		SlashRuntimeEquivocation,
	} {
		enc, err := k.MarshalText()
		require.NoError(err, "MarshalText")

		var s SlashReason
		err = s.UnmarshalText(enc)
		require.NoError(err, "UnmarshalText")

		require.Equal(k, s, "slash reason should round-trip")
	}

	// Test invalid SlashReasons.
	sr := SlashReason(0xff)
	require.Equal("[unknown slash reason]", sr.String())
	enc, err := sr.MarshalText()
	require.Nil(enc, "MarshalText on invalid slash reason should be nil")
	require.Error(err, "MarshalText on invalid slash reason should error")

	err = sr.UnmarshalText([]byte("invalid slash reason"))
	require.Error(err, "UnmarshalText on invalid slash reason should error")
}
