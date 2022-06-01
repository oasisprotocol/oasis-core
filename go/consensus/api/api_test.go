package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConsensusMode(t *testing.T) {
	require := require.New(t)

	// Test valid Modes.
	for _, k := range []Mode{
		ModeArchive,
		ModeFull,
		ModeSeed,
	} {
		enc, err := k.MarshalText()
		require.NoError(err, "MarshalText")

		var s Mode
		err = s.UnmarshalText(enc)
		require.NoError(err, "UnmarshalText")

		require.Equal(k, s, "consensus mode should round-trip")
	}

	// Test invalid Mode.
	sr := Mode("abc")
	require.Equal("[unknown consensus mode: abc]", sr.String())
	enc, err := sr.MarshalText()
	require.Nil(enc, "MarshalText on invalid consensus mode should be nil")
	require.Error(err, "MarshalText on invalid consensus mode should error")

	err = sr.UnmarshalText([]byte("invalid consensus mode"))
	require.Error(err, "UnmarshalText on invalid consensus mode should error")
}
