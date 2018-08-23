package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRound(t *testing.T) {
	for i, vec := range []struct {
		value   uint64
		encoded []byte
	}{
		{0xcafedeadbeeff00d, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xf0, 0x0d}},
		{0xcafedeadbeeff0, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef, 0xf0}},
		{0xcafedeadbeef, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe, 0xef}},
		{0xcafedeadbe, []byte{0xca, 0xfe, 0xde, 0xad, 0xbe}},
		{0xcafedead, []byte{0xca, 0xfe, 0xde, 0xad}},
		{0xcafede, []byte{0xca, 0xfe, 0xde}},
		{0xcafe, []byte{0xca, 0xfe}},
		{0xca, []byte{0xca}},
		{0, []byte{}},
	} {
		var round Round
		round.FromU64(vec.value)

		b, err := round.MarshalBinary()
		require.NoError(t, err, "[%d]: MarshalBinary()", i)
		require.EqualValues(t, vec.encoded, b, "[%d]: MarshalBinary()", i)

		err = round.UnmarshalBinary(vec.encoded)
		require.NoError(t, err, "[%d]: UnmarshalBinary()", i)

		v, err := round.ToU64()
		require.NoError(t, err, "[%d]: ToU64()", i)
		require.Equal(t, vec.value, v, "[%d]: ToU64()", i)
	}
}
