package node

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDepth(t *testing.T) {
	require.Equal(t, 0, Depth(0).ToBytes())
	require.Equal(t, 2, Depth(16).ToBytes())
	require.Equal(t, 3, Depth(17).ToBytes())

	var dt Depth
	require.Equal(t, []byte{0x0a, 0x00}, Depth(10).MarshalBinary())
	_, err := dt.UnmarshalBinary([]byte{0x0a, 0x00})
	require.NoError(t, err, "UnmarshalBinary")
	require.Equal(t, Depth(10), dt)

	require.Equal(t, []byte{0x04, 0x01}, Depth(260).MarshalBinary())
	_, err = dt.UnmarshalBinary([]byte{0x04, 0x01})
	require.NoError(t, err, "UnmarshalBinary")
	require.Equal(t, Depth(260), dt)
}
