package transaction

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadWriteSetSerialization(t *testing.T) {
	rwSet := ReadWriteSet{
		Granularity: 3,
		ReadSet:     CoarsenedSet{[]byte("foo"), []byte("bar")},
		WriteSet:    CoarsenedSet{[]byte("moo")},
	}

	enc := rwSet.MarshalCBOR()

	var decRwSet ReadWriteSet
	err := decRwSet.UnmarshalCBOR(enc)
	require.NoError(t, err, "serialization should round-trip")
	require.EqualValues(t, rwSet, decRwSet, "serialization should round-trip")
	require.True(t, decRwSet.Equal(&rwSet), "Equal should return true")
}
