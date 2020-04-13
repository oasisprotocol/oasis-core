package cbor

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOutOfMem1(t *testing.T) {
	require := require.New(t)

	var f []byte
	err := Unmarshal([]byte("\x9b\x00\x00000000"), f)
	require.Error(err, "Invalid CBOR input should fail")
}

func TestOutOfMem2(t *testing.T) {
	require := require.New(t)

	var f []byte
	err := Unmarshal([]byte("\x9b\x00\x00\x81112233"), f)
	require.Error(err, "Invalid CBOR input should fail")
}

func TestEncoderDecoder(t *testing.T) {
	require := require.New(t)

	var buf bytes.Buffer
	enc := NewEncoder(&buf)
	err := enc.Encode(42)
	require.NoError(err, "Encode")

	var x int
	dec := NewDecoder(&buf)
	err = dec.Decode(&x)
	require.NoError(err, "Decode")
	require.EqualValues(42, x, "decoded value should be correct")
}
