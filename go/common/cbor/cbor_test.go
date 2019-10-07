package cbor

import (
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
