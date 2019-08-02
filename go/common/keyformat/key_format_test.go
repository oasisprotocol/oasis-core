package keyformat

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
)

func TestKeyFormat(t *testing.T) {
	fmt1 := New('N', &common.Namespace{}, &hash.Hash{})
	require.Equal(t, 1+32+32, fmt1.Size(), "format size")

	var ns common.Namespace
	var h hash.Hash
	h.Empty()

	// Test generating only a prefix of the full key.
	enc := fmt1.Encode(&ns)
	require.Equal(t, "4e0000000000000000000000000000000000000000000000000000000000000000", hex.EncodeToString(enc))
	enc = fmt1.Encode()
	require.Equal(t, "4e", hex.EncodeToString(enc))

	// Test full encode.
	enc = fmt1.Encode(&ns, &h)
	require.Equal(t, "4e0000000000000000000000000000000000000000000000000000000000000000c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", hex.EncodeToString(enc))

	var decNs common.Namespace
	var decH hash.Hash
	ok := fmt1.Decode(enc, &decNs, &decH)
	require.True(t, ok, "Decode")
	require.EqualValues(t, ns, decNs, "namespace encode/decode round trip")
	require.EqualValues(t, h, decH, "hash encode/decode round trip")

	fmt2 := New('L', &common.Namespace{}, uint64(0), &hash.Hash{}, &hash.Hash{})
	require.Equal(t, 1+32+8+32+32, fmt2.Size())

	h.FromBytes([]byte("hash one"))
	var h2 hash.Hash
	h2.FromBytes([]byte("hash two"))
	intVal := uint64(42)
	enc = fmt2.Encode(&ns, intVal, &h, &h2)

	var decNs2 common.Namespace
	var decIntVal uint64
	var decH2 hash.Hash
	ok = fmt2.Decode(enc, &decNs, &decIntVal, &decH, &decH2)
	require.True(t, ok, "Decode")
	require.EqualValues(t, ns, decNs2, "namespace encode/decode round trip")
	require.EqualValues(t, intVal, decIntVal, "uint64 encode/decode round trip")
	require.EqualValues(t, h, decH, "hash encode/decode round trip")
	require.EqualValues(t, h2, decH2, "hash encode/decode round trip")

	// Test with incorrect key type.
	ok = fmt1.Decode(enc, &decNs, &decH)
	require.False(t, ok, "Decode")
}
