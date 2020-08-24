package keyformat

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
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

	fmt2 := New('L', &common.Namespace{}, uint64(0), int64(0), &hash.Hash{}, &hash.Hash{})
	require.Equal(t, 1+32+8+8+32+32, fmt2.Size())

	h.FromBytes([]byte("hash one"))
	var h2 hash.Hash
	h2.FromBytes([]byte("hash two"))
	intVal := uint64(42)
	intVal2 := int64(-17)
	enc = fmt2.Encode(&ns, intVal, intVal2, &h, &h2)

	var (
		decNs2     common.Namespace
		decIntVal  uint64
		decIntVal2 int64
		decH2      hash.Hash
	)
	ok = fmt2.Decode(enc, &decNs, &decIntVal, &decIntVal2, &decH, &decH2)
	require.True(t, ok, "Decode")
	require.EqualValues(t, ns, decNs2, "namespace encode/decode round trip")
	require.EqualValues(t, intVal, decIntVal, "uint64 encode/decode round trip")
	require.EqualValues(t, intVal2, decIntVal2, "int64 encode/decode round trip")
	require.EqualValues(t, h, decH, "hash encode/decode round trip")
	require.EqualValues(t, h2, decH2, "hash encode/decode round trip")

	// Test with incorrect key type.
	ok = fmt1.Decode(enc, &decNs, &decH)
	require.False(t, ok, "Decode")
}

func TestPublicKey(t *testing.T) {
	fmt := New('S', &signature.PublicKey{})
	require.Equal(t, 1+32, fmt.Size(), "format size")

	var pk signature.PublicKey
	err := pk.UnmarshalHex("47aadd91516ac548decdb436fde957992610facc09ba2f850da0fe1b2be96119")
	require.NoError(t, err, "UnmarshalHex")

	enc := fmt.Encode(&pk)

	var decPk signature.PublicKey
	ok := fmt.Decode(enc, &decPk)
	require.True(t, ok, "Decode")
	require.EqualValues(t, pk, decPk, "decoded public key must be correct")
}

func TestVariableSize(t *testing.T) {
	// Should panic if more than one variable-size element is specified.
	require.Panics(t, func() {
		New('T', []byte{}, []byte{}, &hash.Hash{})
	}, "New should panic with more than one variable-size element")

	// Create a simple key format with a variable-size element at the
	// beginning.
	fmt1 := New('T', []byte{}, &hash.Hash{})
	require.Equal(t, 1+32, fmt1.Size(), "minimum format size should be correct")

	vsElem := []byte("variable-sized element")
	var h hash.Hash
	h.Empty()

	enc := fmt1.Encode(vsElem, &h)
	require.Equal(t, "547661726961626c652d73697a656420656c656d656e74c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", hex.EncodeToString(enc))

	var decVs []byte
	var decH hash.Hash
	ok := fmt1.Decode(enc, &decVs, &decH)
	require.True(t, ok, "decode should succeed")
	require.EqualValues(t, vsElem, decVs, "decoded variable-sized element should have the same value")
	require.EqualValues(t, h, decH, "decoded hash should have the same value")

	var decVs2 []byte
	ok = fmt1.Decode(enc, &decVs2)
	require.True(t, ok, "decode should succeed")
	require.EqualValues(t, vsElem, decVs, "decoded variable-sized element should have the same value")

	// Create a simple key format with a variable-size element in the
	// middle.
	fmt2 := New('T', &hash.Hash{}, []byte{}, &hash.Hash{})
	require.Equal(t, 1+32+32, fmt2.Size(), "minimum format size should be correct")

	enc = fmt2.Encode(&h, vsElem, &h)
	require.Equal(t, "54c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a7661726961626c652d73697a656420656c656d656e74c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a", hex.EncodeToString(enc))

	var decH3, decH4 hash.Hash
	var decVs3 []byte
	ok = fmt2.Decode(enc, &decH3, &decVs3, &decH4)
	require.True(t, ok, "decode should succeed")
	require.EqualValues(t, h, decH3, "decoded hash should have the same value")
	require.EqualValues(t, vsElem, decVs3, "decoded variable-sized element should have the same value")
	require.EqualValues(t, h, decH4, "decoded hash should have the same value")
}
