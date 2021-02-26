package keyformat

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestHashed(t *testing.T) {
	require := require.New(t)

	var pk signature.PublicKey
	err := pk.UnmarshalHex("47aadd91516ac548decdb436fde957992610facc09ba2f850da0fe1b2be96119")
	require.NoError(err, "UnmarshalHex")

	var ns common.Namespace

	fmt1 := New(0x42, uint64(0), H(&common.Namespace{}), H(&signature.PublicKey{}))
	require.Equal(1+8+32+32, fmt1.Size())

	// Make sure both keys have been hashed.
	enc := fmt1.Encode(uint64(42), &ns, &pk)
	require.Equal("42000000000000002aaf13c048991224a5e4c664446b688aaf48fb5456db3629601b00ec160c74e55477df373036881e67c7b0079f8c062d6634e4bab9581a532210228bc4118baf45", hex.EncodeToString(enc))

	var (
		decInt         uint64
		decNs          common.Namespace
		decPk          signature.PublicKey
		decPh1, decPh2 PreHashed
	)
	ok := fmt1.Decode(enc, &decInt)
	require.True(ok, "Decode")
	require.EqualValues(42, decInt, "decoded uint64 value must be correct")

	require.False(fmt1.Decode(enc, &decInt, &decNs))
	require.False(fmt1.Decode(enc, &decInt, &decPh1, &decPk))

	ok = fmt1.Decode(enc, &decInt, &decPh1, &decPh2)
	require.True(ok, "Decode")
	require.EqualValues(42, decInt, "decoded uint64 value must be correct")
	require.Equal("af13c048991224a5e4c664446b688aaf48fb5456db3629601b00ec160c74e554", hex.EncodeToString(decPh1[:]))
	require.Equal("77df373036881e67c7b0079f8c062d6634e4bab9581a532210228bc4118baf45", hex.EncodeToString(decPh2[:]))

	// Make sure we can correctly encode with prehashed values.
	enc2 := fmt1.Encode(uint64(42), &decPh1, &decPh2)
	require.EqualValues(enc, enc2, "encoding with pre-hashed values must produce correct results")

	// Make sure we can encode variable-length bytes.
	fmt2 := New(0x43, uint64(0), H([]byte{}))
	require.Equal(1+8+32, fmt2.Size())

	enc = fmt2.Encode(uint64(42), []byte("hello world"))
	require.Equal("43000000000000002a0ac561fac838104e3f2e4ad107b4bee3e938bf15f2b15f009ccccd61a913f017", hex.EncodeToString(enc))

	ok = fmt2.Decode(enc, &decInt, &decPh1)
	require.True(ok, "Decode")
	require.Equal("0ac561fac838104e3f2e4ad107b4bee3e938bf15f2b15f009ccccd61a913f017", hex.EncodeToString(decPh1[:]))

	var decBytes []byte
	require.False(fmt2.Decode(enc, &decInt, &decBytes))
}
