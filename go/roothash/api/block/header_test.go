package block

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestConsistentHash(t *testing.T) {
	// NOTE: These hashes MUST be synced with runtime/src/common/roothash.rs.
	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("f7f340550630426b4962c3054cb7f21cf3662bd916642daff4efc9a00b4aab3f")

	var empty Header
	require.EqualValues(t, emptyHeaderHash.String(), empty.EncodedHash().String())

	var populatedHeaderHash hash.Hash
	_ = populatedHeaderHash.UnmarshalHex("e5f8d6958fdedf15e705cb8fc8e2515d870c79d80dd2fa17f35c9e307ca4215a")

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var ns common.Namespace
	_ = ns.UnmarshalBinary(emptyRoot[:])

	var account signature.PublicKey
	require.NoError(t, account.UnmarshalHex("5555555555555555555555555555555555555555555555555555555555555555"), "PublicKey UnmarshalHex")

	var amount quantity.Quantity
	require.NoError(t, amount.FromBigInt(big.NewInt(69376)), "Quantity FromBigInt")

	populated := Header{
		Version:      42,
		Namespace:    ns,
		Round:        1000,
		Timestamp:    1560257841,
		HeaderType:   RoundFailed,
		PreviousHash: emptyHeaderHash,
		IORoot:       emptyRoot,
		StateRoot:    emptyRoot,
		MessagesHash: emptyRoot,
	}
	require.EqualValues(t, populatedHeaderHash.String(), populated.EncodedHash().String())
}
