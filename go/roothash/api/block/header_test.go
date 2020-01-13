package block

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/quantity"
)

func TestConsistentHash(t *testing.T) {
	// NOTE: These hashes MUST be synced with runtime/src/common/roothash.rs.
	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("727b8c92cd436abc597df9ccbe3a02eeba8d7409cc68fcdf0ce3b577450631ac")

	var empty Header
	require.EqualValues(t, emptyHeaderHash, empty.EncodedHash())

	var populatedHeaderHash hash.Hash
	_ = populatedHeaderHash.UnmarshalHex("c39e8aefea5a1f794fb57f294a4ea8599381cd8739e67a8a9acb7763b54a630a")

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
		Messages:     nil,
	}
	require.EqualValues(t, populatedHeaderHash.String(), populated.EncodedHash().String())
}
