package block

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
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

func TestVerifyStorageReceipt(t *testing.T) {
	rightNs := common.NewTestNamespaceFromSeed([]byte("receipt body verification test"), 0)
	wrongNs := common.NewTestNamespaceFromSeed([]byte("rEcEIpt bOdY vErIfIcAtIOn tEst"), 0)

	var err error

	var emptyRoot hash.Hash
	emptyRoot.Empty()

	var emptyHeaderHash hash.Hash
	_ = emptyHeaderHash.UnmarshalHex("57d73e02609a00fcf4ca43cbf8c9f12867c46942d246fb2b0bce42cbdb8db844")

	header := Header{
		Version:           1,
		Namespace:         rightNs,
		Round:             1,
		Timestamp:         1,
		HeaderType:        Normal,
		PreviousHash:      emptyHeaderHash,
		IORoot:            emptyRoot,
		StateRoot:         emptyRoot,
		MessagesHash:      emptyRoot,
		StorageSignatures: nil,
	}

	// Broken storage receipt body.
	receipt := storage.ReceiptBody{
		Version:   1,
		Namespace: wrongNs,
		Round:     2,
		RootTypes: []storage.RootType{storage.RootTypeState, storage.RootTypeIO, storage.RootTypeInvalid},
		Roots: []hash.Hash{
			emptyRoot,
			emptyRoot,
			emptyRoot,
		},
	}

	// Go through the various things the function is supposed to check, and
	// slowly fix the receipt in order to get further.

	err = header.VerifyStorageReceipt(&receipt)
	require.EqualError(t, err, "roothash: receipt has unexpected namespace", "wrong namespace")
	receipt.Namespace = rightNs

	err = header.VerifyStorageReceipt(&receipt)
	require.EqualError(t, err, "roothash: receipt has unexpected round", "wrong round")
	receipt.Round = 1

	err = header.VerifyStorageReceipt(&receipt)
	require.EqualError(t, err, "roothash: receipt has unexpected number of roots", "wrong root count")
	receipt.Roots = receipt.Roots[:2]

	err = header.VerifyStorageReceipt(&receipt)
	require.EqualError(t, err, "roothash: receipt has unexpected number of root types", "wrong root type count")
	receipt.RootTypes = receipt.RootTypes[:2]

	err = header.VerifyStorageReceipt(&receipt)
	require.EqualError(t, err, "roothash: receipt has unexpected root types", "wrong root type")
	receipt.RootTypes = []storage.RootType{storage.RootTypeIO, storage.RootTypeState}

	err = header.VerifyStorageReceipt(&receipt)
	require.NoError(t, err, "correct receipt")
}
