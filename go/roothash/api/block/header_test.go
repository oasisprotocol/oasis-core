package block

import (
	"math/big"
	"testing"
	"time"

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

func TestTimestamp(t *testing.T) {
	require := require.New(t)

	// Set local time zone to a fixed value to be able to compare the
	// marshaled time stamps across different systems and configurations.
	loc, err := time.LoadLocation("Pacific/Honolulu")
	require.NoErrorf(err, "Failed to load a fixed time zone")
	time.Local = loc

	testVectors := []struct {
		timestamp               Timestamp
		timestampString         string
		timestampStringValid    bool
		timestampStringMatching bool
		errMsg                  string
	}{
		// Valid.
		{1, "1969-12-31T14:00:01-10:00", true, true, ""},
		{1629075845, "2021-08-15T15:04:05-10:00", true, true, ""},
		{4772384038, "2121-03-25T12:13:58-10:00", true, true, ""},

		// Invalid - wrong syntax for marshalled time stamps.
		{1629075845, "2021-08-15T15:04:05Z-10:00", false, false, "parsing time \"2021-08-15T15:04:05Z-10:00\": extra text: \"-10:00\""},
		{1629032645, "2021-08-15T15:04:05+2:00", false, false, "parsing time \"2021-08-15T15:04:05+2:00\" as \"2006-01-02T15:04:05Z07:00\": cannot parse \"+2:00\" as \"Z07:00\""},

		// Invalid - not marshaled using the correct time zone.
		{1629039845, "2021-08-15T15:04:05Z", true, false, ""},
		{1629032645, "2021-08-15T15:04:05+02:00", true, false, ""},
	}

	for _, v := range testVectors {
		var unmarshaledTimestamp Timestamp
		err := unmarshaledTimestamp.UnmarshalText([]byte(v.timestampString))
		if !v.timestampStringValid {
			require.EqualErrorf(
				err,
				v.errMsg,
				"Unmarshaling invalid time stamp: '%s' should fail with expected error message",
				v.timestampString,
			)
		} else {
			require.NoErrorf(err, "Failed to unmarshal a valid time stamp: '%s'", v.timestampString)
			require.Equalf(
				v.timestamp,
				unmarshaledTimestamp,
				"Unmarshaled time stamp doesn't equal expected time stamp: %s %#s", v.timestamp, unmarshaledTimestamp,
			)
		}

		textTimestamp, err := v.timestamp.MarshalText()
		require.NoError(err, "Failed to marshal a valid time stamp: '%s'", v.timestamp)
		if v.timestampStringMatching {
			require.Equal(
				v.timestampString,
				string(textTimestamp),
				"Marshaled time stamp doesn't equal expected text time stamp",
			)
		} else {
			require.NotEqual(
				v.timestampString,
				string(textTimestamp),
				"Marshaled time stamp shouldn't equal the expected text time stamp for invalid test cases",
			)
		}
	}
}
