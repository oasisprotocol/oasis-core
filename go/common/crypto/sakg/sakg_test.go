package sakg

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestGetAccountSigner(t *testing.T) {
	require := require.New(t)

	testVectors := []struct { // nolint: maligned
		mnemonic             string
		passphrase           string
		number               uint32
		expectedPubkeyHex    string
		expectedBIP32PathStr string
		valid                bool
		errMsg               string
	}{
		// Valid.
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"",
			0,
			"ad55bbb7c192b8ecfeb6ad18bbd7681c0923f472d5b0c212fbde33008005ad61",
			"m/44'/474'/0'",
			true,
			"",
		},
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"",
			1,
			"73fd7c51a0f059ea34d8dca305e0fdb21134ca32216ca1681ae1d12b3d350e16",
			"m/44'/474'/1'",
			true,
			"",
		},
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"",
			MaxAccountKeyNumber,
			"9e7c2b2d03265ce4ea175e3664a678182548a7fc6db04801513cff7c98c8f151",
			fmt.Sprintf("m/44'/474'/%d'", MaxAccountKeyNumber),
			true,
			"",
		},
		{
			"equip will roof matter pink blind book anxiety banner elbow sun young",
			"p4ssphr4se",
			1,
			"b099f8906467325aa1283590c1bca01e8708d5419557aa7771b826fa02d2abe6",
			"m/44'/474'/1'",
			true,
			"",
		},

		// Invalid.
		{
			"foo bar baz",
			"",
			0,
			"",
			"",
			false,
			"sakg: invalid mnemonic",
		},
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"",
			MaxAccountKeyNumber + 1,
			"",
			"",
			false,
			"sakg: invalid key number: 2147483648 (maximum: 2147483647)",
		},
	}

	for _, v := range testVectors {
		signer, actualBIP32Path, err := GetAccountSigner(v.mnemonic, v.passphrase, v.number)
		if !v.valid {
			require.EqualError(err, v.errMsg, "Generating signer for invalid inputs should fail with expected error message")
			continue
		}
		require.NoErrorf(
			err,
			"Failed to generate signer for:\n- mnemonic: '%s'\n- passphrase: '%s'\n- number: %d\n",
			v.mnemonic,
			v.passphrase,
			v.number,
		)
		// Check generated signer's public key.
		var expectedPK signature.PublicKey
		_ = expectedPK.UnmarshalHex(v.expectedPubkeyHex)
		require.Equal(expectedPK, signer.Public(), "Generated signer's public key doesn't equal expected public key")
		// Check generated signer's BIP-0032 path.
		actualBIP32PathText, _ := actualBIP32Path.MarshalText()
		require.Equal(
			v.expectedBIP32PathStr,
			string(actualBIP32PathText),
			"Generated signer's BIP-0032 path doesn't equal expected BIP-0032 path",
		)
	}
}
