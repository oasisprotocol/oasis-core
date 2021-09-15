package bech32

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBIP173(t *testing.T) {
	require := require.New(t)

	testVectors := []struct {
		str    string
		valid  bool
		errMsg string
	}{
		// Reference test vectors from BIP 173:
		// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#test-vectors
		{"A12UEL5L", true, ""},
		{"a12uel5l", true, ""},
		{"an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs", true, ""},
		{"abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw", true, ""},
		{"11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j", true, ""},
		{"split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w", true, ""},
		{"?1ezyfcl", true, ""},
		// HRP character out of range.
		{"\x201nwldj5", false, "decoding bech32 failed: invalid character in string: ' '"},
		// HRP character out of range.
		{"\x7F1axkwrx", false, "decoding bech32 failed: invalid character in string: '\u007f'"},
		// HRP character out of range.
		{"\x801eym55h", false, "decoding bech32 failed: invalid character in string: '\u0080'"},
		// Overall max length exceeded.
		{
			"an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
			false,
			"decoding bech32 failed: invalid bech32 string length 91",
		},
		// No separator character.
		{"pzry9x0s0muk", false, "decoding bech32 failed: invalid separator index -1"},
		// Empty HRP.
		{"1pzry9x0s0muk", false, "decoding bech32 failed: invalid separator index 0"},
		// Invalid data character.
		{"x1b4n0q5v", false, "decoding bech32 failed: invalid character not part of charset: 98"},
		// Too short checksum.
		{"li1dgmt3", false, "decoding bech32 failed: invalid separator index 2"},
		// Invalid character in checksum.
		{"de1lg7wt\xFF", false, "decoding bech32 failed: invalid character in string: 'ÿ'"},
		// Checksum calculated with uppercase form of HRP.
		{"A1G7SGD8", false, "decoding bech32 failed: invalid checksum (expected 2uel5l got g7sgd8)"},
		// Empty HRP.
		{"10a06t8", false, "decoding bech32 failed: invalid bech32 string length 7"},
		// Empty HRP.
		{"1qzzfhee", false, "decoding bech32 failed: invalid separator index 0"},
	}

	for _, vector := range testVectors {
		hrp, decoded, err := Decode(vector.str)
		if !vector.valid {
			require.EqualErrorf(err, vector.errMsg, "Decoding an invalid bech32 string should fail: %s", vector.str)
			continue
		}
		require.NoError(err, "Failed to decode a valid bech32 string")
		encoded, err := Encode(hrp, decoded)
		require.NoError(err, "Failed to encode previously decoded data")
		// According to BIP 173, encoders must always output an all lowercase Bech32 string:
		// https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki#bech32.
		require.Equal(strings.ToLower(vector.str), encoded,
			"Re-encoded bech32 string should match the original one (except for case)",
		)
	}
}
