package sakg

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBIP32Path(t *testing.T) {
	require := require.New(t)

	testVectors := []struct {
		strPath      string
		strPathValid bool
		path         BIP32Path
		errMsg       string
	}{
		// Valid.
		{"m", true, []uint32{}, ""},
		{"m/1/2/3", true, []uint32{1, 2, 3}, ""},
		{"m/44'", true, []uint32{0x8000002c}, ""},
		{"m/44'/0'", true, []uint32{0x8000002c, 0x80000000}, ""},
		{"m/44'/0'/0'", true, []uint32{0x8000002c, 0x80000000, 0x80000000}, ""},
		{"m/44'/0'/0'/0", true, []uint32{0x8000002c, 0x80000000, 0x80000000, 0}, ""},
		{"m/44'/0'/0'/0/0", true, []uint32{0x8000002c, 0x80000000, 0x80000000, 0, 0}, ""},
		{"m/44'/2147483647", true, []uint32{0x8000002c, 0x7fffffff}, ""},
		{"m/44'/2147483647'", true, []uint32{0x8000002c, 0xffffffff}, ""},

		// Invalid.
		{"", false, []uint32{}, "invalid BIP-0032 path's mnemonic component:  (expected: m)"},
		{"44'/0'", false, []uint32{}, "invalid BIP-0032 path's mnemonic component: 44' (expected: m)"},
		{"foo/44'", false, []uint32{}, "invalid BIP-0032 path's mnemonic component: foo (expected: m)"},
		{"m/bla'", false, []uint32{}, "invalid BIP-0032 path's 2. component: strconv.ParseUint: parsing \"bla\": invalid syntax"},
		{"m/44'/2147483648", false, []uint32{}, "invalid BIP-0032 path's 3. component: maximum value of 2147483647 exceeded (got: 2147483648)"},
		{"m/44'/2147483648'", false, []uint32{}, "invalid BIP-0032 path's 3. component: maximum value of 2147483647 exceeded (got: 2147483648)"},
	}

	for _, v := range testVectors {
		var unmarshaledPath BIP32Path
		err := unmarshaledPath.UnmarshalText([]byte(v.strPath))
		if !v.strPathValid {
			require.EqualErrorf(
				err,
				v.errMsg,
				"Unmarshaling invalid BIP-0032 string path: %s should fail with expected error message",
				v.strPath,
			)
			continue
		}
		require.NoErrorf(err, "Failed to unmarshal a valid BIP-0032 string path: %s", v.strPath)
		require.Equal(v.path, unmarshaledPath, "Unmarshaled BIP-0032 path doesn't equal expected path")

		textPath, err := unmarshaledPath.MarshalText()
		require.NoError(err, "Failed to marshal a valid BIP-0032 path: %s", v.path)
		require.Equal(v.strPath, string(textPath), "Marshaled BIP-0032 path doesn't equal expected text BIP-0032 path")
	}
}
