package address

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBech32HRP(t *testing.T) {
	require := require.New(t)

	// Make sure Bech32 HRPs can be registered.
	var hrp1, hrp2 Bech32HRP
	require.NotPanics(func() { hrp1 = NewBech32HRP("test-dummy-hrp1") },
		"registering a new hrp should not panic")
	require.NotPanics(func() { hrp2 = NewBech32HRP("test-dummy-hrp2") },
		"registering a new hrp should not panic")

	// Make sure registering invalid Bech32 HRPs panics.
	require.Panics(func() { NewBech32HRP("test-dummy-hrp1") },
		"registering the same hrp twice should panic")
	require.Panics(func() { NewBech32HRP(strings.Repeat("a", 20)) },
		"registering a hrp that is too long should panic")

	var addr, decodedAddr Address
	err := addr.UnmarshalBinary([]byte("test address (len=21)"))
	require.NoError(err, "unmarshaling address should work")

	// Make sure we cannot use an unregistered Bech32 HRP.
	unregHRP := Bech32HRP("test-unregistered-hrp")
	require.Panics(func() { _, _ = addr.MarshalBech32(unregHRP) },
		"encoding to Bech32 with an unregistered hrp should panic")
	require.Panics(func() { _ = addr.UnmarshalBech32(unregHRP, []byte("bech encoded test address")) },
		"decoding from Bech32 with an unregistered hrp should panic")

	// Make sure using registered Bech32 HRPs to encode and decoded Addresses works.
	for _, hrp := range []Bech32HRP{hrp1, hrp2} {
		addrBech32, err := addr.MarshalBech32(hrp)
		require.NoError(err, "encoding to Bech32 with registered hrp should work")
		err = decodedAddr.UnmarshalBech32(hrp, addrBech32)
		require.NoError(err, "decoding from Bech32 with registered hrp should work")
		require.Equal(addr, decodedAddr, "decoded address should be the same as the original address")
	}
}
