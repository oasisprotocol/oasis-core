package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestReserved(t *testing.T) {
	require := require.New(t)

	pk := signature.NewPublicKey("badadd1e55ffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	pk2 := signature.NewPublicKey("badbadadd1e55fffffffffffffffffffffffffffffffffffffffffffffffffff")

	var addr, addr2 Address

	addr = NewAddress(pk)
	require.True(addr.IsValid(), "test address should initially be valid")
	require.False(addr.IsReserved(), "test address should not initially be reserved")

	err := addr.Reserve()
	require.NoError(err, "marking test address as reserved should not fail")
	require.True(addr.IsReserved(), "test address should now be reserved")
	require.False(addr.IsValid(), "test address should now be invalid")

	require.Panics(func() { NewReservedAddress(pk) },
		"trying to mark the same address as reserved twice should panic",
	)

	require.NotPanics(func() { addr2 = NewReservedAddress(pk2) })
	require.True(addr2.IsReserved(), "test address 2 should be reserved")
	require.False(addr2.IsValid(), "test address 2 should be invalid")
	require.True(pk2.IsBlacklisted(), "public key for test address 2 should be blacklisted")
	require.False(pk2.IsValid(), "public key for test address 2 should be invalid")
}
