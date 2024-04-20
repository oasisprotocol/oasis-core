package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
)

func TestAddressDeserialization(t *testing.T) {
	require := require.New(t)

	var addr Address
	err := cbor.Unmarshal([]byte{0xF6}, &addr)
	require.NoError(err, "cbor.Unmarshal")
	require.EqualValues("oasis1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0ltrq9", addr.String())

	raw, _ := addr.MarshalBinary()
	require.EqualValues([]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, raw)
}

func TestReserved(t *testing.T) {
	require := require.New(t)

	pk := signature.NewPublicKey("badadd1e55ffffffffffffffffffffffffffffffffffffffffffffffffffffff")
	pk2 := signature.NewPublicKey("badbadadd1e55fffffffffffffffffffffffffffffffffffffffffffffffffff")

	var addr, addr2 Address

	addr = NewAddress(pk)
	require.True(addr.IsValid(), "test address should initially be valid")
	require.False(addr.IsReserved(), "test address should not initially be reserved")
	require.EqualValues("oasis1qryqqccycvckcxp453tflalujvlf78xymcdqw4vz", addr.String(), "test address should be correct")

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

func TestRuntimeAddress(t *testing.T) {
	require := require.New(t)

	id1 := common.NewTestNamespaceFromSeed([]byte("runtime address test 1"), 0)
	id2 := common.NewTestNamespaceFromSeed([]byte("runtime address test 2"), 0)

	addr1 := NewRuntimeAddress(id1)
	require.True(addr1.IsValid(), "runtime address should be valid")
	require.EqualValues("oasis1qpllh99nhwzrd56px4txvl26atzgg4f3a58jzzad", addr1.String(), "runtime address should be correct")

	addr2 := NewRuntimeAddress(id2)
	require.NotEqualValues(addr1, addr2, "runtime addresses for different runtimes should be different")

	// Make sure domain separation works.
	var pk1 signature.PublicKey
	err := pk1.UnmarshalBinary(id1[:])
	require.NoError(err, "UnmarshalBinary")
	addrPk1 := NewAddress(pk1)
	require.NotEqualValues(addr1, addrPk1, "runtime addresses should be separated from staking addresses")
}

func TestModuleAddress(t *testing.T) {
	require := require.New(t)

	addr1 := NewModuleAddress("test", "foo")
	require.True(addr1.IsValid(), "module address should be valid")
	require.EqualValues("oasis1qpgsr850rfz7v8nxpgz8urkw3xp4nnwjgux629kl", addr1.String(), "module address should be correct")

	addr2 := NewModuleAddress("test", "bar")
	require.NotEqualValues(addr1, addr2, "module addresses for different kinds should be different")

	addr3 := NewModuleAddress("another", "foo")
	require.NotEqualValues(addr1, addr3, "module addresses for different modules should be different")
	require.NotEqualValues(addr2, addr3, "module addresses for different modules should be different")
}

func TestInternal(t *testing.T) {
	for _, v := range []struct {
		n       string
		addrStr string // Invariant

		addr Address
	}{
		{"CommonPoolAddress", "oasis1qrmufhkkyyf79s5za2r8yga9gnk4t446dcy3a5zm", CommonPoolAddress},
		{"FeeAccumulatorAddress", "oasis1qqnv3peudzvekhulf8v3ht29z4cthkhy7gkxmph5", FeeAccumulatorAddress},
		{"GovernanceDepositsAddress", "oasis1qp65laz8zsa9a305wxeslpnkh9x4dv2h2qhjz0ec", GovernanceDepositsAddress},
		{"BurnAddress", "oasis1qzq8u7xs328puu2jy524w3fygzs63rv3u5967970", BurnAddress},
	} {
		require.Equal(t, v.addrStr, v.addr.String(), "%s changed value", v.n)
		require.False(t, v.addr.IsValid(), "%s should be invalid", v.n)
		require.True(t, v.addr.IsReserved(), "%s should be reserved", v.n)
		t.Logf("%s - %s", v.n, v.addr)
	}
}
