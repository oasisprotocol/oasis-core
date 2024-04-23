package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	testAddrA = staking.NewModuleAddress("test", "a")
	testAddrB = staking.NewModuleAddress("test", "b")
	testAddrC = staking.NewModuleAddress("test", "c")
	testAddrD = staking.NewModuleAddress("test", "d")
)

func TestAuthority(t *testing.T) {
	require := require.New(t)

	auth := Authority{}
	err := auth.Validate(&DefaultConsensusParameters)
	require.Error(err, "Validate should fail on empty set of addresses")
	require.ErrorContains(err, "no addresses")

	auth = Authority{
		Addresses: []staking.Address{testAddrA},
	}
	err = auth.Validate(&DefaultConsensusParameters)
	require.Error(err, "Validate should fail on zero threshold")

	auth = Authority{
		Addresses: []staking.Address{testAddrA},
		Threshold: 2,
	}
	err = auth.Validate(&DefaultConsensusParameters)
	require.Error(err, "Validate should fail on threshold that exceeds number of addresses")

	auth = Authority{
		Addresses: []staking.Address{
			testAddrA,
			testAddrB,
			testAddrC,
		},
		Threshold: 2,
	}
	err = auth.Validate(&DefaultConsensusParameters)
	require.NoError(err, "Validate should succeed on valid authority configuration")

	ok := auth.Verify([]staking.Address{testAddrA})
	require.False(ok, "Verify(testAddrA)")
	ok = auth.Verify([]staking.Address{testAddrA, testAddrB})
	require.True(ok, "Verify(testAddrA, testAddrB)")
	ok = auth.Verify([]staking.Address{testAddrA, testAddrD})
	require.False(ok, "Verify(testAddrA, testAddrD)")
	ok = auth.Verify([]staking.Address{testAddrA, testAddrB, testAddrC})
	require.True(ok, "Verify(testAddrA, testAddrB, testAddrC)")
	ok = auth.Verify([]staking.Address{testAddrA, testAddrA, testAddrA})
	require.False(ok, "Verify(testAddrA, testAddrA, testAddrA)")
}

func TestAddress(t *testing.T) {
	require := require.New(t)

	vault1 := Vault{
		Creator: testAddrA,
		ID:      0,
	}
	vault2 := Vault{
		Creator: testAddrA,
		ID:      1,
	}
	vault3 := Vault{
		Creator: testAddrB,
		ID:      0,
	}
	vault4 := Vault{
		Creator: testAddrB,
		ID:      1,
	}
	require.EqualValues("oasis1qrzxrldg2xazawgyvpqesyueum7gtsmw65u0za68", vault1.Address().String())
	require.EqualValues("oasis1qq9my0st8dtqdumqg8mcuerg6jzg0202aqw85ayl", vault2.Address().String())
	require.EqualValues("oasis1qpw4gyvddf044nupz4dan42e2lxjftc2uvhhm245", vault3.Address().String())
	require.EqualValues("oasis1qrsl7w8py3xpqknla7v785yms09ecst9k5ncvgym", vault4.Address().String())
}
