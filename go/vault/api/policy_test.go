package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestAuthorizeWithdrawal(t *testing.T) {
	require := require.New(t)

	as := AddressState{
		// Limit rate to 100 base units per 300 blocks.
		WithdrawPolicy: WithdrawPolicy{
			LimitAmount:   *quantity.NewFromUint64(100),
			LimitInterval: 300,
		},
	}
	err := as.WithdrawPolicy.Validate()
	require.NoError(err, "WithdrawPolicy.Validate")

	for _, tc := range []struct {
		height   int64
		amount   uint64
		expected bool
	}{
		// -- new bucket --
		{5, 10, true},
		{6, 10, true},
		{10, 50, true},
		{50, 50, false},
		{51, 10, true},
		{200, 10, true},
		// -- new bucket --
		{310, 70, true},
		{350, 70, false},
		{400, 30, true},
		{402, 1, false},
		{405, 0, true},
		{599, 1, false},
		// -- new bucket --
		{600, 50, true},
	} {
		ok := as.AuthorizeWithdrawal(tc.height, quantity.NewFromUint64(tc.amount))
		require.EqualValues(tc.expected, ok, "AuthorizeWithdrawal(%d, %d)", tc.height, tc.amount)
	}

	// Disabled policy.
	as = AddressState{}
	err = as.WithdrawPolicy.Validate()
	require.NoError(err, "WithdrawPolicy.Validate")
	ok := as.AuthorizeWithdrawal(42, quantity.NewFromUint64(0))
	require.True(ok, "AuthorizeWithdrawal should always return true for zero amount")
	ok = as.AuthorizeWithdrawal(42, quantity.NewFromUint64(10))
	require.False(ok, "AuthorizeWithdrawal should always return false for zero limit")

	as = AddressState{
		WithdrawPolicy: WithdrawPolicy{
			LimitAmount: *quantity.NewFromUint64(100),
		},
	}
	err = as.WithdrawPolicy.Validate()
	require.NoError(err, "WithdrawPolicy.Validate")
	ok = as.AuthorizeWithdrawal(42, quantity.NewFromUint64(10))
	require.False(ok, "AuthorizeWithdrawal should always return false for zero interval")
}
