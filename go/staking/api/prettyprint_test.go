package api

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func mustAddress(t *testing.T, raw string) Address {
	t.Helper()

	var addr Address
	require.NoError(t, addr.UnmarshalText([]byte(raw)))
	return addr
}

func TestPrettyPrintCommissionRatePercentage(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct {
		expectedRate  string
		rateNumerator *quantity.Quantity
	}{
		{"0.0%", quantity.NewFromUint64(0)},
		{"50.0%", quantity.NewFromUint64(50_000)},
		{"100.0%", quantity.NewFromUint64(100_000)},
		{"20.2%", quantity.NewFromUint64(20_200)},
		{"30.03%", quantity.NewFromUint64(30_030)},
		{"12.345%", quantity.NewFromUint64(12_345)},
		// Checks for invalid commission rate numerators.
		{"(invalid)", quantity.NewFromUint64(100_001)},
		{"(invalid)", quantity.NewFromUint64(123_456)},
	} {
		rate := PrettyPrintCommissionRatePercentage(*t.rateNumerator)
		require.Equal(t.expectedRate, rate, "obtained pretty print didn't match expected value")
	}
}

func TestPrettyPrintCommissionScheduleIndexInfixes(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct {
		expectedIndexInfix string
		expectedEmptyInfix string
		index              int
		indexPresent       bool
	}{
		{"(1) ", "    ", 0, true},
		{"(2) ", "    ", 1, true},
		{"(10) ", "     ", 9, true},
		{"(123) ", "      ", 122, true},
		{"(2345678) ", "          ", 2345677, true},
	} {
		require.Equal(len(t.expectedIndexInfix), len(t.expectedEmptyInfix), "expected index and empty infixes should be of equal length")
		ctx := context.WithValue(context.Background(), prettyprint.ContextKeyCommissionScheduleIndex, t.index)
		indexInfix, emptyInfix := PrettyPrintCommissionScheduleIndexInfixes(ctx)
		require.Equal(t.expectedIndexInfix, indexInfix, "obtained index infix didn't match expected value")
		require.Equal(t.expectedEmptyInfix, emptyInfix, "obtained empty infix didn't match expected value")
	}
}

func TestFormatAddressWith(t *testing.T) {
	require := require.New(t)

	addr := mustAddress(t, "oasis1qrydpazemvuwtnp3efm7vmfvg3tde044qg6cxwzx")
	native := addr.String()

	for _, tc := range []struct {
		name     string
		names    AccountNames
		expected string
	}{
		{
			name:     "nil names",
			names:    nil,
			expected: native,
		},
		{
			name:     "empty names",
			names:    AccountNames{},
			expected: native,
		},
		{
			name:     "unknown name",
			names:    AccountNames{"oasis1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpkfh7w": "ignored"},
			expected: native,
		},
		{
			name:     "named address",
			names:    AccountNames{native: "test:bob"},
			expected: "test:bob (" + native + ")",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(tc.expected, FormatAddressWith(tc.names, addr))
		})
	}
}

func TestFormatAddress(t *testing.T) {
	require := require.New(t)

	addr := mustAddress(t, "oasis1qrydpazemvuwtnp3efm7vmfvg3tde044qg6cxwzx")
	native := addr.String()

	t.Run("without context names", func(t *testing.T) {
		require.Equal(native, FormatAddress(context.Background(), addr))
	})

	t.Run("with context names", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyAccountNames, AccountNames{
			native: "test:bob",
		})
		require.Equal("test:bob ("+native+")", FormatAddress(ctx, addr))
	})
}

func TestStakingTxPrettyPrintUsesNamedAddresses(t *testing.T) {
	require := require.New(t)

	addr := mustAddress(t, "oasis1qrydpazemvuwtnp3efm7vmfvg3tde044qg6cxwzx")
	native := addr.String()
	amt := *quantity.NewFromUint64(1)

	ctx := context.WithValue(context.Background(), ContextKeyAccountNames, AccountNames{
		native: "test:bob",
	})

	for _, tc := range []struct {
		name     string
		pretty   func(context.Context, *bytes.Buffer)
		expected string
	}{
		{
			name: "transfer to",
			pretty: func(ctx context.Context, buf *bytes.Buffer) {
				Transfer{To: addr, Amount: amt}.PrettyPrint(ctx, "", buf)
			},
			expected: "To:     test:bob (" + native + ")",
		},
		{
			name: "escrow account",
			pretty: func(ctx context.Context, buf *bytes.Buffer) {
				Escrow{Account: addr, Amount: amt}.PrettyPrint(ctx, "", buf)
			},
			expected: "To:     test:bob (" + native + ")",
		},
		{
			name: "reclaim escrow from",
			pretty: func(ctx context.Context, buf *bytes.Buffer) {
				ReclaimEscrow{Account: addr, Shares: amt}.PrettyPrint(ctx, "", buf)
			},
			expected: "From:   test:bob (" + native + ")",
		},
		{
			name: "allow beneficiary",
			pretty: func(ctx context.Context, buf *bytes.Buffer) {
				Allow{Beneficiary: addr, AmountChange: amt}.PrettyPrint(ctx, "", buf)
			},
			expected: "Beneficiary:   test:bob (" + native + ")",
		},
		{
			name: "withdraw from",
			pretty: func(ctx context.Context, buf *bytes.Buffer) {
				Withdraw{From: addr, Amount: amt}.PrettyPrint(ctx, "", buf)
			},
			expected: "From:   test:bob (" + native + ")",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			tc.pretty(ctx, &buf)
			require.Contains(buf.String(), tc.expected)
		})
	}
}
