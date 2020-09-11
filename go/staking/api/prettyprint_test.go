package api

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

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
