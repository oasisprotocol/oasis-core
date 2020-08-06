package token

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestConvertToTokenAmount(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct {
		expectedTokenAmount string
		amount              *quantity.Quantity
		exp                 uint8
		valid               bool
	}{
		// General checks where 1 tokens equals 10^9 base units.
		{"10000000000.0", quantity.NewFromUint64(10000000000000000000), 9, true},
		{"100.0", quantity.NewFromUint64(100000000000), 9, true},
		{"7999217230.11968289", quantity.NewFromUint64(7999217230119682890), 9, true},
		{"7999217230.1196", quantity.NewFromUint64(7999217230119600000), 9, true},
		{"7999217230.1", quantity.NewFromUint64(7999217230100000000), 9, true},
		{"0.0", quantity.NewFromUint64(0), 9, true},
		// Check for a too large token's value base-10 exponent.
		{"INVALID", quantity.NewFromUint64(10000000000000000001), 21, false},
		// Special checks for large and small token's value base-10 exponents.
		{"10.0", quantity.NewFromUint64(10000000000000000000), 18, true},
		{"10.000000000000000001", quantity.NewFromUint64(10000000000000000001), 18, true},
		{"0.0000001", quantity.NewFromUint64(100000000000), 18, true},
		{"0.0", quantity.NewFromUint64(0), 18, true},
		{"10000000000000000000.0", quantity.NewFromUint64(10000000000000000000), 0, true},
		{"10000000000000000001.0", quantity.NewFromUint64(10000000000000000001), 0, true},
		{"0.0", quantity.NewFromUint64(0), 0, true},
	} {
		tokenAmount, err := ConvertToTokenAmount(*t.amount, t.exp)
		if !t.valid {
			require.Error(err, "converting base unit amount to tokens should fail")
			continue
		}
		require.NoError(err, "converting base unit amount to tokens shouldn't fail")
		require.Equal(t.expectedTokenAmount, tokenAmount,
			"converting base unit amount to tokens didn't return the expected amount")
	}
}

func TestPrettyPrintAmount(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct { // nolint: maligned
		expectedPrettyPrint string
		amount              *quantity.Quantity
		addSymbol           bool
		symbol              string
		addExp              bool
		exp                 uint8
	}{
		{"CORE 10000000000.0", quantity.NewFromUint64(10000000000000000000), true, "CORE", true, 9},
		{"CORE 100.0", quantity.NewFromUint64(100000000000), true, "CORE", true, 9},
		{"CORE 7999217230.1196", quantity.NewFromUint64(7999217230119600000), true, "CORE", true, 9},
		{"CORE 0.0", quantity.NewFromUint64(0), true, "CORE", true, 9},
		// Check large and small token's value base-10 exponents.
		{"BIG 10.0", quantity.NewFromUint64(10000000000000000000), true, "BIG", true, 18},
		{"SMALL 10000000000000000001.0", quantity.NewFromUint64(10000000000000000001), true, "SMALL", true, 0},
		// Check invalid token's value base-10 exponent.
		{"100000000 base units", quantity.NewFromUint64(100000000), true, "TOOBIG", true, 21},
		// Check invalid token's ticker symbol.
		{"100000 base units", quantity.NewFromUint64(100000), true, "SOMETHINGLONG", true, 6},
		{"100000 base units", quantity.NewFromUint64(100000), true, "", true, 6},
		// Check missing combinations of token's symbol and value exponent.
		{"100000 base units", quantity.NewFromUint64(100000), false, "MISSING", true, 6},
		{"100000 base units", quantity.NewFromUint64(100000), true, "NOEXP", false, 0},
		{"100000 base units", quantity.NewFromUint64(100000), false, "MISSING", false, 0},
	} {
		ctx := context.Background()
		if t.addSymbol {
			ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenSymbol, t.symbol)
		}
		if t.addExp {
			ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueExponent, t.exp)
		}
		var actualPrettyPrint bytes.Buffer
		PrettyPrintAmount(ctx, *t.amount, &actualPrettyPrint)
		require.Equal(t.expectedPrettyPrint, actualPrettyPrint.String(),
			"pretty printing stake amount didn't return the expected result")
	}
}
