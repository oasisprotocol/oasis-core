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
		addSign             bool
		sign                string
	}{
		{"10000000000.0 CORE", quantity.NewFromUint64(10000000000000000000), true, "CORE", true, 9, false, ""},
		{"100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, false, ""},
		{"7999217230.1196 CORE", quantity.NewFromUint64(7999217230119600000), true, "CORE", true, 9, false, ""},
		{"0.0 CORE", quantity.NewFromUint64(0), true, "CORE", true, 9, false, ""},
		{"-100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, true, "-"},
		{"+100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, true, "+"},
		// Check large and small token's value base-10 exponents.
		{"10.0 BIG", quantity.NewFromUint64(10000000000000000000), true, "BIG", true, 18, false, ""},
		{"-10000000000000000001.0 SMALL", quantity.NewFromUint64(10000000000000000001), true, "SMALL", true, 0, true, "-"},
		// Check invalid token's value base-10 exponent.
		{"100000000 base units", quantity.NewFromUint64(100000000), true, "TOOBIG", true, 21, false, ""},
		// Check invalid token's ticker symbol.
		{"-100000 base units", quantity.NewFromUint64(100000), true, "SOMETHINGLONG", true, 6, true, "-"},
		{"100000 base units", quantity.NewFromUint64(100000), true, "", true, 6, false, ""},
		// Check invalid token's value sign.
		{"100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, true, ""},
		{"100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, true, "--"},
		{"100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, true, "++"},
		{"100.0 CORE", quantity.NewFromUint64(100000000000), true, "CORE", true, 9, true, "?"},
		// Check missing combinations of token's symbol, value exponent and value sign.
		{"+100000 base units", quantity.NewFromUint64(100000), false, "MISSING", true, 6, true, "+"},
		{"-100000 base units", quantity.NewFromUint64(100000), true, "NOEXP", false, 0, true, "-"},
		{"100000 base units", quantity.NewFromUint64(100000), false, "MISSING", false, 0, true, "?"},
		{"100000 base units", quantity.NewFromUint64(100000), false, "MISSING", true, 6, false, ""},
		{"100000 base units", quantity.NewFromUint64(100000), true, "NOEXP", false, 0, false, ""},
		{"100000 base units", quantity.NewFromUint64(100000), false, "MISSING", false, 0, false, ""},
	} {
		ctx := context.Background()
		if t.addSymbol {
			ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenSymbol, t.symbol)
		}
		if t.addExp {
			ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueExponent, t.exp)
		}
		if t.addSign {
			ctx = context.WithValue(ctx, prettyprint.ContextKeyTokenValueSign, t.sign)
		}
		var actualPrettyPrint bytes.Buffer
		PrettyPrintAmount(ctx, *t.amount, &actualPrettyPrint)
		require.Equal(t.expectedPrettyPrint, actualPrettyPrint.String(),
			"pretty printing stake amount (from quantity.Quantity) didn't return the expected result")

		actualPrettyPrint.Reset()
		ppQuantityAmount := prettyprint.NewFromQuanQuantity(t.amount)
		PrettyPrintAmount(ctx, ppQuantityAmount, &actualPrettyPrint)
		require.Equal(t.expectedPrettyPrint, actualPrettyPrint.String(),
			"pretty printing stake amount (from prettyprint.Quantity) didn't return the expected result")

	}
}
