package api

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

var (
	// PrettyPrinterContextKeyTokenSymbol is the key to retrieve the token's
	// ticker symbol value from a context.
	PrettyPrinterContextKeyTokenSymbol = contextKey("staking/token-symbol")
	// PrettyPrinterContextKeyTokenValueExponent is the key to retrieve the
	// token's value base-10 exponent from a context.
	PrettyPrinterContextKeyTokenValueExponent = contextKey("staking/token-value-exponent")
)

type contextKey string

// ConvertToTokenAmount returns the given amount in base units to the
// corresponding token amount accourding to the given token's value base-10
// exponent.
func ConvertToTokenAmount(amount quantity.Quantity, tokenValueExponent uint8) (string, error) {
	if tokenValueExponent > TokenValueExponentMaxValue {
		return "", ErrInvalidTokenValueExponent
	}

	return prettyprint.FractionBase10(amount, tokenValueExponent), nil
}

// PrettyPrintAmount writes a pretty-printed representation of the given amount
// to the given writer.
//
// If the context carries appropriate values for the token's ticker symbol and
// token's value base-10 exponent, then the amount is printed in tokens instead
// of base units.
func PrettyPrintAmount(ctx context.Context, amount quantity.Quantity, w io.Writer) {
	useBaseUnits := false

	symbol, ok := ctx.Value(PrettyPrinterContextKeyTokenSymbol).(string)
	if !ok || symbol == "" || len(symbol) > TokenSymbolMaxLength {
		useBaseUnits = true
	}
	exp, ok := ctx.Value(PrettyPrinterContextKeyTokenValueExponent).(uint8)
	if !ok {
		useBaseUnits = true
	}

	var tokenAmount string
	var err error
	if !useBaseUnits {
		tokenAmount, err = ConvertToTokenAmount(amount, exp)
		if err != nil {
			useBaseUnits = true
		}
	}

	if useBaseUnits {
		fmt.Fprintf(w, "%s base units", amount)
	} else {
		fmt.Fprintf(w, "%s %s", symbol, tokenAmount)
	}
}

// PrettyPrintCommissionRatePercentage returns the string representing the
// commission rate (bound) in percentage for the given commission rate (bound)
// numerator.
func PrettyPrintCommissionRatePercentage(rateNumerator quantity.Quantity) string {
	// Handle invalid commission rate (bound) numerator.
	if rateNumerator.Cmp(CommissionRateDenominator) > 0 {
		return "(invalid)"
	}
	// Reduce commission rate denominator's base-10 exponent by 2 to obtain the
	// value in percentage.
	denominatorExp := commissionRateDenominatorExponent - 2
	return fmt.Sprintf("%s%%", prettyprint.FractionBase10(rateNumerator, denominatorExp))
}
