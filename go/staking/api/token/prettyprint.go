package token

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// ConvertToTokenAmount returns the given amount in base units to the
// corresponding token amount accourding to the given token's value base-10
// exponent.
func ConvertToTokenAmount(amount quantity.Quantity, tokenValueExponent uint8) (string, error) {
	if tokenValueExponent > TokenValueExponentMaxValue {
		return "", ErrInvalidTokenValueExponent
	}

	return prettyprint.QuantityFrac(amount, tokenValueExponent), nil
}

// PrettyPrintAmount writes a pretty-printed representation of the given amount
// to the given writer.
//
// If the context carries appropriate values for the token's ticker symbol and
// token's value base-10 exponent, then the amount is printed in tokens instead
// of base units.
func PrettyPrintAmount(ctx context.Context, amount quantity.Quantity, w io.Writer) {
	useBaseUnits := false

	symbol, ok := ctx.Value(prettyprint.ContextKeyTokenSymbol).(string)
	if !ok || symbol == "" || len(symbol) > TokenSymbolMaxLength {
		useBaseUnits = true
	}
	exp, ok := ctx.Value(prettyprint.ContextKeyTokenValueExponent).(uint8)
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
