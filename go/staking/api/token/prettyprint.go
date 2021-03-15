package token

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// TokenValueAllowedSigns specifies allowed token's value signs.
var TokenValueAllowedSigns = []string{"+", "-"}

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
// If the context carries appropriate value for the token's value sign, then the
// amount is prefixed with the sign.
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

	sign := ""
	// Use token's value sign if it is contained in the context and a valid one.
	signCtx, ok := ctx.Value(prettyprint.ContextKeyTokenValueSign).(string)
	if ok {
		for _, s := range TokenValueAllowedSigns {
			if signCtx == s {
				sign = signCtx
				break
			}
		}
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
		fmt.Fprintf(w, "%s%s base units", sign, amount)
	} else {
		fmt.Fprintf(w, "%s %s%s", symbol, sign, tokenAmount)
	}
}
