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
func PrettyPrintAmount(ctx context.Context, amount interface{}, w io.Writer) {
	useBaseUnits := false
	validAmount := true

	// Try to get token's symbol and token's value base-10 exponent from context.
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

	// Get amount from different types.
	var amountQ quantity.Quantity
	switch a := amount.(type) {
	case quantity.Quantity:
		amountQ = a
	case prettyprint.Quantity:
		if !a.IsValid() {
			validAmount = false
		} else {
			amountQ = *a.Unwrap()
		}
	default:
		validAmount = false
	}

	// Try to convert the base unit amount to tokens.
	var tokenAmount string
	var err error
	if validAmount && !useBaseUnits {
		tokenAmount, err = ConvertToTokenAmount(amountQ, exp)
		if err != nil {
			useBaseUnits = true
		}
	}

	switch {
	case !validAmount:
		fmt.Fprintf(w, prettyprint.QuantityInvalidText)
	case useBaseUnits:
		fmt.Fprintf(w, "%s%s base units", sign, amountQ)
	default:
		fmt.Fprintf(w, "%s%s %s", sign, tokenAmount, symbol)
	}
}
