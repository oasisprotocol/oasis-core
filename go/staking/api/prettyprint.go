package api

import (
	"context"
	"fmt"
	"io"
	"math/big"
	"strings"

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

	divisor := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(tokenValueExponent)), nil)

	// NOTE: We use DivMod() and manual string construction to avoid conversion
	// to other types and support arbitrarily large amounts.
	var quotient, remainder *big.Int
	quotient, remainder = new(big.Int).DivMod(amount.ToBigInt(), divisor, new(big.Int))

	// Prefix the remainder with the appropriate number of zeros.
	remainderStr := fmt.Sprintf("%0*s", tokenValueExponent, remainder)
	// Trim trailing zeros from the remainder.
	remainderStr = strings.TrimRight(remainderStr, "0")
	// Ensure remainder is not empty.
	if remainderStr == "" {
		remainderStr = "0"
	}

	// Combine quotient and remainder to a string representing the token amount.
	return fmt.Sprintf("%s.%s", quotient, remainderStr), nil
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
