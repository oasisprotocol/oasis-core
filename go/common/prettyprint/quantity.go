package prettyprint

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// FractionBase10 returns a decimal representation of a fraction from fraction's
// numerator and denominator's base-10 exponent.
func FractionBase10(numerator quantity.Quantity, denominatorExp uint8) string {
	denominator := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(denominatorExp)), nil)

	// NOTE: We use DivMod() and manual string construction to avoid conversion
	// to other types and support arbitrarily large amounts.
	var quotient, remainder *big.Int
	quotient, remainder = new(big.Int).DivMod(numerator.ToBigInt(), denominator, new(big.Int))

	// Prefix the remainder with the appropriate number of zeros.
	remainderStr := fmt.Sprintf("%0*s", denominatorExp, remainder)
	// Trim trailing zeros from the remainder.
	remainderStr = strings.TrimRight(remainderStr, "0")
	// Ensure remainder is not empty.
	if remainderStr == "" {
		remainderStr = "0"
	}

	// Combine quotient and remainder to a string representing the decimal
	// representation of the given fraction.
	return fmt.Sprintf("%s.%s", quotient, remainderStr)
}
