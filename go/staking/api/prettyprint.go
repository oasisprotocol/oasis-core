package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

type contextKey string

// ContextKeyAccountNames is the key to retrieve native (Bech32) account names from context.
var ContextKeyAccountNames = contextKey("staking/account-names")

// AccountNames maps native (Bech32) addresses to user-defined account names for pretty printing.
type AccountNames map[string]string

// FormatAddress is like FormatAddressWith but reads names from ctx.
func FormatAddress(ctx context.Context, addr Address) string {
	var names AccountNames
	if v, ok := ctx.Value(ContextKeyAccountNames).(AccountNames); ok {
		names = v
	}

	return FormatAddressWith(names, addr)
}

// FormatAddressWith formats a staking address for display.
//
// Output cases:
//   - Named address:   "name (oasis1...)"
//   - Unknown address: "oasis1..."
func FormatAddressWith(names AccountNames, addr Address) string {
	native := addr.String()
	if names == nil {
		return native
	}

	name := names[native]
	if name == "" {
		return native
	}

	return fmt.Sprintf("%s (%s)", name, native)
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
	return fmt.Sprintf("%s%%", prettyprint.QuantityFrac(rateNumerator, denominatorExp))
}

// PrettyPrintCommissionScheduleIndexInfixes returns two infixes:
//   - indexInfix holds the infix to use to pretty print the given commission
//     schedule rate (bound) index
//   - emptyInfix holds the infix to use to pretty print an empty string of an
//     equivalent length
func PrettyPrintCommissionScheduleIndexInfixes(ctx context.Context) (indexInfix, emptyInfix string) {
	index, ok := ctx.Value(prettyprint.ContextKeyCommissionScheduleIndex).(int)
	if !ok {
		return "", ""
	}
	indexInfix = fmt.Sprintf("(%d) ", index+1)
	emptyInfix = strings.Repeat(" ", len(indexInfix))
	return indexInfix, emptyInfix
}
