package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

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
// - indexInfix holds the infix to use to pretty print the given commission
//   schedule rate (bound) index
// - emptyInfix holds the infix to use to pretty print an empty string of an
//   equivalent length
func PrettyPrintCommissionScheduleIndexInfixes(ctx context.Context) (indexInfix, emptyInfix string) {
	index, ok := ctx.Value(prettyprint.ContextKeyCommissionScheduleIndex).(int)
	if ok {
		indexInfix = fmt.Sprintf("(%d) ", index+1)
		emptyInfix = strings.Repeat(" ", len(indexInfix))
	}
	return
}
