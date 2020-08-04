package api

import (
	"fmt"

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
