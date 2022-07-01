package prettyprint

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

// QuantityInvalidText is the textual representation of an invalid Quantity.
const QuantityInvalidText = "(invalid)"

// Quantity is a quantity.Quantity wrapper for pretty-printing.
//
// Operations over it never return an error, but just record that the Quantity
// has become invalid.
type Quantity struct {
	quan    *quantity.Quantity
	invalid bool
}

// Add adds n to q if q is valid.
func (q *Quantity) Add(n Quantity) {
	if q.invalid {
		return
	}
	if err := q.quan.Add(n.quan); err != nil {
		q.invalid = true
	}
}

// Sub subtracts exactly n from q if q is valid.
func (q *Quantity) Sub(n Quantity) {
	if q.invalid {
		return
	}
	if err := q.quan.Sub(n.quan); err != nil {
		q.invalid = true
	}
}

// Mul multiplies n with q if q is valid.
func (q *Quantity) Mul(n Quantity) {
	if q.invalid {
		return
	}
	if err := q.quan.Mul(n.quan); err != nil {
		q.invalid = true
	}
}

// Quo divides q with n if q is valid.
func (q *Quantity) Quo(n Quantity) {
	if q.invalid {
		return
	}
	if err := q.quan.Quo(n.quan); err != nil {
		q.invalid = true
	}
}

// IsValid returns true iff the q is valid.
func (q Quantity) IsValid() bool {
	return !q.invalid && q.quan.IsValid()
}

// Unwrap returns q's wrapped quantity.Quantity object.
func (q Quantity) Unwrap() *quantity.Quantity {
	return q.quan
}

// String returns the string representation of q.
func (q Quantity) String() string {
	if !q.IsValid() {
		return QuantityInvalidText
	}
	return q.quan.String()
}

// NewQuantity creates a new Quantity, initialized to zero.
func NewQuantity() (q Quantity) {
	return Quantity{
		quan: quantity.NewQuantity(),
	}
}

// NewFromQuanQuantity creates a new Quantity from a given quantity.Quantity object.
func NewFromQuanQuantity(q *quantity.Quantity) Quantity {
	return Quantity{
		quan:    q.Clone(),
		invalid: !q.IsValid(),
	}
}

// QuantityFrac returns a pretty-printed representation of a quantity fraction
// for the given numerator and denominator's base-10 exponent.
func QuantityFrac(numerator quantity.Quantity, denominatorExp uint8) string {
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
