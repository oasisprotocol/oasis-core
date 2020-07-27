package prettyprint

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func TestQuantityFrac(t *testing.T) {
	require := require.New(t)

	for _, t := range []struct {
		expectedOutput string
		numerator      *quantity.Quantity
		denominatorExp uint8
	}{
		{"10000000000.0", quantity.NewFromUint64(10000000000000000000), 9},
		{"100.0", quantity.NewFromUint64(100000000000), 9},
		{"7999217230.11968289", quantity.NewFromUint64(7999217230119682890), 9},
		{"7999217230.1196", quantity.NewFromUint64(7999217230119600000), 9},
		{"7999217230.1", quantity.NewFromUint64(7999217230100000000), 9},
		{"0.0", quantity.NewFromUint64(0), 9},
		// Checks for large and small denominator base-10 exponents.
		{"0.010000000000000000001", quantity.NewFromUint64(10000000000000000001), 21},
		{"10.0", quantity.NewFromUint64(10000000000000000000), 18},
		{"10.000000000000000001", quantity.NewFromUint64(10000000000000000001), 18},
		{"0.0000001", quantity.NewFromUint64(100000000000), 18},
		{"0.0", quantity.NewFromUint64(0), 18},
		{"10000000000000000000.0", quantity.NewFromUint64(10000000000000000000), 0},
		{"10000000000000000001.0", quantity.NewFromUint64(10000000000000000001), 0},
		{"0.0", quantity.NewFromUint64(0), 0},
	} {
		output := QuantityFrac(*t.numerator, t.denominatorExp)
		require.Equal(t.expectedOutput, output, "obtained pretty print didn't match expected value")
	}
}
