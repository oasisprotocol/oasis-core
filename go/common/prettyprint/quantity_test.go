package prettyprint

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/quantity"
)

func fromUint(n uint64) Quantity {
	quanQ := quantity.NewFromUint64(n)
	return NewFromQuanQuantity(quanQ)
}

func TestQuantityAdd(t *testing.T) {
	require := require.New(t)

	q := fromUint(100)

	q.Add(fromUint(200))
	require.True(q.IsValid(), "Add(200) valid")
	require.Equal(fromUint(300), q, "Add(200) value")
}

func TestQuantitySub(t *testing.T) {
	require := require.New(t)

	q := fromUint(500)

	q.Sub(fromUint(300))
	require.True(q.IsValid(), "Sub(300) valid")
	require.Equal(fromUint(200), q, "Sub(300) value")
}

func TestQuantityMul(t *testing.T) {
	require := require.New(t)

	q := fromUint(400)

	q.Mul(fromUint(200))
	require.True(q.IsValid(), "Mul(200) valid")
	require.Equal(fromUint(80_000), q, "Mul(200) value")
}

func TestQuantityQuo(t *testing.T) {
	require := require.New(t)

	q := fromUint(1200)

	q.Quo(fromUint(40))
	require.True(q.IsValid(), "Quo(40) valid")
	require.Equal(fromUint(30), q, "Quo(40) value")

	q = fromUint(100)
	p := fromUint(0)

	q.Quo(p)
	require.False(q.IsValid(), "Quo(0) valid")
}

func TestNewQuantity(t *testing.T) {
	require := require.New(t)

	q := NewQuantity()
	require.True(q.IsValid(), "NewQuantity() valid")
	require.Equal(fromUint(0), q, "NewQuantity() value")
}

func TestNewFromQuanQuantity(t *testing.T) {
	require := require.New(t)

	quanQ := quantity.NewFromUint64(200)
	q := NewFromQuanQuantity(quanQ)
	require.True(q.IsValid(), "NewFromQuanQuantity() valid")
	p := Quantity{
		quan: quantity.NewFromUint64(200),
	}
	require.Equal(p, q, "NewFromQuanQuantity() value")
}

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
