package api

import (
	"errors"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

func TestBasicGasAccountant(t *testing.T) {
	require := require.New(t)

	cheapOp := transaction.Op("cheap op")
	expensiveOp := transaction.Op("expensive op")
	overflowOp := transaction.Op("overflow op")
	costs := transaction.Costs{
		cheapOp:     10,
		expensiveOp: 71,
		overflowOp:  math.MaxUint64,
	}

	a := NewGasAccountant(100)
	require.EqualValues(100, a.GasWanted(), "GasWanted")

	// Bad multiplier.
	require.Panics(func() { _ = a.UseGas(-1, cheapOp, costs) })

	// Normal gas consumption.
	err := a.UseGas(1, cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(10, a.GasUsed(), "GasUsed")

	err = a.UseGas(2, cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(30, a.GasUsed(), "GasUsed")

	// Zero multiplier.
	err = a.UseGas(0, overflowOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(30, a.GasUsed(), "GasUsed")

	// Overflow.
	err = a.UseGas(1, overflowOp, costs)
	require.Error(err, "UseGas should fail on overflow")
	require.True(errors.Is(err, ErrGasOverflow))
	require.EqualValues(30, a.GasUsed(), "GasUsed")

	// Out of gas.
	err = a.UseGas(1, expensiveOp, costs)
	require.Error(err, "UseGas should fail when out of gas")
	require.True(errors.Is(err, ErrOutOfGas))
	require.EqualValues(30, a.GasUsed(), "GasUsed")

	require.EqualValues(100, a.GasWanted(), "GasWanted")
}

func TestNopGasAccountant(t *testing.T) {
	require := require.New(t)

	cheapOp := transaction.Op("cheap op")
	expensiveOp := transaction.Op("expensive op")
	overflowOp := transaction.Op("overflow op")
	costs := transaction.Costs{
		cheapOp:     10,
		expensiveOp: 91,
		overflowOp:  math.MaxUint64,
	}

	a := NewNopGasAccountant()
	require.EqualValues(0, a.GasWanted(), "GasWanted")

	// Bad multiplier.
	require.Panics(func() { _ = a.UseGas(-1, cheapOp, costs) })

	// Normal gas consumption.
	err := a.UseGas(1, cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(0, a.GasUsed(), "GasUsed")

	// Overflow.
	err = a.UseGas(1, overflowOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(0, a.GasUsed(), "GasUsed")

	// Out of gas.
	err = a.UseGas(1, expensiveOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(0, a.GasUsed(), "GasUsed")

	require.EqualValues(0, a.GasWanted(), "GasWanted")
}

func TestCompositeGasAccountant(t *testing.T) {
	require := require.New(t)

	cheapOp := transaction.Op("cheap op")
	expensiveOp := transaction.Op("expensive op")
	overflowOp := transaction.Op("overflow op")
	costs := transaction.Costs{
		cheapOp:     10,
		expensiveOp: 71,
		overflowOp:  math.MaxUint64,
	}

	a := NewGasAccountant(10)
	b := NewGasAccountant(10)
	c := NewCompositeGasAccountant(a, b)
	require.EqualValues(10, c.GasWanted(), "GasWanted")

	// Bad multiplier.
	require.Panics(func() { _ = c.UseGas(-1, cheapOp, costs) })
	require.EqualValues(0, c.GasUsed(), "GasUsed")

	// Normal gas consumption.
	err := c.UseGas(1, cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")

	// Overflow.
	err = c.UseGas(1, overflowOp, costs)
	require.Error(err, "UseGas should fail on overflow")
	require.True(errors.Is(err, ErrGasOverflow))
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")

	// Out of gas.
	err = a.UseGas(1, expensiveOp, costs)
	require.Error(err, "UseGas should fail when out of gas")
	require.True(errors.Is(err, ErrOutOfGas))
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")

	require.EqualValues(10, c.GasWanted(), "GasWanted")

	// Reuse one of the accountants, reset the other.
	a = NewGasAccountant(10)
	c = NewCompositeGasAccountant(a, b)
	require.EqualValues(10, c.GasWanted(), "GasWanted")
	require.EqualValues(10, c.GasUsed(), "GasUsed")

	err = c.UseGas(1, cheapOp, costs)
	require.Error(err, "UseGas should fail when out of gas")
	require.True(errors.Is(err, ErrOutOfGas))
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")
}
