package abci

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
)

func TestBasicGasAccountant(t *testing.T) {
	require := require.New(t)

	cheapOp := transaction.Op("cheap op")
	expensiveOp := transaction.Op("expensive op")
	overflowOp := transaction.Op("overflow op")
	costs := transaction.Costs{
		cheapOp:     10,
		expensiveOp: 91,
		overflowOp:  math.MaxUint64,
	}

	a := NewGasAccountant(100)
	require.EqualValues(100, a.GasWanted(), "GasWanted")

	// Normal gas consumption.
	err := a.UseGas(cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(10, a.GasUsed(), "GasUsed")

	// Overflow.
	err = a.UseGas(overflowOp, costs)
	require.Error(err, "UseGas should fail on overflow")
	require.Equal(ErrGasOverflow, err)
	require.EqualValues(10, a.GasUsed(), "GasUsed")

	// Out of gas.
	err = a.UseGas(expensiveOp, costs)
	require.Error(err, "UseGas should fail when out of gas")
	require.Equal(ErrOutOfGas, err)
	require.EqualValues(10, a.GasUsed(), "GasUsed")

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

	// Normal gas consumption.
	err := a.UseGas(cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(0, a.GasUsed(), "GasUsed")

	// Overflow.
	err = a.UseGas(overflowOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(0, a.GasUsed(), "GasUsed")

	// Out of gas.
	err = a.UseGas(expensiveOp, costs)
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
		expensiveOp: 91,
		overflowOp:  math.MaxUint64,
	}

	a := NewGasAccountant(10)
	b := NewGasAccountant(10)
	c := NewCompositeGasAccountant(a, b)
	require.EqualValues(10, c.GasWanted(), "GasWanted")

	// Normal gas consumption.
	err := c.UseGas(cheapOp, costs)
	require.NoError(err, "UseGas")
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")

	// Overflow.
	err = c.UseGas(overflowOp, costs)
	require.Error(err, "UseGas should fail on overflow")
	require.Equal(ErrGasOverflow, err)
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")

	// Out of gas.
	err = a.UseGas(expensiveOp, costs)
	require.Error(err, "UseGas should fail when out of gas")
	require.Equal(ErrOutOfGas, err)
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")

	require.EqualValues(10, c.GasWanted(), "GasWanted")

	// Reuse one of the accountants, reset the other.
	a = NewGasAccountant(10)
	c = NewCompositeGasAccountant(a, b)
	require.EqualValues(10, c.GasWanted(), "GasWanted")
	require.EqualValues(10, c.GasUsed(), "GasUsed")

	err = c.UseGas(cheapOp, costs)
	require.Error(err, "UseGas should fail when out of gas")
	require.Equal(ErrOutOfGas, err)
	require.EqualValues(10, c.GasUsed(), "GasUsed")
	require.EqualValues(10, a.GasUsed(), "GasUsed")
	require.EqualValues(10, b.GasUsed(), "GasUsed")
}
