package abci

import (
	"errors"
	"math"

	"github.com/oasislabs/oasis-core/go/common/consensus/gas"
)

var (
	// ErrGasOverflow is the error returned if the gas counter would
	// overflow.
	ErrGasOverflow = errors.New("gas overflow")
	// ErrOutOfGas is the error returned if the caller is out of gas.
	ErrOutOfGas = errors.New("out of gas")
)

// GasAccountant is a gas accountant interface.
type GasAccountant interface {
	// UseGas attempts the use the given amount of gas. If the limit is
	// reached this method will return ErrOutOfGas.
	UseGas(gas.Op, gas.Costs) error

	// GasUsed returns the amount of gas used so far.
	GasUsed() gas.Gas
}

type basicGasAccountant struct {
	maxUsedGas gas.Gas
	usedGas    gas.Gas
}

func (ga *basicGasAccountant) UseGas(op gas.Op, costs gas.Costs) error {
	amount, ok := costs[op]
	if !ok {
		return nil
	}

	// Check for overflow.
	if math.MaxUint64-ga.usedGas < amount {
		return ErrGasOverflow
	}

	if ga.usedGas+amount > ga.maxUsedGas {
		return ErrOutOfGas
	}

	ga.usedGas += amount
	return nil
}

func (ga *basicGasAccountant) GasUsed() gas.Gas {
	return ga.usedGas
}

// NewGasAccountant creates a basic gas accountant.
//
// The gas accountant is not safe for concurrent use.
func NewGasAccountant(maxUsedGas gas.Gas) GasAccountant {
	return &basicGasAccountant{maxUsedGas: maxUsedGas}
}

type nopGasAccountant struct{}

func (ga *nopGasAccountant) UseGas(op gas.Op, costs gas.Costs) error {
	return nil
}

func (ga *nopGasAccountant) GasUsed() gas.Gas {
	return 0
}

// NewNopGasAccountant creates a no-op gas accountant that doesn't
// do any accounting.
func NewNopGasAccountant() GasAccountant {
	return &nopGasAccountant{}
}
