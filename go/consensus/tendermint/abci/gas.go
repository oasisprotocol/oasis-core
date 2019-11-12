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

	// GasWanted returns the amount of gas wanted.
	GasWanted() gas.Gas

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

func (ga *basicGasAccountant) GasWanted() gas.Gas {
	return ga.maxUsedGas
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

func (ga *nopGasAccountant) GasWanted() gas.Gas {
	return 0
}

func (ga *nopGasAccountant) GasUsed() gas.Gas {
	return 0
}

// NewNopGasAccountant creates a no-op gas accountant that doesn't
// do any accounting.
func NewNopGasAccountant() GasAccountant {
	return &nopGasAccountant{}
}

// GasAccountantKey is the gas accountant block context key.
type GasAccountantKey struct{}

// NewDefault returns a new default value for the given key.
func (gak GasAccountantKey) NewDefault() interface{} {
	// This should never be called as a gas accountant must always
	// be created by the application multiplexer.
	panic("gas: no gas accountant in block context")
}

type compositeGasAccountant struct {
	accts []GasAccountant
}

func (ga *compositeGasAccountant) UseGas(op gas.Op, costs gas.Costs) error {
	for _, a := range ga.accts {
		if err := a.UseGas(op, costs); err != nil {
			return err
		}
	}
	return nil
}

func (ga *compositeGasAccountant) GasWanted() gas.Gas {
	if len(ga.accts) == 0 {
		return 0
	}
	return ga.accts[0].GasWanted()
}

func (ga *compositeGasAccountant) GasUsed() gas.Gas {
	var max gas.Gas
	for _, a := range ga.accts {
		if g := a.GasUsed(); g > max {
			max = g
		}
	}
	return max
}

// NewCompositeGasAccountant creates a gas accountant that is composed
// of multiple gas accountants. Any gas used is dispatched to all
// accountants and if any returns an error, the error is propagated.
//
// The first accountant is used for GasWanted reporting.
func NewCompositeGasAccountant(accts ...GasAccountant) GasAccountant {
	return &compositeGasAccountant{accts}
}
