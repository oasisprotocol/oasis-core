package api

import (
	"errors"
	"fmt"
	"math"

	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
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
	//
	// The actual amount defined by the costs map will be multiplied by
	// the given multiplier which must be a positive value.
	UseGas(multiplier int, op transaction.Op, costs transaction.Costs) error

	// GasWanted returns the amount of gas wanted.
	GasWanted() transaction.Gas

	// GasUsed returns the amount of gas used so far.
	GasUsed() transaction.Gas
}

type basicGasAccountant struct {
	maxUsedGas transaction.Gas
	usedGas    transaction.Gas
}

func (ga *basicGasAccountant) UseGas(multiplier int, op transaction.Op, costs transaction.Costs) error {
	if multiplier < 0 {
		panic("gas: multiplier must be >= 0")
	}

	amount, ok := costs[op]
	if !ok {
		return nil
	}
	amount = amount * transaction.Gas(multiplier)

	// Check for overflow.
	if math.MaxUint64-ga.usedGas < amount {
		return ErrGasOverflow
	}

	if ga.usedGas+amount > ga.maxUsedGas {
		return fmt.Errorf("%w (limit: %d wanted: %d)", ErrOutOfGas, ga.maxUsedGas, ga.usedGas+amount)
	}

	ga.usedGas += amount
	return nil
}

func (ga *basicGasAccountant) GasWanted() transaction.Gas {
	return ga.maxUsedGas
}

func (ga *basicGasAccountant) GasUsed() transaction.Gas {
	return ga.usedGas
}

// NewGasAccountant creates a basic gas accountant.
//
// The gas accountant is not safe for concurrent use.
func NewGasAccountant(maxUsedGas transaction.Gas) GasAccountant {
	return &basicGasAccountant{maxUsedGas: maxUsedGas}
}

type nopGasAccountant struct{}

func (ga *nopGasAccountant) UseGas(multiplier int, op transaction.Op, costs transaction.Costs) error {
	if multiplier < 0 {
		panic("gas: multiplier must be >= 0")
	}

	return nil
}

func (ga *nopGasAccountant) GasWanted() transaction.Gas {
	return 0
}

func (ga *nopGasAccountant) GasUsed() transaction.Gas {
	return 0
}

// Always use the same global no-op gas accountant instance to make it easier to check whether a
// no-op gas accountant is being used.
var nopGasAccountantImpl = &nopGasAccountant{}

// NewNopGasAccountant creates a no-op gas accountant that doesn't
// do any accounting.
func NewNopGasAccountant() GasAccountant {
	return nopGasAccountantImpl
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

func (ga *compositeGasAccountant) UseGas(multiplier int, op transaction.Op, costs transaction.Costs) error {
	if multiplier < 0 {
		panic("gas: multiplier must be >= 0")
	}

	for _, a := range ga.accts {
		if err := a.UseGas(multiplier, op, costs); err != nil {
			return err
		}
	}
	return nil
}

func (ga *compositeGasAccountant) GasWanted() transaction.Gas {
	if len(ga.accts) == 0 {
		return 0
	}
	return ga.accts[0].GasWanted()
}

func (ga *compositeGasAccountant) GasUsed() transaction.Gas {
	var max transaction.Gas
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
