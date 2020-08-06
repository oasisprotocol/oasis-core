package transaction

import (
	"context"
	"fmt"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

var (
	// ErrInsufficientFeeBalance is the error returned when there is insufficient
	// balance to pay consensus fees.
	ErrInsufficientFeeBalance = errors.New(moduleName, 2, "transaction: insufficient balance to pay fees")

	// ErrGasPriceTooLow is the error returned when the gas price is too low.
	ErrGasPriceTooLow = errors.New(moduleName, 3, "transaction: gas price too low")

	_ prettyprint.PrettyPrinter = (*Fee)(nil)
)

// Gas is the consensus gas representation.
type Gas uint64

// Fee is the consensus transaction fee the sender wishes to pay for
// operations which require a fee to be paid to validators.
type Fee struct {
	// Amount is the fee amount to be paid.
	Amount quantity.Quantity `json:"amount"`
	// Gas is the maximum gas that a transaction can use.
	Gas Gas `json:"gas"`
}

// PrettyPrint writes a pretty-printed representation of the fee to the given
// writer.
func (f Fee) PrettyPrint(ctx context.Context, prefix string, w io.Writer) {
	fmt.Fprintf(w, "%sAmount: ", prefix)
	token.PrettyPrintAmount(ctx, f.Amount, w)
	fmt.Fprintln(w)

	fmt.Fprintf(w, "%sGas limit: %d\n", prefix, f.Gas)
	fmt.Fprintf(w, "%s(gas price: ", prefix)
	token.PrettyPrintAmount(ctx, *f.GasPrice(), w)
	fmt.Fprintln(w, " per gas unit)")
}

// PrettyType returns a representation of Fee that can be used for pretty
// printing.
func (f Fee) PrettyType() (interface{}, error) {
	return f, nil
}

// GasPrice returns the gas price implied by the amount and gas.
func (f Fee) GasPrice() *quantity.Quantity {
	if f.Amount.IsZero() || f.Gas == 0 {
		return quantity.NewQuantity()
	}

	var gasQ quantity.Quantity
	if err := gasQ.FromUint64(uint64(f.Gas)); err != nil {
		// Should never happen.
		panic(err)
	}

	amt := f.Amount.Clone()
	if err := amt.Quo(&gasQ); err != nil {
		// Should never happen.
		panic(err)
	}
	return amt
}

// Costs defines gas costs for different operations.
type Costs map[Op]Gas

// Op identifies an operation that requires gas to run.
type Op string
