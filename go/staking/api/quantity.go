package api

import (
	"encoding"
	"math/big"
)

var (
	_ encoding.BinaryMarshaler   = (*Quantity)(nil)
	_ encoding.BinaryUnmarshaler = (*Quantity)(nil)

	zero big.Int
)

// Quantity is a arbitrary precision unsigned integer that never underflows.
type Quantity struct {
	inner big.Int
}

// Clone copies a Quantity.
func (q *Quantity) Clone() *Quantity {
	tmp := NewQuantity()
	tmp.inner.Set(&q.inner)
	return tmp
}

// MarshalBinary encodes a Quantity into binary form.
func (q *Quantity) MarshalBinary() ([]byte, error) {
	return append([]byte{}, q.inner.Bytes()...), nil
}

// UnmarshalBinary decodes a byte slice into a Quantity.
func (q *Quantity) UnmarshalBinary(data []byte) error {
	var tmp big.Int
	tmp.SetBytes(data)
	q.inner.Set(&tmp)

	return nil
}

// FromBigInt converts from a big.Int to a Quantity.
func (q *Quantity) FromBigInt(n *big.Int) error {
	if n == nil || !isValid(n) {
		return ErrInvalidArgument
	}

	q.inner.Set(n)

	return nil
}

// ToBigInt converts from a Quantity to a big.Int.
func (q *Quantity) ToBigInt() *big.Int {
	var tmp big.Int
	tmp.Set(&q.inner)

	return &tmp
}

// Add adds n to q, returning an error if n < 0 or n == nil.
func (q *Quantity) Add(n *Quantity) error {
	if n == nil || !n.IsValid() {
		return ErrInvalidArgument
	}

	q.inner.Add(&q.inner, &n.inner)

	return nil
}

// Sub subtracts exactly n from q, returning an error if q < n, n < 0 or
// n == nil.
func (q *Quantity) Sub(n *Quantity) error {
	if n == nil || !n.IsValid() {
		return ErrInvalidArgument
	}
	if q.inner.Cmp(&n.inner) == -1 {
		return ErrInsufficientBalance
	}

	q.inner.Sub(&q.inner, &n.inner)

	return nil
}

// SubUpTo subtracts up to n from q, and returns the amount subtracted,
// returning an error if n < 0 or n == nil.
func (q *Quantity) SubUpTo(n *Quantity) (*Quantity, error) {
	if n == nil || !n.IsValid() {
		return nil, ErrInvalidArgument
	}

	var amount big.Int
	switch q.Cmp(n) {
	case -1:
		amount.Set(&q.inner)
	default:
		amount.Set(&n.inner)
	}

	q.inner.Sub(&q.inner, &amount)

	return &Quantity{inner: amount}, nil
}

// Cmp returns -1 if q < n, 0 if q == n, and 1 if q > n.
func (q *Quantity) Cmp(n *Quantity) int {
	return q.inner.Cmp(&n.inner)
}

// IsZero returns true iff the quantity is zero.
func (q *Quantity) IsZero() bool {
	return q.inner.CmpAbs(&zero) == 0
}

// String returns the string representation of q.
func (q Quantity) String() string {
	// Return the string representation of inner directly if the value
	// is invalid, for the purpose of error messages.
	if !q.IsValid() {
		return q.inner.String()
	}

	var tmp big.Int
	tmp.Abs(&q.inner)
	return tmp.String()
}

// IsValid returns true iff the quantity is in the valid range.
func (q *Quantity) IsValid() bool {
	return isValid(&q.inner)
}

// New creates a new Quantity, initialized to zero.
func NewQuantity() (q *Quantity) {
	return &Quantity{}
}

func isValid(n *big.Int) bool {
	return n.Cmp(&zero) >= 0
}
