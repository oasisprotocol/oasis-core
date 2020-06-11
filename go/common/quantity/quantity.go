package quantity

import (
	"encoding"
	"errors"
	"math/big"
)

var (
	// ErrInvalidQuantity is the error returned on malformed arguments.
	ErrInvalidQuantity = errors.New("invalid quantity")

	// ErrInsufficientBalance is the error returned when an operation
	// fails due to insufficient balance.
	ErrInsufficientBalance = errors.New("insufficient balance")

	// ErrInvalidAccount is the error returned when an operation fails
	// due to a missing account.
	ErrInvalidAccount = errors.New("invalid account")

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

	if !q.IsValid() {
		return ErrInvalidQuantity
	}

	return nil
}

// MarshalText encodes a Quantity into text form.
func (q Quantity) MarshalText() ([]byte, error) {
	return q.inner.MarshalText()
}

// UnmarshalText decodes a text slice into a Quantity.
func (q *Quantity) UnmarshalText(text []byte) error {
	var tmp big.Int
	if err := tmp.UnmarshalText(text); err != nil {
		return err
	}
	q.inner.Set(&tmp)

	if !q.IsValid() {
		return ErrInvalidQuantity
	}

	return nil
}

// FromInt64 converts from an int64 to a Quantity.
func (q *Quantity) FromInt64(n int64) error {
	return q.FromBigInt(big.NewInt(n))
}

// FromUint64 converts from an uint64 to a Quantity.
func (q *Quantity) FromUint64(n uint64) error {
	var tmp big.Int
	tmp.SetUint64(n)

	return q.FromBigInt(&tmp)
}

// FromBigInt converts from a big.Int to a Quantity.
func (q *Quantity) FromBigInt(n *big.Int) error {
	if n == nil || !isValid(n) {
		return ErrInvalidQuantity
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
		return ErrInvalidQuantity
	}

	q.inner.Add(&q.inner, &n.inner)

	return nil
}

// Sub subtracts exactly n from q, returning an error if q < n, n < 0 or
// n == nil.
func (q *Quantity) Sub(n *Quantity) error {
	if n == nil || !n.IsValid() {
		return ErrInvalidQuantity
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
		return nil, ErrInvalidQuantity
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

// Mul multiplies n with q, returning an error if n < 0 or n == nil.
func (q *Quantity) Mul(n *Quantity) error {
	if n == nil || !n.IsValid() {
		return ErrInvalidQuantity
	}

	q.inner.Mul(&q.inner, &n.inner)

	return nil
}

// Quo divides q with n, returning an error if n <= 0 or n == nil.
func (q *Quantity) Quo(n *Quantity) error {
	if n == nil || !n.IsValid() || n.IsZero() {
		return ErrInvalidQuantity
	}

	q.inner.Quo(&q.inner, &n.inner)

	return nil
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

// NewFromUint64 creates a new Quantity from an uint64 or panics.
func NewFromUint64(n uint64) *Quantity {
	var q Quantity
	if err := q.FromUint64(n); err != nil {
		panic(err)
	}
	return &q
}

func isValid(n *big.Int) bool {
	return n.Cmp(&zero) >= 0
}

// Move moves exactly n from src to dst.  On failures neither src nor dst
// are altered.
func Move(dst, src, n *Quantity) error {
	if dst == nil || src == nil {
		return ErrInvalidAccount
	}
	if src == n {
		n = n.Clone()
	}
	if err := src.Sub(n); err != nil {
		return err
	}
	_ = dst.Add(n)

	return nil
}

// MoveUpTo moves up to n from src to dst, and returns the amount moved.
// On failures neither src nor dst are altered.
func MoveUpTo(dst, src, n *Quantity) (*Quantity, error) {
	if dst == nil || src == nil {
		return nil, ErrInvalidAccount
	}
	amount, err := src.SubUpTo(n)
	if err != nil {
		return nil, err
	}
	_ = dst.Add(amount)

	return amount, nil
}
