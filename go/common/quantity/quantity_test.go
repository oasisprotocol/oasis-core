package quantity

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

func fromInt(n int) *Quantity {
	q := NewQuantity()
	q.inner.SetInt64(int64(n))
	return q
}

func (q *Quantity) eqInt(n int) bool {
	nq := fromInt(n)
	return q.Cmp(nq) == 0
}

func TestQuantityCtors(t *testing.T) {
	require := require.New(t)

	q := NewQuantity()
	require.NotNil(q, "NewQuantity")
	require.True(q.eqInt(0), "New value")

	q = fromInt(23)
	nq := q.Clone()
	_ = q.FromBigInt(big.NewInt(666))
	require.True(nq.eqInt(23), "Clone value")
}

func TestFromBigInt(t *testing.T) {
	require := require.New(t)

	var q Quantity
	err := q.FromBigInt(nil)
	require.Equal(ErrInvalidQuantity, err, "FromBigInt(nil)")

	err = q.FromBigInt(big.NewInt(-1))
	require.Equal(ErrInvalidQuantity, err, "FromBigInt(-1)")

	err = q.FromBigInt(big.NewInt(23))
	require.NoError(err, "FromBigInt(23)")
	require.True(q.eqInt(23), "FromBigInt(23) value")
}

func TestFromInt64(t *testing.T) {
	require := require.New(t)

	var q Quantity
	err := q.FromInt64(-1)
	require.Equal(ErrInvalidQuantity, err, "FromInt64(-1)")

	err = q.FromInt64(23)
	require.NoError(err, "FromInt64(23)")
	require.True(q.eqInt(23), "FromInt64(23) value")
}

func TestFromUint64(t *testing.T) {
	require := require.New(t)

	var q Quantity
	err := q.FromUint64(46)
	require.NoError(err, "FromUint64(46)")
	require.True(q.eqInt(46), "FromUint64(46) value")

	err = q.FromUint64(0xFFFFFFFFFFFFFFFF)
	require.NoError(err, "FromUint64(0xFFFFFFFFFFFFFFFF)")

	var p Quantity
	p.inner.SetUint64(0xFFFFFFFFFFFFFFFF)
	require.True(q.Cmp(&p) == 0)
}

func TestQuantityBinaryRoundTrip(t *testing.T) {
	const expected int = 0xdeadbeef

	require := require.New(t)

	q := fromInt(expected)
	b, err := q.MarshalBinary()
	require.NoError(err, "MarshalBinary")

	var nq Quantity
	err = nq.UnmarshalBinary(b)
	require.NoError(err, "UnmarshalBinary")

	require.Zero(q.Cmp(&nq), "Round trip matches")
}

func TestQuantityCBORRoundTrip(t *testing.T) {
	require := require.New(t)

	// NOTE: These should be synced with runtime/src/common/quantity.rs.
	for _, tc := range []struct {
		value  uint64
		rawHex string
	}{
		{0, "40"},
		{1, "4101"},
		{10, "410a"},
		{100, "4164"},
		{1000, "4203e8"},
		{1000000, "430f4240"},
		{18446744073709551615, "48ffffffffffffffff"},
	} {
		raw, err := hex.DecodeString(tc.rawHex)
		require.NoError(err, "DecodeString(%s)", tc.rawHex)

		q := NewFromUint64(tc.value)
		enc := cbor.Marshal(q)
		require.EqualValues(raw, enc, "serialization should match")

		var dec Quantity
		err = cbor.Unmarshal(enc, &dec)
		require.NoError(err, "deserialization should succeed")
		require.EqualValues(&dec, q, "serialization should round-trip")
	}
}

func TestQuantityAdd(t *testing.T) {
	require := require.New(t)

	q := fromInt(100)

	err := q.Add(nil)
	require.Equal(ErrInvalidQuantity, err, "Add(nil)")

	err = q.Add(fromInt(-1))
	require.Equal(ErrInvalidQuantity, err, "Add(-1)")

	err = q.Add(fromInt(200))
	require.NoError(err, "Add")
	require.True(q.eqInt(300), "Add(200) value")
}

func TestQuantitySub(t *testing.T) {
	require := require.New(t)

	q := fromInt(100)

	err := q.Sub(nil)
	require.Equal(ErrInvalidQuantity, err, "Sub(nil)")

	err = q.Sub(fromInt(-1))
	require.Equal(ErrInvalidQuantity, err, "Sub(-1)")

	err = q.Sub(fromInt(200))
	require.Equal(ErrInsufficientBalance, err, "Sub(200)")

	err = q.Sub(fromInt(23))
	require.NoError(err, "Sub")
	require.True(q.eqInt(77), "Sub(23) value")
}

func TestQuantitySubUpTo(t *testing.T) {
	require := require.New(t)

	q := fromInt(100)

	_, err := q.SubUpTo(nil)
	require.Equal(ErrInvalidQuantity, err, "SubUpTo(nil)")

	_, err = q.SubUpTo(fromInt(-1))
	require.Equal(ErrInvalidQuantity, err, "SubUpTo(-1)")

	n, err := q.SubUpTo(fromInt(23))
	require.NoError(err, "SubUpTo")
	require.True(q.eqInt(77), "SubUpTo(23) value")
	require.True(n.eqInt(23), "SubUpTo(23) subtracted")

	n, err = q.SubUpTo(fromInt(9000))
	require.NoError(err, "SubUpTo(9000)")
	require.True(q.eqInt(0), "SubUpTo(9000) value")
	require.True(n.eqInt(77), "SubUpTo(9000) subtracted")
}

func TestQuantityMul(t *testing.T) {
	require := require.New(t)

	q := fromInt(100)

	err := q.Mul(nil)
	require.Equal(ErrInvalidQuantity, err, "Mul(nil)")

	err = q.Mul(fromInt(-1))
	require.Equal(ErrInvalidQuantity, err, "Mul(-1)")

	err = q.Mul(fromInt(23))
	require.NoError(err, "Mul")
	require.True(q.eqInt(2300), "Mul(23) value")
}

func TestQuantityQuo(t *testing.T) {
	require := require.New(t)

	q := fromInt(100)

	err := q.Quo(nil)
	require.Equal(ErrInvalidQuantity, err, "Quo(nil)")

	err = q.Quo(fromInt(-1))
	require.Equal(ErrInvalidQuantity, err, "Quo(-1)")

	err = q.Quo(fromInt(0))
	require.Equal(ErrInvalidQuantity, err, "Quo(0)")

	err = q.Quo(fromInt(50))
	require.NoError(err, "Quo")
	require.True(q.eqInt(2), "Quo(50) value")
}

func TestQuantityCmp(t *testing.T) {
	require := require.New(t)

	q := fromInt(100)

	require.Equal(-1, q.Cmp(fromInt(9001)), "q.Cmp(9001)")
	require.Equal(0, q.Cmp(fromInt(100)), "q.Cmp(100)")
	require.Equal(1, q.Cmp(fromInt(42)), "q.Cmp(42)")

	require.False(q.IsZero(), "q.IsZero()")
	require.True(NewQuantity().IsZero(), "NewQuantity().IsZero()")
}

func TestQuantityString(t *testing.T) {
	require := require.New(t)

	require.Equal("-500", fromInt(-500).String(), "Invalid returns raw inner")
	require.Equal("123456", fromInt(123456).String(), "Positive integer")
}

func TestMove(t *testing.T) {
	require := require.New(t)

	err := Move(nil, fromInt(100), fromInt(25))
	require.Equal(err, ErrInvalidAccount, "Move(nil, 100, 25)")
	err = Move(fromInt(50), nil, fromInt(25))
	require.Equal(err, ErrInvalidAccount, "Move(50, nil, 25)")
	err = Move(fromInt(50), fromInt(100), nil)
	require.Equal(err, ErrInvalidQuantity, "Move(50, 100, nil)")

	dst, src := fromInt(100), fromInt(300)
	err = Move(dst, src, fromInt(9000))
	require.Equal(err, ErrInsufficientBalance, "Move(100, 300, 9000)")
	require.True(dst.eqInt(100) && src.eqInt(300), "Move(fail) - dst/src unchanged")

	err = Move(dst, src, fromInt(75))
	require.NoError(err, "Move")
	require.True(dst.eqInt(175), "Move - dst value")
	require.True(src.eqInt(225), "Move - src value")
}

func TestMoveUpTo(t *testing.T) {
	require := require.New(t)

	_, err := MoveUpTo(nil, fromInt(100), fromInt(25))
	require.Equal(err, ErrInvalidAccount, "MoveUpTo(nil, 100, 25)")
	_, err = MoveUpTo(fromInt(50), nil, fromInt(25))
	require.Equal(err, ErrInvalidAccount, "MoveUpTo(50, nil, 25)")
	_, err = MoveUpTo(fromInt(50), fromInt(100), nil)
	require.Equal(err, ErrInvalidQuantity, "MoveUpTo(50, 100, nil)")

	dst, src := fromInt(100), fromInt(300)
	moved, err := MoveUpTo(dst, src, fromInt(75))
	require.NoError(err, "MoveUpTo")
	require.True(dst.eqInt(175), "MoveUpTo - dst value")
	require.True(src.eqInt(225), "MoveUpTo - src value")
	require.True(moved.eqInt(75), "MoveUpTo - moved")

	moved, err = MoveUpTo(dst, src, fromInt(90000))
	require.NoError(err, "MoveUpTo, oversized")
	require.True(dst.eqInt(400), "MoveUpTo, oversized - dst value")
	require.True(src.eqInt(0), "MoveUpTo, oversized - src value")
	require.True(moved.eqInt(225), "MoveUpTo, oversized - moved")
}
