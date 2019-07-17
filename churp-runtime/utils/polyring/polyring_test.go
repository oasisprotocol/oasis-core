package polyring

import (
	"math/rand"
	"testing"

	"github.com/ncw/gmp"
	"github.com/stretchr/testify/assert"
)

const RAND_SEED = 1

var randomness = rand.New(rand.NewSource(RAND_SEED))

func TestNew(t *testing.T) {
	ZERO := gmp.NewInt(0)

	degree := 100
	poly, err := New(degree)

	assert.Nil(t, err, "error in New")
	assert.Equal(t, degree+1, len(poly.coeff), "coeff len")

	for i := 0; i < len(poly.coeff); i++ {
		assert.Zero(t, poly.coeff[i].Cmp(ZERO))
	}

	_, err = New(-1)
	assert.NotNil(t, err, "negative degree")
}

func TestNewOne(t *testing.T) {
	ONE := gmp.NewInt(1)

	onePoly := NewOne()

	assert.Equal(t, 0, onePoly.GetDegree(), "degree")
	assert.Equal(t, 1, len(onePoly.coeff), "coeff len")

	assert.Equal(t, 0, ONE.Cmp(onePoly.coeff[0]))
}

func TestNewEmpty(t *testing.T) {
	emptyPoly := NewEmpty()

	assert.Equal(t, 0, emptyPoly.GetDegree(), "degree")
	assert.Equal(t, int32(0), emptyPoly.GetPtrToConstant().Int32(), "const")
}

func TestNewRand(t *testing.T) {
	var degree = 100
	var n = gmp.NewInt(1000)

	r := rand.New(rand.NewSource(RAND_SEED))
	poly, err := NewRand(degree, r, n)
	assert.Nil(t, err, "err in NewRand")

	assert.Equal(t, degree+1, len(poly.coeff), "coeff len")

	for i := range poly.coeff {
		assert.Equal(t, -1, poly.coeff[i].Cmp(n), "rand range")
	}
}

func TestPolynomial_ResetToDegree(t *testing.T) {
	op1 := FromVec(1, 1, 1, 1, 1, 1)

	op1.resetToDegree(100)
}

func TestPolynomialCap(t *testing.T) {
	op := FromVec(1, 1, 1, 1, 1, 1, 0, 0, 0)
	assert.Equal(t, 9, op.GetCap())

	op.GrowCapTo(100)
	assert.Equal(t, 100, op.GetCap())
}

func TestPolynomial_ShrinkToSize(t *testing.T) {
	op1 := FromVec(1, 1, 1, 1, 1, 1, 0, 0, 0)

	op1.shrinkToSize()

	assert.Equal(t, 5, op1.GetDegree())

	op1 = FromVec(0, 0, 0, 0, 0)

	op1.shrinkToSize()

	assert.Equal(t, 0, op1.GetDegree())
}

func TestPolynomial_Add(t *testing.T) {
	var degree = 10
	var n = gmp.NewInt(1000)

	poly1, err := NewRand(degree, randomness, n)
	assert.Nil(t, err, "err in NewRand")

	poly2, err := NewRand(degree, randomness, n)
	assert.Nil(t, err, "err in NewRand")

	result := NewEmpty()

	err = result.Add(poly1, poly2)
	assert.Nil(t, err, "add")

	var tmp = gmp.NewInt(0)
	for i := 0; i <= degree; i++ {
		tmp.Add(poly1.coeff[i], poly2.coeff[i])
		assert.Zero(t, result.coeff[i].Cmp(tmp), "add result")
		tmp.SetInt64(0)
	}
}

func TestPolynomial_Sub(t *testing.T) {
	var tests = []struct {
		op1      []int64
		op2      []int64
		expected []int64
	}{
		{[]int64{1, 1}, []int64{0, 1}, []int64{1}},
		{[]int64{1, 1, 1}, []int64{1, 1, 1}, []int64{0}},
	}

	for _, test := range tests {
		op1 := FromVec(test.op1...)
		op2 := FromVec(test.op2...)
		expected := FromVec(test.expected...)

		result, _ := New(op1.GetDegree())
		result.Sub(op1, op2)

		assert.True(t, expected.IsSame(result))
	}

}

func TestPolynomial_AddMul(t *testing.T) {
	var degree = 100
	var n = gmp.NewInt(1000)

	r := rand.New(rand.NewSource(RAND_SEED))
	poly1, err := NewRand(degree, r, n)
	assert.Nil(t, err, "err in NewRand")

	poly2, err := NewRand(degree, r, n)
	assert.Nil(t, err, "err in NewRand")

	polyOnePlusTwo, _ := New(degree)
	polyOnePlusTwo.Add(poly1, poly2)

	poly1.AddMul(poly2, gmp.NewInt(1))
	assert.True(t, poly1.IsSame(polyOnePlusTwo))
}

func TestPolynomial_AddSelf(t *testing.T) {
	var degree = 100
	var n = gmp.NewInt(1000)

	poly1, err := NewRand(degree, randomness, n)
	assert.Nil(t, err, "err in NewRand")

	poly2, err := NewRand(degree, randomness, n)
	assert.Nil(t, err, "err in NewRand")

	// add two polys using Add
	result, err := New(degree)
	result.Add(poly1, poly2)

	// add two polys using AddSelf
	err = poly1.AddSelf(poly2)
	assert.Nil(t, err, "add")

	assert.True(t, result.IsSame(poly1), "addself")
}

func TestPolynomial_Mul(t *testing.T) {
	op1 := FromVec(1, 1, 1, 1, 1, 1)
	result := NewEmpty()

	err := result.Mul(op1, op1)
	assert.Nil(t, err, "Mul")

	expected := FromVec(1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1)
	assert.True(t, expected.IsSame(result), "Mul")
}

func TestPolynomial_MulSelf(t *testing.T) {
	op1 := FromVec(1, 1, 1, 1, 1, 1)

	poly := FromVec(1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0)

	err := poly.MulSelf(op1)
	assert.Nil(t, err, "MulSelf")

	expected := FromVec(1, 2, 3, 4, 5, 6, 5, 4, 3, 2, 1)
	assert.True(t, expected.IsSame(poly), "MulSelf")
}

func TestPolynomial_Div2(t *testing.T) {
	var degree = 100

	var n = gmp.NewInt(1000)
	randPoly, err := NewRand(degree, randomness, n)
	assert.Nil(t, err, "NewRand")

	// op2(x) = x + 1
	op2 := FromVec(1, 1)

	productPoly, err := New(randPoly.GetDegree() + op2.GetDegree())
	assert.Nil(t, err, "New")

	productPoly.Mul(randPoly, op2)

	result := NewEmpty()

	// result = randPoly / op2
	err = result.Div2(productPoly, op2)
	assert.Nil(t, err, "Div2")

	assert.True(t, result.IsSame(randPoly))

	// test invalid input
	err = result.Div2(productPoly, randPoly)
	assert.NotNil(t, err, "Div2 only accept x-a as op2")
}

func TestPolynomial_GetDegree(t *testing.T) {
	var tests = []struct {
		coeffs []int64
		degree int
	}{
		{[]int64{1, 1}, 1},
		{[]int64{0, 1, 0}, 1},
		{[]int64{0, 0}, 0},
		{[]int64{1, 0, 0, 1}, 3},
	}

	for _, test := range tests {
		p := FromVec(test.coeffs...)
		assert.Equal(t, test.degree, p.GetDegree(), "%s", test.coeffs)
	}
}

func TestPolynomial_GetCoefficient(t *testing.T) {
	var tests = []struct {
		coeffs      []int64
		getAt       int
		expected    int64
		expectError bool
	}{
		{[]int64{1, 1}, 1, 1, false},
		{[]int64{0, 1, 0}, 3, 1, true},
		{[]int64{0, 0}, 0, 0, false},
		{[]int64{1, 0, 0, 1}, 3, 1, false},
	}

	for _, test := range tests {
		p := FromVec(test.coeffs...)
		coeff, err := p.GetCoefficient(test.getAt)
		if test.expectError {
			assert.NotNil(t, err, p.ToString())
		} else {
			assert.Equal(t, test.expected, coeff.Int64(), p.ToString())
		}
	}
}

func TestPolynomial_EvalMod(t *testing.T) {
	var tests = []struct {
		coeffs   []int64
		evalAt   int64
		expected int64
	}{
		{[]int64{1, 1}, 1, 2},
		{[]int64{1, 2, 3}, 0, 1},
		{[]int64{1, 2, 3}, 1, 6},
		{[]int64{1, 2, 3}, 2, 17},
		{[]int64{2, 2}, 0, 2},
		{[]int64{1, 0, 0, 1, 0}, 3, 28},
	}

	mod := gmp.NewInt(100)

	for _, test := range tests {
		p := FromVec(test.coeffs...)
		eval := gmp.NewInt(0)
		p.EvalMod(gmp.NewInt(test.evalAt), mod, eval)
		assert.Equal(t, test.expected, eval.Int64(), p.ToString())
	}
}

func TestPolynomial_EvalModArray(t *testing.T) {
	var tests = []struct {
		coeffs   []int64
		evalAt   []int64
		expected []int64
	}{
		{[]int64{1, 2, 3}, []int64{0, 1, 2}, []int64{1, 6, 17}},
	}

	mod := gmp.NewInt(100)

	for _, test := range tests {
		p := FromVec(test.coeffs...)

		x := make([]*gmp.Int, len(test.evalAt))
		for i, xx := range test.evalAt {
			x[i] = gmp.NewInt(xx)
		}

		evalResults := make([]*gmp.Int, len(test.evalAt))
		VecInit(evalResults)

		p.EvalModArray(x, mod, evalResults)

		y := make([]int64, len(evalResults))
		for i, yy := range evalResults {
			y[i] = yy.Int64()
		}
		assert.Equal(t, test.expected, y, p.ToString())
	}
}

func TestPolynomial_GetLeadingCoefficient(t *testing.T) {
	var tests = []struct {
		coeffs   []int64
		expected int64
	}{
		{[]int64{1, 1}, 1},
		{[]int64{1, 2, 3}, 3},
		{[]int64{2, 2}, 2},
		{[]int64{1, 0, 0, 1, 0}, 1},
	}

	for _, test := range tests {
		p := FromVec(test.coeffs...)
		lc := p.GetLeadingCoefficient()
		assert.Equal(t, 0, gmp.NewInt(test.expected).Cmp(&lc))
	}
}

func TestPolynomial_ResetTo(t *testing.T) {
	var tests = []struct {
		coeffs   []int64
		expected int64
	}{
		{[]int64{1, 1}, 7},
		{[]int64{1, 2, 3}, 8},
		{[]int64{2, 2}, 234},
		{[]int64{1, 0, 0, 1, 0}, 12384776},
	}

	for _, test := range tests {
		empty := NewEmpty()
		p := FromVec(test.coeffs...)
		empty.ResetTo(p)
		assert.True(t, empty.IsSame(p))
	}
}

func TestDiv(t *testing.T) {
	mod := gmp.NewInt(17)

	// to test if q, r = DivMod(a, b)
	var tests = []struct {
		a []int64
		b []int64
		q []int64
		r []int64
	}{
		{[]int64{1, 2, 1}, []int64{1, 1}, []int64{1, 1}, []int64{}},
		{[]int64{7, 0, 0, 0, 2, 1}, []int64{-5, 0, 0, 1}, []int64{0, 2, 1}, []int64{7, 10, 5}},
		{[]int64{7, 10, 5, 2}, []int64{4, 0, 1}, []int64{5, 2}, []int64{4, 2}},
		{[]int64{1, 2, 1}, []int64{1, 2}, []int64{5, 9}, []int64{13}},
	}

	for _, test := range tests {
		a := FromVec(test.a...)
		b := FromVec(test.b...)
		q := FromVec(test.q...)
		r := FromVec(test.r...)

		qq, rr := NewEmpty(), NewEmpty()
		err := DivMod(a, b, mod, &qq, &rr)
		assert.Nil(t, err, "DivMod")

		assert.True(t, qq.IsSame(q))
		assert.True(t, rr.IsSame(r))
	}
}
