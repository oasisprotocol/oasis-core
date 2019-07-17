package polyring

import (
	"errors"
	"fmt"
	"math/rand"
	"strings"

	"github.com/ncw/gmp"
)

type Polynomial struct {
	coeff []*gmp.Int // coefficients P(x) = coeff[0] + coeff[1] x + ... + coeff[degree] x^degree ...
}

// GetDegree returns the degree, ignoring removing leading zeroes
func (poly Polynomial) GetDegree() int {
	deg := len(poly.coeff) - 1

	// note: i == 0 is not tested, because even the constant term is zero, we consider it's degree 0
	for i := deg; i > 0; i-- {
		if poly.coeff[i].CmpInt32(0) == 0 {
			deg--
		} else {
			break
		}
	}

	return deg
}

// GetCoefficient returns coeff[i]
func (poly Polynomial) GetCoefficient(i int) (gmp.Int, error) {
	if i < 0 || i >= len(poly.coeff) {
		return *gmp.NewInt(0), errors.New("out of boundary")
	}

	return *poly.coeff[i], nil
}

// GetAllCoeffcients returns a copy of
func (poly Polynomial) GetAllCoefficients() (all []*gmp.Int) {
	all = make([]*gmp.Int, poly.GetDegree()+1)

	for i := range all {
		all[i] = gmp.NewInt(0)
		all[i] = poly.coeff[i]
	}

	return all
}

func (poly Polynomial) DeepCopy() Polynomial {
	dst, err := New(poly.GetDegree())
	if err != nil {
		panic("deepcopy failed: " + err.Error())
	}

	for i := 0; i < len(dst.coeff); i++ {
		dst.coeff[i].Set(poly.coeff[i])
	}

	return dst
}

// GetLeadingCoefficient returns the coefficient of the highest degree of the variable
func (poly Polynomial) GetLeadingCoefficient() gmp.Int {
	lc := gmp.NewInt(0)
	lc.Set(poly.coeff[poly.GetDegree()])

	return *lc
}

// GetCoefficient returns a pointer to coeff[0]
func (poly Polynomial) GetPtrToConstant() *gmp.Int {
	return poly.coeff[0]
}

// SetCoefficient sets the poly.coeff[i] to ci
func (poly *Polynomial) SetCoefficient(i int, ci int64) error {
	if i < 0 || i >= len(poly.coeff) {
		return errors.New("out of boundary")
	}

	poly.coeff[i].SetInt64(ci)

	return nil
}

// SetCoefficientBig sets the poly.coeff[i] to ci (a gmp.Int)
func (poly *Polynomial) SetCoefficientBig(i int, ci *gmp.Int) error {
	if i < 0 || i >= len(poly.coeff) {
		return errors.New("out of boundary")
	}

	poly.coeff[i].Set(ci)

	return nil
}

// Reset sets the coefficients to zeroes
func (poly *Polynomial) Reset() {
	for i := 0; i < len(poly.coeff); i++ {
		poly.coeff[i].SetInt64(0)
	}
}

func (poly *Polynomial) ResetTo(other Polynomial) {
	poly.resetToDegree(other.GetDegree())

	for i := 0; i < other.GetDegree()+1; i++ {
		poly.coeff[i].Set(other.coeff[i])
	}
}

// resetToDegree resizes the slice to degree
func (poly *Polynomial) resetToDegree(degree int) {
	// if we just need to shrink the size
	if degree+1 <= len(poly.coeff) {
		poly.coeff = poly.coeff[:degree+1]
	} else {
		// if we need to grow the slice
		needed := degree + 1 - len(poly.coeff)
		neededPointers := make([]*gmp.Int, needed)
		for i := 0; i < len(neededPointers); i++ {
			neededPointers[i] = gmp.NewInt(0)
		}

		poly.coeff = append(poly.coeff, neededPointers...)
	}

	poly.Reset()
}

func (poly *Polynomial) shrinkToSize() {
	poly.coeff = poly.coeff[:poly.GetDegree()+1]
}

func (poly Polynomial) GetCap() int {
	return len(poly.coeff)
}

func (poly *Polynomial) GrowCapTo(cap int) {
	current := poly.GetCap()
	if cap <= current {
		return
	}

	// if we need to grow the slice
	needed := cap - current
	neededPointers := make([]*gmp.Int, needed)
	for i := 0; i < len(neededPointers); i++ {
		neededPointers[i] = gmp.NewInt(0)
	}

	poly.coeff = append(poly.coeff, neededPointers...)
}

// New returns a polynomial P(x) = 0 with capacity degree + 1
func New(degree int) (Polynomial, error) {
	if degree < 0 {
		return Polynomial{}, errors.New(fmt.Sprintf("degree must be non-negative, got %d", degree))
	}

	coeff := make([]*gmp.Int, degree+1)

	for i := 0; i < len(coeff); i++ {
		coeff[i] = gmp.NewInt(0)
	}

	//set the leading coefficient
	//coeff[len(coeff) - 1].SetInt64(1)

	return Polynomial{coeff}, nil
}

// NewOne returns create a constant polynomial P(x) = c
func NewConstant(c int64) Polynomial {
	zero, err := New(0)
	if err != nil {
		panic(err.Error())
	}

	zero.coeff[0] = gmp.NewInt(c)
	return zero
}

// NewOne creates a constant polynomial P(x) = 1
func NewOne() Polynomial {
	return NewConstant(1)
}

// NewEmpty creates a constant polynomial P(x) = 0
func NewEmpty() Polynomial {
	return NewConstant(0)
}

// NewRand returns a randomized polynomial with specified degree
// coefficients are pesudo-random numbers in [0, n)
func NewRand(degree int, rand *rand.Rand, n *gmp.Int) (Polynomial, error) {
	p, e := New(degree)
	if e != nil {
		return Polynomial{}, e
	}

	p.Rand(rand, n)

	return p, nil
}

func FromVec(coeff ...int64) Polynomial {
	if len(coeff) == 0 {
		return NewConstant(0)
	}
	deg := len(coeff) - 1

	poly, err := New(deg)
	if err != nil {
		panic(err.Error())
	}

	for i := range poly.coeff {
		poly.coeff[i].SetInt64(coeff[i])
	}

	return poly
}

func FromString(s string) Polynomial {
	// Convert input string to slice of gmp.Int
	coeffStr := strings.Split(s, ";")
	if len(coeffStr) == 0 {
		return NewConstant(0)
	}
	coeff := make([]*gmp.Int, 0)
	for i := 0; i < len(coeffStr); i++ {
		tmp := gmp.NewInt(0)
		tmp.SetString(coeffStr[i], 10)
		coeff = append(coeff, tmp)
	}
	// Determine poly degree
	deg := len(coeff) - 1
	for i := len(coeff) - 1; i >= 0; i-- {
		if coeff[i].CmpInt32(0) != 0 {
			continue
		}
		deg = i
	}
	// Create and return new poly
	poly, err := New(deg)
	if err != nil {
		panic(err.Error())
	}

	for i := range poly.coeff {
		poly.coeff[i].Set(coeff[i])
	}

	return poly
}

// Rand sets the polynomial coefficients to a pseudo-random number in [0, n)
// WARNING: Rand makes sure that the highest coefficient is not zero
func (poly *Polynomial) Rand(rand *rand.Rand, mod *gmp.Int) {
	for i := range poly.coeff {
		poly.coeff[i].Rand(rand, mod)
	}

	highest := len(poly.coeff) - 1

	for {
		if 0 == poly.coeff[highest].CmpInt32(0) {
			poly.coeff[highest].Rand(rand, mod)
		} else {
			break
		}
	}

}

// Converts to a string representation. Can be converted back using SetString
// 6 + 3x + 2x^2 => "6;3;2"
func (poly Polynomial) String() string {
	s := ""
	for i, coeff := range poly.coeff {
		s += coeff.String()
		if i < len(poly.coeff)-1 {
			s += ";"
		}
	}
	return s
}

func (poly Polynomial) ToString() string {
	var s = ""

	for i := len(poly.coeff) - 1; i >= 0; i-- {
		// skip zero coefficients but the constant term
		if i != 0 && poly.coeff[i].CmpInt32(0) == 0 {
			continue
		}
		if i > 0 {
			s += fmt.Sprintf("%s x^%d + ", poly.coeff[i].String(), i)
		} else {
			// constant term
			s += fmt.Sprintf("%s", poly.coeff[i].String())
		}
	}

	return s
}

// Print the polynomial
func (poly Polynomial) Print(title ...string) {
	var name = "P(x)"
	if len(title) > 0 {
		name = title[0]
	}

	fmt.Printf("%s = %s\n", name, poly.ToString())
}

// Print the degree
func (poly Polynomial) PrintDegree(title ...string) {
	var name = "P(x)"
	if len(title) > 0 {
		name = title[0]
	}

	fmt.Printf("deg %s = %d\n", name, poly.GetDegree())
}

// One sets the constant to one
func (poly *Polynomial) One() {
	poly.Reset()
	poly.coeff[0].SetInt64(1)
}

// I hate Go! how can we don't have min for integers
func min(a, b int) int {
	if a < b {
		return a
	} else {
		return b
	}
}

func max(a, b int) int {
	if a > b {
		return a
	} else {
		return b
	}
}

// Add sets poly to op1 + op2
func (poly *Polynomial) Add(op1 Polynomial, op2 Polynomial) error {
	// make sure poly is as long as the longest of op1 and op2
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	if deg1 > deg2 {
		poly.ResetTo(op1)
	} else {
		poly.ResetTo(op2)
	}

	for i := 0; i < min(deg1, deg2)+1; i++ {
		poly.coeff[i].Add(op1.coeff[i], op2.coeff[i])
	}

	// FIXME: no need to return error
	return nil
}

// AddSelf sets poly to poly + op
func (poly *Polynomial) AddSelf(op Polynomial) error {
	op1 := poly.DeepCopy()
	return poly.Add(op1, op)
}

// Sub sets poly to op1 - op2
func (poly *Polynomial) Sub(op1 Polynomial, op2 Polynomial) error {
	// make sure poly is as long as the longest of op1 and op2
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	if deg1 > deg2 {
		poly.ResetTo(op1)
	} else {
		poly.ResetTo(op2)
	}

	for i := 0; i < min(deg1, deg2)+1; i++ {
		poly.coeff[i].Sub(op1.coeff[i], op2.coeff[i])
	}

	poly.shrinkToSize()

	// FIXME: no need to return error
	return nil
}

// SubSelf sets poly to poly - op
func (poly *Polynomial) SubSelf(op Polynomial) error {
	// make sure poly is as long as the longest of op1 and op2
	deg1 := op.GetDegree()

	poly.GrowCapTo(deg1 + 1)

	for i := 0; i < deg1+1; i++ {
		poly.coeff[i].Sub(poly.coeff[i], op.coeff[i])
	}

	poly.shrinkToSize()

	// FIXME: no need to return error
	return nil
}

// MulSelf set poly to op1 * op2
func (poly *Polynomial) Mul(op1 Polynomial, op2 Polynomial) error {
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	poly.resetToDegree(deg1 + deg2)

	for i := 0; i <= deg1; i++ {
		for j := 0; j <= deg2; j++ {
			poly.coeff[i+j].AddMul(op1.coeff[i], op2.coeff[j])
		}
	}

	poly.shrinkToSize()
	// FIXME: no need to return
	return nil
}

// MulSelf set poly to poly * op
func (poly *Polynomial) MulSelf(op Polynomial) error {
	op1 := poly.DeepCopy()
	return poly.Mul(op1, op)
}

// AddMul sets poly to poly + poly2 * k (k being a scalar)
func (poly *Polynomial) AddMul(poly2 Polynomial, k *gmp.Int) {
	for i := 0; i <= poly2.GetDegree(); i++ {
		poly.coeff[i].AddMul(poly2.coeff[i], k)
	}
}

// DivMod sets computes q, r such that a = b*q + r.
// This is an implementation of Euclidean division. The complexity is O(n^3)!!
func DivMod(a Polynomial, b Polynomial, p *gmp.Int, q, r *Polynomial) (err error) {
	if b.IsZero() {
		return errors.New("divide by zero")
	}

	q.resetToDegree(0)
	r.ResetTo(a)

	d := b.GetDegree()
	c := b.GetLeadingCoefficient()

	// cInv = 1/c
	cInv := gmp.NewInt(0)
	cInv.ModInverse(&c, p)

	for r.GetDegree() >= d {
		lc := r.GetLeadingCoefficient()
		s, err := New(r.GetDegree() - d)
		if err != nil {
			return err
		}

		s.SetCoefficientBig(r.GetDegree()-d, lc.Mul(&lc, cInv))

		q.AddSelf(s)

		sb := NewEmpty()
		sb.Mul(s, b)

		// deg r reduces by each iteration
		r.SubSelf(sb)

		// modulo p
		q.Mod(p)
		r.Mod(p)
	}

	return nil
}

// Div2 sets poly to op1 / op2. **op2 must be of format x+a **
// Complexity is O(deg1)
func (poly *Polynomial) Div2(op1 Polynomial, op2 Polynomial) error {
	deg1 := op1.GetDegree()
	deg2 := op2.GetDegree()

	poly.resetToDegree(deg1)

	if deg2 != 1 {
		return errors.New("op2 must be of format x-a")
	}

	if poly.GetCap() < deg1-1 {
		return errors.New("receiver too small")
	}

	tmp := gmp.NewInt(0)

	inter, err := New(deg1)
	if err != nil {
		return errors.New("unknown error")
	}

	for i := 0; i <= deg1; i++ {
		inter.coeff[i].Set(op1.coeff[i])
	}

	for i := deg1; i > 0; i-- {
		poly.coeff[i-1].Div(inter.coeff[i], op2.coeff[deg2])
		for j := deg2; j >= 0; j-- {
			tmp.Mul(poly.coeff[i-1], op2.coeff[j])
			inter.coeff[i+j-deg2].Sub(inter.coeff[i+j-deg2], tmp)
		}
	}

	poly.shrinkToSize()
	return nil
}

// Mod sets poly to poly % p
func (poly *Polynomial) Mod(p *gmp.Int) {
	for i := 0; i < len(poly.coeff); i++ {
		poly.coeff[i].Mod(poly.coeff[i], p)
	}
}

// EvalMod returns poly(x) using Horner's rule. If p != nil, returns poly(x) mod p
func (poly Polynomial) EvalMod(x *gmp.Int, p *gmp.Int, result *gmp.Int) {
	result.Set(poly.coeff[poly.GetDegree()])

	for i := poly.GetDegree(); i >= 1; i-- {
		result.Mul(result, x)
		result.Add(result, poly.coeff[i-1])
	}

	if p != nil {
		result.Mod(result, p)
	}
}

// EvalArray returns poly[x[1]], ..., poly[x[n]]
func (poly Polynomial) EvalModArray(x []*gmp.Int, mod *gmp.Int, results []*gmp.Int) {
	for i := 0; i < len(x); i++ {
		poly.EvalMod(x[i], mod, results[i])
	}
}

// IsSame returns op == poly
func (poly Polynomial) IsSame(op Polynomial) bool {
	if op.GetDegree() != poly.GetDegree() {
		return false
	}

	for i := 0; i <= op.GetDegree(); i++ {
		if op.coeff[i].Cmp(poly.coeff[i]) != 0 {
			return false
		}
	}

	return true
}

// IsZero returns if poly == 0
func (poly Polynomial) IsZero() bool {
	if poly.GetDegree() != 0 {
		return false
	}

	return poly.GetPtrToConstant().CmpInt32(0) == 0
}

func VecInit(vec []*gmp.Int) {
	for i := 0; i < len(vec); i++ {
		vec[i] = gmp.NewInt(0)
	}
}

func VecRand(vec []*gmp.Int, p *gmp.Int, rand_state *rand.Rand) {
	for i := 0; i < len(vec); i++ {
		vec[i].Rand(rand_state, p)
	}
}

func VecPrint(vec []*gmp.Int) {
	for i := 0; i < len(vec); i++ {
		fmt.Printf("%s, ", vec[i].String())
	}
	fmt.Printf("\n")
}
