package randgen

import (
	"math/rand"
)

// Uniform implements the Rng interface and generates uniform random numbers in the half-open
// interval [0, MaxValue).
type Uniform struct {
	MaxValue int
	rng      *rand.Rand
}

// NewUniform returns a newly constructed Uniform object.  This is a thin wrapper around rand's
// Intn.
func NewUniform(m int, r *rand.Rand) *Uniform {
	if m <= 0 {
		panic("uniform distribution with zero elements?")
	}
	return &Uniform{MaxValue: m, rng: r}
}

// Generate a uniformly random number in [0, MaxValue).
func (z *Uniform) Generate() int {
	return z.rng.Intn(z.MaxValue)
}
