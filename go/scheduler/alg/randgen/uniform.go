package randgen

import (
	"fmt"
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
func NewUniform(m int, r *rand.Rand) (*Uniform, error) {
	if m <= 0 {
		return nil, fmt.Errorf("uniform distribution with zero or fewer (%d) elements?", m)
	}
	return &Uniform{MaxValue: m, rng: r}, nil
}

// Generate a uniformly random number in [0, MaxValue).
func (z *Uniform) Generate() int {
	return z.rng.Intn(z.MaxValue)
}
