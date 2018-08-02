package random_distribution

import (
	"math/rand"
)

type Uniform struct {
	MaxValue int
	rng      *rand.Rand
}

func NewUniform(m int, r *rand.Rand) *Uniform {
	if m <= 0 {
		panic("uniform distribution with zero elements?")
	}
	return &Uniform{MaxValue: m, rng: r}
}

func (z *Uniform) Generate() int {
	return z.rng.Intn(z.MaxValue)
}
