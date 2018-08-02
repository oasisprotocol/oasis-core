package random_distribution

// We cannot use math/rand's NewZipf because it requires s > 1.  (s
// corresponds to alpha in this implementation.)

// The algorithm implemented here is a bit memory intensive, since it
// generates a table representing the cumulative distribution function
// to take a uniformly-distributed random number in the half-open
// interval [0.0, 1.0) and map it into the integers [0, m).
//
// This algorithm works for any alpha: 0 <= alpha, but NB: if both
// alpha and m are large then the low-probability values near m will
// probably not be generated with the proper distribution because the
// CDF summing of large and very small numbers will essentially cause
// the small numbers to be ignored.

import (
	"math"
	"math/rand"
)

type Zipf struct {
	Alpha    float64
	MaxValue int
	rng      *rand.Rand
	cdf      []float64 // cumulative distribution function via table lookup
}

func NewZipf(a float64, m int, r *rand.Rand) *Zipf {
	if m <= 0 {
		panic("zipf distribution with zero elements?")
	}
	num_elts := m + 1
	if num_elts < m {
		panic("zipf distribution with too many elements")
	}
	v := make([]float64, num_elts) // could cause OOM
	v[0] = 0.0
	for ix := 1; ix <= m; ix++ {
		v[ix] = v[ix-1] + 1.0/math.Pow(float64(ix), a)
	}
	normalizer := 1.0 / v[m]
	for ix := 1; ix <= m; ix++ {
		v[ix] = normalizer * v[ix]
	}
	return &Zipf{Alpha: a, MaxValue: m, rng: r, cdf: v}
}

func (z *Zipf) Generate() int {
	uniform := z.rng.Float64()
	var low, high int
	low = 0
	high = z.MaxValue
	for low+1 < high {
		mid := (high-low)/2 + low
		v := z.cdf[mid]
		if v < uniform {
			low = mid
		} else {
			high = mid
		}
	}
	return low
}
