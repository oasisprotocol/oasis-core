package random

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRandomGenerateValues(t *testing.T) {
	// Ensure that random number generation is consistent with the std library.
	rand1 := NewRand(0)
	rand2 := rand.New(rand.NewSource(0))

	assert.Equal(t, rand1.Float64(), rand2.Float64(), "should generate a float64")
	assert.Equal(t, rand1.Uint64(), rand2.Uint64(), "should generate a uint64")

	// Reseeding should keep the value equal.
	rand1.Seed(10)
	rand2.Seed(10)

	assert.Equal(t, rand1.Uint32(), rand2.Uint32(), "should generate a uint32")
}
