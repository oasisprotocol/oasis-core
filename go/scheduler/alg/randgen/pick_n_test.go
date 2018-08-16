package randgen

import (
	"flag"
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var pickNFromNSeed int64

func init() {
	flag.Int64Var(&pickNFromNSeed, "pick-n-from-m-seed", 0, "pick-n-from-m reproducibility seed")
}

// ShouldPanic runs f, which is expected to panic.
func ShouldPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered from expected panic in f", r)
		} else {
			t.Errorf("ShouldPanic: f() did not panic (in defer)")
		}
	}()
	f()
	t.Errorf("ShouldPanic: f() did not panic")
}

func ensureIsShuffle(t *testing.T, size int64, r *rand.Rand) {
	fmt.Printf("Size %d shuffle\n", size)
	shuffle := PickNFromM(size, size, r)
	for i := int64(0); i < int64(size); i++ {
		found := false
		for _, v := range(shuffle) {
			if v == i {
				found = true
			}
		}
		assert.True(t, found, "Shuffled element %d not found in result %v", i, shuffle)
	}
}

func efficientPickSmall(t *testing.T, numElts, size int64, r *rand.Rand) {
	fmt.Printf("PickNFromM(%d, %d, .)\n", numElts, size)
	sample := PickNFromM(numElts, size, r)
	// just ensure all elements are in [0, size)
	for _, v := range(sample) {
		assert.True(t, 0 <= v && v < size, "Found illegal element %d", v)
	}
	showElts := len(sample)
	if showElts > 20 {
		showElts = 20
	}
	for _, v := range(sample[:showElts]) {
		fmt.Printf("%d ", v)
	}
	fmt.Printf("\n")
}

func TestPickNFromM(t *testing.T) {
	handleTestSeed(&pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	ensureIsShuffle(t, 10, r)
	ensureIsShuffle(t, 100, r)
	ensureIsShuffle(t, 1000, r)

	efficientPickSmall(t, 10, 1000000000, r)
	efficientPickSmall(t, 10, 10000000000, r)
	efficientPickSmall(t, 10, 100000000000000, r)

	efficientPickSmall(t, 1000, 10000000000000000, r)
	efficientPickSmall(t, 1000, 100000000000000000, r)
	efficientPickSmall(t, 1000, 1000000000000000000, r)

	ensureIsShuffle(t, 1, r)
	efficientPickSmall(t, 0, 1, r)
	efficientPickSmall(t, 0, 1000000000000000000, r)

	ShouldPanic(t, func() {
		ensureIsShuffle(t, 0, r)
	})
	ShouldPanic(t, func() {
		efficientPickSmall(t, 0, 0, r)
	})
	ShouldPanic(t, func() {
		efficientPickSmall(t, 1, 0, r)
	})
}
