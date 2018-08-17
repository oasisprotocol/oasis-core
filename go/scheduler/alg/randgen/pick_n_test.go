package randgen

import (
	"flag"
	"fmt"
	"math/rand"
	"testing"
	"time"

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

func ensureIsShuffle(t *testing.T, picker func(n, m int64, r *rand.Rand) []int64, pickerName string, size int64, r *rand.Rand) {
	fmt.Printf("%s: size %d shuffle\n", pickerName, size)
	shuffle := picker(size, size, r)
	seen := make(map[int64]struct{})
	for _, v := range shuffle {
		assert.True(t, 0 <= v && v < size, "Shuffle element %d out of range\n", v)
		_, twice := seen[v]
		assert.False(t, twice, "Shuffle element %d duplicate in result\n", v)
		seen[v] = struct{}{}
	}
	assert.Equal(t, size, int64(len(shuffle)), "Not all elements found in shuffle\n")
}

func efficientPickSmall(t *testing.T, picker func(n, m int64, r *rand.Rand) []int64, pickerName string, numElts, size int64, r *rand.Rand) {
	fmt.Printf("%s(%d, %d, .)\n", pickerName, numElts, size)
	sample := picker(numElts, size, r)
	// just ensure all elements are in [0, size)
	for _, v := range sample {
		assert.True(t, 0 <= v && v < size, "Found illegal element %d", v)
	}
	showElts := len(sample)
	if showElts > 20 {
		showElts = 20
	}
	for _, v := range sample[:showElts] {
		fmt.Printf("%d ", v)
	}
	fmt.Printf("\n")
}

func timeFunc(f func()) {
	startTime := time.Now()
	f()
	elapsedTime := time.Since(startTime)
	fmt.Printf("Time took %s\n", elapsedTime)
}

func PickNFromMVarious(t *testing.T, picker func(n, m int64, r *rand.Rand) []int64, pickerName string) {
	handleTestSeed(&pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	ensureIsShuffle(t, picker, pickerName, 10, r)
	ensureIsShuffle(t, picker, pickerName, 100, r)
	ensureIsShuffle(t, picker, pickerName, 1000, r)
	ensureIsShuffle(t, picker, pickerName, 10000, r)
	timeFunc(func() { ensureIsShuffle(t, picker, pickerName, 1000000, r) })

	efficientPickSmall(t, picker, pickerName, 10, 1000000000, r)
	efficientPickSmall(t, picker, pickerName, 10, 10000000000, r)
	efficientPickSmall(t, picker, pickerName, 10, 100000000000000, r)

	efficientPickSmall(t, picker, pickerName, 1000, 10000000000000000, r)
	efficientPickSmall(t, picker, pickerName, 1000, 100000000000000000, r)
	efficientPickSmall(t, picker, pickerName, 1000, 1000000000000000000, r)

	ensureIsShuffle(t, picker, pickerName, 1, r)
	efficientPickSmall(t, picker, pickerName, 0, 1, r)
	efficientPickSmall(t, picker, pickerName, 0, 1000000000000000000, r)

	ShouldPanic(t, func() {
		ensureIsShuffle(t, picker, pickerName, 0, r)
	})
	ShouldPanic(t, func() {
		efficientPickSmall(t, picker, pickerName, 0, 0, r)
	})
	ShouldPanic(t, func() {
		efficientPickSmall(t, picker, pickerName, 1, 0, r)
	})
}

func TestPickNFromM(t *testing.T) {
	PickNFromMVarious(t, PickNFromMRemapping, "PickNFromMRemapping")
	PickNFromMVarious(t, PickNFromMRejectionSampling, "PickNFromMRejectionSampling")
}
