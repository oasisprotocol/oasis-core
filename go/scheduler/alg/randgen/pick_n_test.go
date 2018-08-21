package randgen

import (
	"flag"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var pickNFromNSeed int64

func init() {
	flag.Int64Var(&pickNFromNSeed, "pick-n-from-m-seed", 0, "pick-n-from-m reproducibility seed")
}

func ensureIsShuffle(t *testing.T, picker func(n, m int64, r *rand.Rand) []int64, pickerName string, size int64, r *rand.Rand) {
	t.Logf("%s: size %d shuffle\n", pickerName, size)
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
	t.Logf("%s(%d, %d, .)\n", pickerName, numElts, size)
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
		t.Logf("%d ", v)
	}
	t.Logf("\n")
}

func PickNFromMVarious(t *testing.T, picker func(n, m int64, r *rand.Rand) []int64, pickerName string) {
	assert := assert.New(t)
	handleTestSeed(t.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	ensureIsShuffle(t, picker, pickerName, 10, r)
	ensureIsShuffle(t, picker, pickerName, 100, r)
	ensureIsShuffle(t, picker, pickerName, 1000, r)
	ensureIsShuffle(t, picker, pickerName, 10000, r)

	efficientPickSmall(t, picker, pickerName, 10, 1000000000, r)
	efficientPickSmall(t, picker, pickerName, 10, 10000000000, r)
	efficientPickSmall(t, picker, pickerName, 10, 100000000000000, r)

	efficientPickSmall(t, picker, pickerName, 1000, 10000000000000000, r)
	efficientPickSmall(t, picker, pickerName, 1000, 100000000000000000, r)
	efficientPickSmall(t, picker, pickerName, 1000, 1000000000000000000, r)

	ensureIsShuffle(t, picker, pickerName, 1, r)
	efficientPickSmall(t, picker, pickerName, 0, 1, r)
	efficientPickSmall(t, picker, pickerName, 0, 1000000000000000000, r)

	assert.Panics(func() {
		ensureIsShuffle(t, picker, pickerName, 0, r)
	}, "shuffle of zero elements should panic")
	assert.Panics(func() {
		efficientPickSmall(t, picker, pickerName, 0, 0, r)
	}, "picking from zero elements from zero elements should panic")
	assert.Panics(func() {
		efficientPickSmall(t, picker, pickerName, 1, 0, r)
	}, "picking one element from zero elements should panic")
}

func TestPickNFromM(t *testing.T) {
	PickNFromMVarious(t, PickNFromMRemapping, "PickNFromMRemapping")
	PickNFromMVarious(t, PickNFromMRejectionSampling, "PickNFromMRejectionSampling")
	PickNFromMVarious(t, PickNFromM, "PickNFromM")
}

func doShuffleBench(b *testing.B, picker func(n, m int64, r *rand.Rand) []int64, pickerName string, r *rand.Rand) {
	b.Logf("%s: size %d shuffle\n", pickerName, b.N)
	_ = picker(int64(b.N), int64(b.N), r)
}

func BenchmarkShuffleRemapping(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doShuffleBench(b, PickNFromMRemapping, "PickNFromMRemapping", r)
}

func BenchmarkShuffleRejectionSampling(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doShuffleBench(b, PickNFromMRejectionSampling, "PickNFromMRejectionSampling", r)
}

func doPickSmall(b *testing.B, picker func(n, m int64, r *rand.Rand) []int64, pickerName string, pickNum int64, r *rand.Rand) {
	// We do not control b.N to ensure that it is large enough.
	if pickNum > int64(b.N) {
		pickNum = int64(b.N)
	}
	b.Logf("%s: %d from %d pick small  \n", pickerName, pickNum, b.N)
	_ = picker(pickNum, int64(b.N), r)
}

// repeat for various small values

func BenchmarkPickSmallRemapping10(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doPickSmall(b, PickNFromMRemapping, "PickNFromMRemapping", 10, r)
}

func BenchmarkPickSmallRejectionSampling10(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doPickSmall(b, PickNFromMRejectionSampling, "PickNFromMRejectionSampling", 10, r)
}

func BenchmarkPickSmallRemapping100(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doPickSmall(b, PickNFromMRemapping, "PickNFromMRemapping", 100, r)
}

func BenchmarkPickSmallRejectionSampling100(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doPickSmall(b, PickNFromMRejectionSampling, "PickNFromMRejectionSampling", 100, r)
}

func BenchmarkPickSmallRemapping1000(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doPickSmall(b, PickNFromMRemapping, "PickNFromMRemapping", 1000, r)
}

func BenchmarkPickSmallRejectionSampling1000(b *testing.B) {
	handleTestSeed(b.Logf, &pickNFromNSeed, "pick-n-from-m")
	r := rand.New(rand.NewSource(pickNFromNSeed))
	doPickSmall(b, PickNFromMRejectionSampling, "PickNFromMRejectionSampling", 1000, r)
}
