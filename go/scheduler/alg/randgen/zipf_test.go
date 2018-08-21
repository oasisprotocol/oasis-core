package randgen

import (
	"flag"
	"math"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var zipfSeed int64

func init() {
	flag.Int64Var(&zipfSeed, "zipf-test-seed", 0, "zipf-test reproducibility seed value")
}

func TestZipfNew(t *testing.T) {
	assert := assert.New(t)
	handleTestSeed(t.Logf, &zipfSeed, "zipf CDF test")
	r := rand.New(rand.NewSource(zipfSeed))
	_, err := NewZipf(-1.0, 100000, r)
	assert.Error(err, "Negative exponent should not work")
	_, err = NewZipf(1.5, 0, r)
	assert.Error(err, "Zero possible values should not work")
	_, err = NewZipf(1.5, -1, r)
	assert.Error(err, "Negative possible values should not work")
	maxint := int(math.MaxInt64)
	if maxint < 0 {
		maxint = int(math.MaxInt32)
	}
	_, err = NewZipf(1.5, maxint, r)
	assert.Error(err, "MaxInt values should not work")
}

// nolint: gocyclo
func TestZipfCdf(t *testing.T) {
	assert := assert.New(t)
	const maxValue = 1000000
	handleTestSeed(t.Logf, &zipfSeed, "zipf CDF test")
	z, err := NewZipf(1.0, maxValue, rand.New(rand.NewSource(zipfSeed)))
	if err != nil {
		t.Errorf("NewZipf failed: %s", err.Error())
	}
	cdf := z.cdf
	assert.Equal(0.0, cdf[0], "zeroth element should be zero exactly")

	if cdf[1000000] != 1.0 {
		t.Error("last element should be 1.0 exactly")
	}
	const margin = 1.0e-12 // percent difference
	//                 0123456789012
	assert.InEpsilon(0.0694795377732, cdf[1], margin, "The first element differs from expected")
	//                 1234567890123
	assert.InEpsilon(0.3597217968027, cdf[99], margin, "The 99th element differs from expected")

	for cnt := 0; cnt < 1000; cnt++ {
		if v := z.Generate(); v < 0.0 || v >= maxValue {
			t.Error("generator output out of range")
		}
	}
}
