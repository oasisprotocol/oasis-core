package randgen

import (
	"flag"
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

var seed int64

func init() {
	flag.Int64Var(&seed, "seed", 0, "test reproducibility seed value")
}

// nolint: gocyclo
func TestZipfCdf(t *testing.T) {
	const maxValue = 1000000
	if seed == 0 {
		seed = time.Now().UTC().UnixNano()
	}
	fmt.Printf("TestZipfCdf seed = %d\n", seed)
	z, err := NewZipf(1.0, maxValue, rand.New(rand.NewSource(seed)))
	if err != nil {
		t.Errorf("NewZipf failed: %s", err.Error())
	}
	cdf := z.cdf
	for ix := 0; ix < 100; ix++ {
		fmt.Printf("%2d: %15.13f\n", ix, cdf[ix])
	}
	if cdf[0] != 0.0 {
		t.Error("zeroth element should be zero exactly")
	}
	if cdf[1000000] != 1.0 {
		t.Error("last element should be 1.0 exactly")
	}
	const margin = 1.0e-13
	//                   1234567890123
	if math.Abs(cdf[1]-0.0694795377732) > margin {
		t.Error("The first element differs from expected")
	}
	if math.Abs(cdf[99]-0.3597217968027) > margin {
		t.Error("The 99th element differs from expected")
	}
	for cnt := 0; cnt < 1000; cnt++ {
		if v := z.Generate(); v < 0.0 || v >= maxValue {
			t.Error("generator output out of range")
		}
	}
}
