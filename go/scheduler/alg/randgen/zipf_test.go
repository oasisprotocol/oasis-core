package randgen

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"
)

func TestZipfCdf(t *testing.T) {
	z, err := NewZipf(1.0, 1000000, rand.New(rand.NewSource(time.Now().UTC().UnixNano())))
	if err != nil {
		panic(err.Error())
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
	//                   1234567890123      1234567890123
	if math.Abs(cdf[1]-0.0694795377732) > 0.0000000000001 {
		t.Error("The first element differs from expected")
	}
	if math.Abs(cdf[99]-0.3597217968027) > 0.0000000000001 {
		t.Error("The 99th element differs from expected")
	}
}
