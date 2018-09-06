package main

/*

Synthetic load generator.

Generate random transactions with given read/write set sizes, with the
locations accessed generated using a specified distribution (uniform
or zipf).

*/

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/randgen"
)

var verbosity int
var seed int64
var distribution string
var alpha float64
var numLocations uint
var numReadLocs uint
var numWriteLocs uint
var numTransactions uint

func init() {
	flag.IntVar(&verbosity, "verbosity", 0, "verbosity level for debug output")
	flag.Int64Var(&seed, "seed", 0, "pseudorandom number generator seed")

	flag.StringVar(&distribution, "distribution", "zipf", "random location generation distribution (uniform or zipf)")
	flag.Float64Var(&alpha, "alpha", 1.0, "zipf distribution alpha parameter")
	// For the Ethereum world, the number of possible locations is
	// 2^{160+256}, but it is extremely sparse.  Furthermore, many
	// locations are in (pseudo) equivalence classes, i.e., if a
	// contract reads one of the locations, then it is almost
	// certainly going to read the rest, and similarly for writes.
	flag.UintVar(&numLocations, "numLocations", 1<<20, "number of possible locations")
	flag.UintVar(&numReadLocs, "numReads", 0, "number of read locations")
	flag.UintVar(&numWriteLocs, "numWrites", 2, "number of write locations")
	flag.UintVar(&numTransactions, "numTransactions", 1<<20, "number of transactions to generate")
}

func generateTransactions( // nolint: gosec
	numTrans, numReads, numWrites uint,
	gen randgen.Rng,
	out *bufio.Writer) {

	var tid uint
	for tid = 0; tid < numTrans; tid++ {
		t := alg.NewTransaction()
		var n uint
		for n = 0; n < numReads; n++ {
			t.ReadSet.Add(alg.TestLocation(gen.Generate()))
		}
		for n = 0; n < numWrites; n++ {
			t.WriteSet.Add(alg.TestLocation(gen.Generate()))
		}
		t.TimeCost = 1
		t.CreationSeqno = tid
		t.Write(out)
		_, _ = out.WriteRune('\n')
	}
}

func main() {
	flag.Parse()
	if verbosity > 0 {
		fmt.Println("verbosity has value ", verbosity)
	}
	if seed == 0 {
		seed = int64(time.Now().Nanosecond())
	}
	if numLocations <= 0 {
		panic("Number of memory locations too small")
	}
	numLocations := int(numLocations)
	var rg randgen.Rng
	var err error
	if distribution == "zipf" {
		rg, err = randgen.NewZipf(1.0, numLocations, rand.New(rand.NewSource(seed)))
		if err != nil {
			panic(err.Error())
		}
	} else if distribution == "uniform" {
		rg, err = randgen.NewUniform(numLocations, rand.New(rand.NewSource(seed)))
		if err != nil {
			panic(err.Error())
		}
	} else {
		panic(fmt.Sprintf("Random distribution %s not understood", distribution))
	}

	bw := bufio.NewWriter(os.Stdout)
	defer func(bw *bufio.Writer) {
		if err := bw.Flush(); err != nil {
			panic(fmt.Sprintf("I/O error: %s", err))
		}
	}(bw)

	generateTransactions(numTransactions, numReadLocs, numWriteLocs, rg, bw)
}
