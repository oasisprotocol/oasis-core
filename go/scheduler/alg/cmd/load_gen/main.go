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
	"github.com/oasislabs/ekiden/go/scheduler/alg/random_distribution"
)

var verbosity int
var seed int64
var distribution string
var alpha float64
var num_locations uint
var num_read_locs uint
var num_write_locs uint
var num_transactions uint

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
	flag.UintVar(&num_locations, "num_locations", 1<<20, "number of possible locations")
	flag.UintVar(&num_read_locs, "num_reads", 0, "number of read locations")
	flag.UintVar(&num_write_locs, "num_writes", 2, "number of write locations")
	flag.UintVar(&num_transactions, "num_transactions", 1<<20, "number of transactions to generate")
}

func generate_transactions(
	num_trans, num_reads, num_writes uint,
	gen random_distribution.DiscreteGenerator,
	out *bufio.Writer) {

	var tid uint
	for tid = 0; tid < num_trans; tid++ {
		t := alg.NewTransaction()
		var n uint
		for n = 0; n < num_reads; n++ {
			t.ReadSet.Add(alg.TestLocation(gen.Generate()))
		}
		for n = 0; n < num_writes; n++ {
			t.WriteSet.Add(alg.TestLocation(gen.Generate()))
		}
		t.TimeCost = 1
		t.CreationSeqno = tid
		t.Write(out)
		out.WriteRune('\n')
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
	if num_locations <= 0 {
		panic("Number of memory locations too small")
	}
	num_locations := int(num_locations)
	var rg random_distribution.DiscreteGenerator
	if distribution == "zipf" {
		rg = random_distribution.NewZipf(1.0, num_locations, rand.New(rand.NewSource(seed)))
	} else if distribution == "uniform" {
		rg = random_distribution.NewUniform(num_locations, rand.New(rand.NewSource(seed)))
	} else {
		panic(fmt.Sprintf("Random distribution %s not understood", distribution))
	}

	bw := bufio.NewWriter(os.Stdout)
	defer bw.Flush()

	generate_transactions(num_transactions, num_read_locs, num_write_locs, rg, bw)
}
