package main

/*

Scheduling algorithm driver.

Generate / read random transactions and feed into selected scheduling algorithm.

*/

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/oasislabs/ekiden/go/scheduler/alg/random_distribution"
	"github.com/oasislabs/ekiden/go/scheduler/alg"
)

var verbosity int

type DistributionConfig struct {
	seed int64
	distribution_name string
	input_file string  // "-" means standard input
	output_file string
	alpha float64
	num_locations uint
	num_read_locs uint
	num_write_locs uint
	num_transactions uint
}

dconfig_from_flags := DistributionConfig{}

var scheduler_name string

func init() {
	flag.IntVar(&verbosity, "verbosity", 0, "verbosity level for debug output")

	flag.StringVar(&scheduler_name, "scheduler", "greedy_subgraph", "scheduling algorithm")

	// Distribution generator parameters

	// seed is only important for reproducible RNG; input_file/output_file is another mechanism for reproducibility
	flag.Int64Var(&dconfig_from_flags.seed, "seed", 0, "pseudorandom number generator seed")

	flag.StringVar(&dconfig_from_flags.distribution_name, "distribution", "zipf", "random location generation distribution (uniform, or zipf)")
	flag.StringVar(&dconfig_from_flags.input_file, "input", nil, "read transactions from file instead of generating")
	flag.StringVar(&dconfig_from_flags.output_file, "output", nil, "write transactions to file in addition to scheduling")
	flag.Float64Var(&dconfig_from_flags.alpha, "alpha", 1.0, "zipf distribution alpha parameter")
	// For the Ethereum world, the number of possible locations is
	// 2^{160+256}, but it is extremely sparse.  Furthermore, many
	// locations are in (pseudo) equivalence classes, i.e., if a
	// contract reads one of the locations, then it is almost
	// certainly going to read the rest, and similarly for writes.
	flag.UintVar(&dconfig_from_flags.num_locations, "num_locations", 1<<20, "number of possible locations")
	flag.UintVar(&dconfig_from_flags.num_read_locs, "num_reads", 0, "number of read locations")
	flag.UintVar(&dconfig_from_flags.num_write_locs, "num_writes", 2, "number of write locations")
	flag.UintVar(&dconfig_from_flags.num_transactions, "num_transactions", 1<<20, "number of transactions to generate")
}

type TransactionSource interface {
	Get() (*Transaction, error)
	Close()  // Logging "source" needs to flush its buffers; and file readers should close.
}

type RDTransactionSource struct {
	num_trans, num_reads, num_writes uint
	rg random_distribution.DiscreteGenerator
}

func NewRDTransactionSource(nt, nr, nw uint, rg random_distribution.DiscreteGenerator) *RDTransactionSource {
	return &RDTransactionSource{num_trans: nt, num_reads: nr, num_writes: nw, rg: rg}
}

func (rdt *RDTransactionSource) Get(seqno uint) (*Transaction, error) {
	if rdt.num_trans == 0 {
		return nil, errors.New("All requested transactions generated")
	}
	rdt.num_trans--
	t := alg.NewTransaction();
	var n uint
	for n = 0; n < rdt.num_reads; n++ {
		t.ReadSet.Add(alg.TestLocation(rdt.rg.Generate()))
	}
	for n = 0; n < rdt.num_writes; n++ {
		t.WriteSet.Add(alg.TestLocation(rdt.rg.Generate()))
	}
	t.TimeCost = 1
	t.CreationSeqno = seqno
	return t, nil
}

func (rdt *RDTransactionSource) Close() {}

type FileTransactionSource struct {
	iof *os.File
	in *bufio.Reader
}

func NewFileTransactionSource(fn string) *FileTransactionSource {
	// "-" case
	if f, err := os.Open(fn); err != nil {
		panic("Could not open %s", fn);
	}
	return &FileTransactionSource{ iof: f, in: bufio.NewReader(f) }
}

// This will stop at *any* errors, e.g., badly formatted transactions, and not just EOF.
func (ft *FileTransactionSource) Get(_ uint) (*Transaction, error) {
	return alg.ReadNewTransaction(TestLocation(0), ft.in)
}

func (ft *FileTransactionSource) Close() {
	ft.iof.Close()
	ft.in = nil  // No Close() because no "ownership" transfer(?) of *io.File
}

func TransactionSourceFactory(cnf DistributionConfig) *TransactionSource {
	if cnf.seed == 0 {
		cnf.seed = int64(time.Now().Nanosecond())
	}
	if cnf.in_file != nil {
		cnf.distribution_name = "input"
	}
	if cnf.distribution_name == "input" && cnf.input_file == nil {
		panic("input distribution but no input_file specified")
	}
	num_locations := int(cnf.num_locations)
	if num_locations <= 0 {
		panic("Number of memory locations overflowed")
	}

	var rg random_distribution.DiscreteGenerator

	if cnf.distribution_name == "input" {
		return NewFileTransactionSource(input_file)
	} else if cnf.distribution_name == "uniform" {
		rg = random_distribution.NewUniform(num_locations, rand.New(rand.NewSource(cnf.seed)))
	} else if cnf.distribution_name == "zipf" {
		rg = random_distribution.NewZipf(1.0, num_locations, rand.New(rand.NewSource(cnf.seed)))
	} else {
		panic("Random distribution name not recognized: ", cnf.distribution_name)
	}
	return NewRDTransactionSource(cnf.num_trans, cnf.num_reads, cnf.num_writes, rg)
}

func generate_transactions(dcnf DistributionConfig) {
	ts := TransactionSourceFactory(dcnf)

	if dcnf.out_file != nil {
		ts = LoggingTransactionSource(dcnf.out_file, ts)
	}

	var tid uint
	for tid = 0; tid < num_trans; tid++ {
		t := ts.Get(tid)
		t.Write(out)
		out.WriteRune('\n')
	}
}

func main() {
	flag.Parse()
	if verbosity > 0 {
		fmt.Println("verbosity has value ", verbosity)
	}

	bw := bufio.NewWriter(os.Stdout)
	defer bw.Flush()

	generate_transactions(dconfig_from_flags)
}
