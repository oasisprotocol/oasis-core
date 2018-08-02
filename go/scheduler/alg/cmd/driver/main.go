package main

/*

Scheduling algorithm driver.

Generate / read randomly generated sythetic transaction descriptions (or actual data extracted
from Parity) and feed into selected scheduling algorithm.

*/

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/random_distribution"
)

// Flag variables

var verbosity int
var scheduler_name string

// Distribution parameters, gathered into one struct.  When we add new distributions we should
// just add new fields.  The factory function for sources will only use the config value(s)
// appropriate for the selected TransactionSource.
type DistributionConfig struct {
	seed              int64
	distribution_name string
	input_file        string // "-" means standard input
	output_file       string
	alpha             float64
	num_locations     uint
	num_read_locs     uint
	num_write_locs    uint
	num_transactions  uint
}

var dconfig_from_flags DistributionConfig

func init() {
	dconfig_from_flags = DistributionConfig{}

	flag.IntVar(&verbosity, "verbosity", 0, "verbosity level for debug output")

	flag.StringVar(&scheduler_name, "scheduler", "greedy_subgraph", "scheduling algorithm")

	// Distribution generator parameters

	// seed is only important for reproducible RNG; input_file/output_file is another
	// mechanism for reproducibility
	flag.Int64Var(&dconfig_from_flags.seed, "seed", 0, "pseudorandom number generator seed")

	flag.StringVar(&dconfig_from_flags.distribution_name, "distribution",
		"zipf", "random location generation distribution (uniform, or zipf)")
	flag.StringVar(&dconfig_from_flags.input_file, "input",
		"", "read transactions from file instead of generating")
	flag.StringVar(&dconfig_from_flags.output_file, "output",
		"", "write transactions to file in addition to scheduling")
	flag.Float64Var(&dconfig_from_flags.alpha, "alpha",
		1.0, "zipf distribution alpha parameter")
	// For the Ethereum world, the number of possible locations is 2^{160+256}, but it is
	// extremely sparse.  Furthermore, many locations are in (pseudo) equivalence classes,
	// i.e., if a contract reads one of the locations, then it is almost certainly going to
	// read the rest, and similarly for writes.
	flag.UintVar(&dconfig_from_flags.num_locations, "num_locations",
		1<<20, "number of possible locations")
	flag.UintVar(&dconfig_from_flags.num_read_locs, "num_reads",
		0, "number of read locations")
	flag.UintVar(&dconfig_from_flags.num_write_locs, "num_writes",
		2, "number of write locations")
	flag.UintVar(&dconfig_from_flags.num_transactions, "num_transactions",
		1<<20, "number of transactions to generate")
}

type TransactionSource interface {
	Get(seqno uint) (*alg.Transaction, error)
	Close() // Logging "source" needs to flush its buffers; and file readers should close.
}

type RDTransactionSource struct {
	num_trans, num_reads, num_writes uint
	rg                               random_distribution.DiscreteGenerator
}

func NewRDTransactionSource(nt, nr, nw uint, rg random_distribution.DiscreteGenerator) *RDTransactionSource {
	return &RDTransactionSource{num_trans: nt, num_reads: nr, num_writes: nw, rg: rg}
}

func (rdt *RDTransactionSource) Get(seqno uint) (*alg.Transaction, error) {
	if rdt.num_trans == 0 {
		return nil, errors.New("All requested transactions generated")
	}
	rdt.num_trans--
	t := alg.NewTransaction()
	var n uint
	var loc alg.TestLocation
	for n = 0; n < rdt.num_reads; n++ {
		for {
			loc = alg.TestLocation(rdt.rg.Generate())
			if !t.ReadSet.Contains(loc) {
				break
			}
		}
		t.ReadSet.Add(loc)
	}
	for n = 0; n < rdt.num_writes; n++ {
		for {
			loc = alg.TestLocation(rdt.rg.Generate())
			if !t.WriteSet.Contains(loc) {
				break
			}
		}
		t.WriteSet.Add(loc)
	}
	t.TimeCost = 1
	t.CreationSeqno = seqno
	return t, nil
}

func (rdt *RDTransactionSource) Close() {}

type FileTransactionSource struct {
	iof *os.File
	in  *bufio.Reader
}

func NewFileTransactionSource(fn string) *FileTransactionSource {
	// Handle "-" case to mean stdin.  This means files named "-" would have to be referred
	// to via "./-" which is awkward.  We could instead have the empty string "" mean
	// standard input, but that is different from the usual Unix convention.
	if fn == "-" {
		return &FileTransactionSource{iof: nil, in: bufio.NewReader(os.Stdin)}
	}
	f, err := os.Open(fn)
	if err != nil {
		panic(fmt.Sprintf("Could not open %s", fn))
	}
	return &FileTransactionSource{iof: f, in: bufio.NewReader(f)}
}

// This will stop at *any* errors, e.g., badly formatted transactions, and not just EOF.
func (ft *FileTransactionSource) Get(_ uint) (*alg.Transaction, error) {
	return alg.ReadNewTransaction(alg.TestLocation(0), ft.in)
}

func (ft *FileTransactionSource) Close() {
	if ft.iof != nil {
		ft.iof.Close()
	}
	ft.in = nil // No Close() because no "ownership" transfer(?) of *io.File
}

type LoggingTransactionSource struct {
	os *os.File
	bw *bufio.Writer
	ts TransactionSource
}

func NewLoggingTransactionSource(fn string, ts TransactionSource) *LoggingTransactionSource {
	os, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		panic(fmt.Sprintf("Could not open file %s for logging transactions", fn))
	}
	return &LoggingTransactionSource{os: os, bw: bufio.NewWriter(os), ts: ts}
}

func (lts *LoggingTransactionSource) Get(seqno uint) (*alg.Transaction, error) {
	t, e := lts.ts.Get(seqno)
	if e != nil {
		t.Write(lts.bw)
		lts.bw.WriteRune('\n')
	}
	return t, e
}

func (lts *LoggingTransactionSource) Close() {
	lts.ts.Close()
	if lts.bw.Flush() != nil {
		panic(fmt.Sprintf("Write to transaction output log %s failed", lts.os.Name()))
	}
	lts.os.Close()
}

func TransactionSourceFactory(cnf DistributionConfig) TransactionSource {
	if cnf.seed == 0 {
		cnf.seed = int64(time.Now().Nanosecond())
	}
	if cnf.input_file != "" {
		cnf.distribution_name = "input"
	}
	if cnf.distribution_name == "input" && cnf.input_file == "" {
		panic("input distribution but no input_file specified")
	}
	num_locations := int(cnf.num_locations)
	if num_locations <= 0 {
		panic("Number of memory locations overflowed")
	}

	var rg random_distribution.DiscreteGenerator

	if cnf.distribution_name == "input" {
		return NewFileTransactionSource(cnf.input_file)
	} else if cnf.distribution_name == "uniform" {
		rg = random_distribution.NewUniform(num_locations, rand.New(rand.NewSource(cnf.seed)))
	} else if cnf.distribution_name == "zipf" {
		rg = random_distribution.NewZipf(1.0, num_locations, rand.New(rand.NewSource(cnf.seed)))
	} else {
		panic(fmt.Sprintf("Random distribution name not recognized: %s", cnf.distribution_name))
	}
	return NewRDTransactionSource(cnf.num_transactions, cnf.num_read_locs, cnf.num_write_locs, rg)
}

func generate_transactions(dcnf DistributionConfig, bw *bufio.Writer) {
	ts := TransactionSourceFactory(dcnf)

	if dcnf.output_file != "" {
		ts = NewLoggingTransactionSource(dcnf.output_file, ts)
	}

	var tid uint
	for {
		t, err := ts.Get(tid)
		if err != nil {
			break
		}
		// TODO send to scheduler here and process execution schedules, if any
		t.Write(bw)
		bw.WriteRune('\n')
	}
	ts.Close()
}

func main() {
	flag.Parse()
	if verbosity > 0 {
		fmt.Println("verbosity has value ", verbosity)
	}

	bw := bufio.NewWriter(os.Stdout)
	defer bw.Flush()

	// TODO pick scheduler based on scheduler_name and use instead of bw
	generate_transactions(dconfig_from_flags, bw)
}
