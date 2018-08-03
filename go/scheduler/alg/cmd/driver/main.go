package main

/*

Scheduling algorithm driver.

Generate / read randomly generated sythetic transaction descriptions (or actual data extracted
from Parity) and feed into selected scheduling algorithm.

*/

import (
	"bufio"
	"container/heap"
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

// For verbosity level where execution parameters ought to be shown.  Use flag names instead
// of variable names.  Instead of flag.PrintDefaults(), what we want is a flag.PrintActual()
// for showing simulator initial state, after flag.Parse() is done, and any special case
// handling (e.g. seed, or sconfig_from_flags.max_pending below).
func (dcnf *DistributionConfig) Show(bw *bufio.Writer) {
	fmt.Fprintf(bw, "\nSynthetic Load Generator Parameters\n") 
	fmt.Fprintf(bw, "  seed = %d\n", dcnf.seed)
	fmt.Fprintf(bw, "  distribution = \"%s\"\n", dcnf.distribution_name)
	fmt.Fprintf(bw, "  input = \"%s\"\n", dcnf.input_file)
	fmt.Fprintf(bw, "  output = \"%s\"\n", dcnf.output_file)
	fmt.Fprintf(bw, "  alpha = %f\n", dcnf.alpha)
	fmt.Fprintf(bw, "  num-locations = %d\n", dcnf.num_locations)
	fmt.Fprintf(bw, "  num-reads = %d\n", dcnf.num_read_locs)
	fmt.Fprintf(bw, "  num-writes = %d\n", dcnf.num_write_locs)
	fmt.Fprintf(bw, "  num-transactions = %d\n", dcnf.num_transactions)
}

func (dcnf *DistributionConfig) UpdateAndCheckDefaults() {
	if dcnf.seed == 0 {
		dcnf.seed = int64(time.Now().UTC().UnixNano())
	}
	if dcnf.input_file != "" {
		dcnf.distribution_name = "input"
	}
	if dcnf.distribution_name == "input" && dcnf.input_file == "" {
		panic("input distribution but no input_file specified")
	}
	if int(dcnf.num_locations) < 0 {
		panic("Number of memory/conflict locations overflowed")
	}
}

var dconfig_from_flags DistributionConfig

type LogicalShardingConfig struct {
	seed         int64
	shard_top_n  int
	shard_factor int
}

func (lcnf *LogicalShardingConfig) Show(bw *bufio.Writer) {
	fmt.Fprintf(bw, "\nLogical Sharding Parameters\n")
	fmt.Fprintf(bw, "  shard-seed = %d\n", lcnf.seed)
	fmt.Fprintf(bw, "  shard-top = %d\n", lcnf.shard_top_n)
	fmt.Fprintf(bw, "  shard-factor = %d\n", lcnf.shard_factor)
}

func (lcnf *LogicalShardingConfig) UpdateAndCheckDefaults() {
	if lcnf.seed == 0 {
		lcnf.seed = int64(time.Now().UTC().UnixNano())
	}
}

var lsconfig_from_flags LogicalShardingConfig

type SchedulerConfig struct {
	name string

	// Buffer at most this many transactions before generating a schedule.
	max_pending int

	// max_time is per subgraph execution time, but post-schedule generation subgraph merging
	// will result in higher total execution times per compute committee.
	max_time uint
}

func (scnf *SchedulerConfig) Show(bw *bufio.Writer) {
	fmt.Fprintf(bw, "\nScheduler Configuration Parameters\n")
	fmt.Fprintf(bw, "  scheduler = \"%s\"\n", scnf.name)
	fmt.Fprintf(bw, "  max-pending = %d\n", scnf.max_pending)
	fmt.Fprintf(bw, "  max-subgraph-time = %d\n", scnf.max_time)
}

func (scnf *SchedulerConfig) UpdateAndCheckDefaults(xcnf ExecutionConfig) {
	if scnf.max_pending < 0 {
		scnf.max_pending = 2 * int(scnf.max_time) * xcnf.num_committees
	}
}

var sconfig_from_flags SchedulerConfig

type ExecutionConfig struct {
	num_committees int
}

func (xcnf *ExecutionConfig) Show(bw *bufio.Writer) {
	fmt.Fprintf(bw, "\nExecution Simulator Parameters\n")
	fmt.Fprintf(bw, "  num-committees = %d\n", xcnf.num_committees)
}

func (xcnf *ExecutionConfig) UpdateAndCheckDefaults() {
	if xcnf.num_committees < 1 {
		panic(fmt.Sprintf("Number of execution committees must be at least 1, not %d",
			xcnf.num_committees))
	}
}

var xconfig_from_flags ExecutionConfig

func init() {
	dconfig_from_flags = DistributionConfig{}
	sconfig_from_flags = SchedulerConfig{}
	lsconfig_from_flags = LogicalShardingConfig{}
	xconfig_from_flags = ExecutionConfig{}

	flag.IntVar(&verbosity, "verbosity", 0, "verbosity level for debug output")

	// Distribution generator parameters

	// seed is only important for reproducible RNG; input_file/output_file is another
	// mechanism for reproducibility
	flag.Int64Var(&dconfig_from_flags.seed, "seed", 0,
		"pseudorandom number generator seed for synthetic load generator (default: UnixNano)")

	flag.StringVar(&dconfig_from_flags.distribution_name, "distribution", "zipf",
		"random location generation distribution (uniform, or zipf)")
	flag.StringVar(&dconfig_from_flags.input_file, "input",	"",
		"read transactions from file instead of generating")
	flag.StringVar(&dconfig_from_flags.output_file, "output", "",
		"write transactions to file in addition to scheduling")
	flag.Float64Var(&dconfig_from_flags.alpha, "alpha", 1.0,
		"zipf distribution alpha parameter")
	// For the Ethereum world, the number of possible locations is 2^{160+256}, but it is
	// extremely sparse.  Furthermore, many locations are in (pseudo) equivalence classes,
	// i.e., if a contract reads one of the locations, then it is almost certainly going to
	// read the rest, and similarly for writes.
	flag.UintVar(&dconfig_from_flags.num_locations, "num-locations", 100000,
		"number of possible memory locations")
	flag.UintVar(&dconfig_from_flags.num_read_locs, "num-reads", 0,
		"number of read locations in a transaction")
	flag.UintVar(&dconfig_from_flags.num_write_locs, "num-writes", 2,
		"number of write locations in a transaction")
	flag.UintVar(&dconfig_from_flags.num_transactions, "num-transactions", 1000000,
		"number of transactions to generate")

	// Logical sharding filter configuration parameters
	flag.Int64Var(&lsconfig_from_flags.seed, "shard-seed", 0,
		"pseudorandom number generator seed for logical sharding filter (default: UnixNano)")
	flag.IntVar(&lsconfig_from_flags.shard_top_n, "shard-top", 0,
		"shard the highest <shard-top> probable locations")
	flag.IntVar(&lsconfig_from_flags.shard_factor, "shard-factor", 16,
		"number of new (negative) shards per original location")

	// Scheduler configuration parameters

	flag.StringVar(&sconfig_from_flags.name, "scheduler", "greedy-subgraph",
		"scheduling algorithm (greedy-subgraph)")
	flag.IntVar(&sconfig_from_flags.max_pending, "max-pending", -1,
		"scheduling when there are this many transactions (default 2 * max-subgraph-time * num-committees")
	// In the python simulator, this was 'block_size', and we may still want to have a
	// maximum transactions as well as maximum execution time.
	flag.UintVar(&sconfig_from_flags.max_time, "max-subgraph-time", 20,
		"disallow adding to a subgraph if the total estimated execution time would exceed this")

	// Execution Committees configuration parameters
	flag.IntVar(&xconfig_from_flags.num_committees, "num-committees", 40,
		"number of execution committees")
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
	if e == nil {
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

type LogicalShardingFilter struct {
	cnf     LogicalShardingConfig
	ts      TransactionSource
	r       *rand.Rand
	top_map []int64
}

func (lsf *LogicalShardingFilter) Get(seqno uint) (*alg.Transaction, error) {
	lsf.top_map = make([]int64, lsf.cnf.shard_top_n) // zeros means no value
	t, e := lsf.ts.Get(seqno)
	if e == nil {
		// iterate over t's read-set and write-set, replace all elements 0 <= e <
		// cnf.shard_top_n with a random negative value (memoized)
		lsf.UpdateSet(t.ReadSet)
		lsf.UpdateSet(t.WriteSet)
	}
	return t, e
}

func (lsf *LogicalShardingFilter) UpdateSet(ls *alg.LocationSet) {
	repl := alg.NewLocationSet()
	for loc := range ls.Locations {
		tloc := loc.(alg.TestLocation)
		iloc := int64(tloc)
		if 0 <= iloc && iloc < int64(lsf.cnf.shard_top_n) {
			loc := int(iloc)
			if lsf.top_map[loc] == 0 {
				shard := int64(lsf.r.Intn(lsf.cnf.shard_factor))
				shard_base := int64(loc * lsf.cnf.shard_factor)
				lsf.top_map[loc] = -(1 + shard_base + shard)
			}
			repl.Add(alg.TestLocation(lsf.top_map[loc]))
		}
	}
	*ls = *repl
}

func (lsf *LogicalShardingFilter) Close() {
	lsf.ts.Close()
}

func NewLogicalShardingFilter(cnf LogicalShardingConfig, ts TransactionSource) *LogicalShardingFilter {
	return &LogicalShardingFilter{cnf: cnf, ts: ts, r: rand.New(rand.NewSource(cnf.seed))}
}

func TransactionSourceFactory(cnf DistributionConfig) TransactionSource {
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
		rg = random_distribution.NewZipf(cnf.alpha, num_locations, rand.New(rand.NewSource(cnf.seed)))
	} else {
		panic(fmt.Sprintf("Random distribution name not recognized: %s", cnf.distribution_name))
	}
	return NewRDTransactionSource(cnf.num_transactions, cnf.num_read_locs, cnf.num_write_locs, rg)
}

func scheduler_factory(scnf SchedulerConfig, xcnf ExecutionConfig) alg.Scheduler {
	if scnf.name == "greedy-subgraph" {
		return alg.NewGreedySubgraphs(scnf.max_pending, alg.ExecutionTime(scnf.max_time))
	}
	panic(fmt.Sprintf("Scheduler %s not recognized", scnf.name))
}

type CommitteeMember struct {
	batches        []*alg.Subgraph
	execution_time alg.ExecutionTime
}

type CommitteeMemberHeap []*CommitteeMember

func (h CommitteeMemberHeap) Len() int           { return len(h) }
func (h CommitteeMemberHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h CommitteeMemberHeap) Less(i, j int) bool { return h[i].execution_time < h[j].execution_time }
func (h *CommitteeMemberHeap) Push(x interface{}) {
	*h = append(*h, x.(*CommitteeMember))
}
func (h *CommitteeMemberHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func generate_transactions(dcnf DistributionConfig, scnf SchedulerConfig,
	lscnf LogicalShardingConfig, xcnf ExecutionConfig, bw *bufio.Writer) {

	total_execution_time := alg.ExecutionTime(0)
	linear_execution_time := alg.ExecutionTime(0)

	ts := TransactionSourceFactory(dcnf)
	sched := scheduler_factory(scnf, xcnf)

	if dcnf.output_file != "" {
		ts = NewLoggingTransactionSource(dcnf.output_file, ts)
	}

	if lscnf.shard_top_n > 0 {
		ts = NewLogicalShardingFilter(lscnf, ts)
	}

	sched_num := 0
	tid := uint(0)
	trans := make([]*alg.Transaction, 1)
	var err error
	flush := false
	for {
		var sgl []*alg.Subgraph
		if !flush {
			trans[0], err = ts.Get(tid)
			if err == nil {
				tid++
				if verbosity > 4 {
					trans[0].Write(bw)
					bw.WriteRune('\n')
				}

				linear_execution_time += trans[0].TimeCost

				sgl = sched.AddTransactions(trans)
			} else {
				flush = true
			}
		}
		if flush {
			sgl = sched.FlushSchedule()
		}
		if len(sgl) > 0 {
			sched_num++
			if verbosity > 3 {
				fmt.Fprintf(bw, "\n\n")
				fmt.Fprintf(bw, "Schedule %3d\n", sched_num)
				fmt.Fprintf(bw, "------------\n")
				fmt.Fprintf(bw, " deferred: %d\n", sched.NumDeferred())
				for _, sg := range sgl {
					sg.Write(bw)
					bw.WriteRune('\n')
				}
			}
			// assign subgraphs to execution committees using first-free heuristic
			committee := make([]CommitteeMember, xcnf.num_committees)
			h := &CommitteeMemberHeap{}
			heap.Init(h)
			for ix := 0; ix < xcnf.num_committees; ix++ {
				heap.Push(h, &committee[ix])
			}
			for _, sg := range sgl {
				cmt := heap.Pop(h).(*CommitteeMember)
				cmt.execution_time += sg.EstExecutionTime()
				cmt.batches = append(cmt.batches, sg)
				heap.Push(h, cmt)
			}
			// Calculate execution time for this schedule (max over all members)
			sched_execution_time := alg.ExecutionTime(0)
			for ix, cmt := range committee {
				if cmt.execution_time > sched_execution_time {
					sched_execution_time = cmt.execution_time
				}
				// Now show committee statistics
				if verbosity > 1 {
					fmt.Fprintf(bw, "\n")
					fmt.Fprintf(bw, "Committee member %d\n", ix)
					fmt.Fprintf(bw, " est execution time = %d\n", uint64(cmt.execution_time))
					fmt.Fprintf(bw, " number of batches = %d\n", len(cmt.batches))
					if verbosity > 2 {
						// show the subgraphs
						for _, sg := range cmt.batches {
							sg.Write(bw)
							bw.WriteRune('\n')
						}
					}
				}
			}
			total_execution_time += sched_execution_time
		}
		if flush && len(sgl) == 0 {
			break
		}
	}
	ts.Close()

	fmt.Fprintf(bw, "\n********\n")
	fmt.Fprintf(bw, "Linear execution time: %8d\n", uint64(linear_execution_time))
	fmt.Fprintf(bw, "Total execution time:  %8d\n", uint64(total_execution_time))
	fmt.Fprintf(bw, "Speedup:               %22.13f\n", float64(linear_execution_time)/float64(total_execution_time))
}

func main() {
	flag.Parse()
	if verbosity > 0 {
		fmt.Println("verbosity has value ", verbosity)
	}

	bw := bufio.NewWriter(os.Stdout)
	defer bw.Flush()

	dconfig_from_flags.UpdateAndCheckDefaults()
	lsconfig_from_flags.UpdateAndCheckDefaults()
	sconfig_from_flags.UpdateAndCheckDefaults(xconfig_from_flags)
	xconfig_from_flags.UpdateAndCheckDefaults()
	if (verbosity > 0) {
		dconfig_from_flags.Show(bw)
		lsconfig_from_flags.Show(bw)
		sconfig_from_flags.Show(bw)
		xconfig_from_flags.Show(bw)
		bw.Flush()
	}

	generate_transactions(dconfig_from_flags, sconfig_from_flags, lsconfig_from_flags, xconfig_from_flags, bw)
}
