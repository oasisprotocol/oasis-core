package main

/*

Scheduling algorithm driver.

Generate / read randomly generated sythetic transaction descriptions (or actual data extracted
from Parity) and feed into selected scheduling algorithm.

*/

import (
	"bufio"
	"container/heap"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/randgen"
	"github.com/oasislabs/ekiden/go/scheduler/alg/simulator"
)

// Flag variables: verbosity is a single, global flag, and per-module flags are grouped
// together in *Config structs, with a *FromFlags global instance/singleton, just like
// verbosity.  The convention is that we use an init() function to provide initial values, help
// strings, etc, then in main() we invoke flag.Parse(), after which we run the
// UpdateAndCheckDefaults() method to check for contradictory flags, update defaults (e.g., if
// an input file is specified as the source of synthetic load data, then the distribution
// parameter that controls the pseudorandom synthetic load generation has to be unset or set to
// "input")

var verbosity int

// DistributionConfig are distribution parameters, gathered into one struct.  When we add new
// distributions we should just add new fields.  The factory function for sources will only use
// the config value(s) appropriate for the selected TransactionSource.
type distributionConfig struct {
	seed             int64
	distributionName string
	inputFile        string // "-" means standard input
	outputFile       string
	alpha            float64
	numLocations     uint
	numReadLocs      uint
	numWriteLocs     uint
	numTransactions  uint
}

const useInput = "input"

// Show prints the config parameters.  For verbosity level where execution parameters ought to
// be shown.  Use flag names instead of variable names.  Instead of flag.PrintDefaults(), what
// we want is a flag.PrintActual() for showing simulator initial state, after flag.Parse() is
// done, and any special case handling (e.g. seed, or sconfigFromFlags.maxPending below).
func (dcnf *distributionConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nSynthetic Load Generator Parameters\n")
	_, _ = fmt.Fprintf(bw, "  seed = %d\n", dcnf.seed)
	_, _ = fmt.Fprintf(bw, "  distribution = \"%s\"\n", dcnf.distributionName)
	_, _ = fmt.Fprintf(bw, "  input = \"%s\"\n", dcnf.inputFile)
	_, _ = fmt.Fprintf(bw, "  output = \"%s\"\n", dcnf.outputFile)
	_, _ = fmt.Fprintf(bw, "  alpha = %f\n", dcnf.alpha)
	_, _ = fmt.Fprintf(bw, "  num-locations = %d\n", dcnf.numLocations)
	_, _ = fmt.Fprintf(bw, "  num-reads = %d\n", dcnf.numReadLocs)
	_, _ = fmt.Fprintf(bw, "  num-writes = %d\n", dcnf.numWriteLocs)
	_, _ = fmt.Fprintf(bw, "  num-transactions = %d\n", dcnf.numTransactions)
}

// UpdateAndCheckDefaults sets the RNG seed if unspecified by a command-line flag and ensures
// that the "input" distribution name is used when there is a file named via the -input-file
// flag.
func (dcnf *distributionConfig) UpdateAndCheckDefaults() {
	if dcnf.seed == 0 {
		dcnf.seed = time.Now().UTC().UnixNano()
	}
	if dcnf.inputFile != "" {
		if dcnf.distributionName == "" || dcnf.distributionName == useInput {
			dcnf.distributionName = useInput
		} else {
			panic(fmt.Sprintf("input distribution \"%s\" specified, but also input file \"%s\" specified\n", dcnf.distributionName, dcnf.inputFile))
		}
	}
	if dcnf.distributionName == useInput && dcnf.inputFile == "" {
		panic("input distribution but no input-file specified")
	}
	if int(dcnf.numLocations) < 0 {
		panic("Number of memory/conflict locations overflowed")
	}
}

var dconfigFromFlags distributionConfig

// logicalShardingConfig holds configuration variables that control how LogicalShardingFilter
// performs sharding.
type logicalShardingConfig struct {
	seed        int64
	shardTopN   int
	shardFactor int
}

// Show prints the logicalShardingConfig configuration parameters.
func (lcnf *logicalShardingConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nLogical Sharding Parameters\n")
	_, _ = fmt.Fprintf(bw, "  shard-seed = %d\n", lcnf.seed)
	_, _ = fmt.Fprintf(bw, "  shard-top = %d\n", lcnf.shardTopN)
	_, _ = fmt.Fprintf(bw, "  shard-factor = %d\n", lcnf.shardFactor)
}

// UpdateAndCheckDefaults sets the RNG seed for the sharding RNG, if unspecified by a
// command-line flag.
func (lcnf *logicalShardingConfig) UpdateAndCheckDefaults() {
	if lcnf.seed == 0 {
		lcnf.seed = time.Now().UTC().UnixNano()
	}
}

var lsconfigFromFlags logicalShardingConfig

type adversaryConfig struct {
	seed            int64
	injectionProb   float64
	targetFrac      float64
	readFrac        float64
	dosBatchSize    int
	targetAddresses string
	seqno           uint

	// not set via config, but during param validation to avoid dup work
	targets *alg.LocationRangeSet
}

func (acnf *adversaryConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nAdversary (DOS) Transaction Generator Parameters\n")
	_, _ = fmt.Fprintf(bw, "  dos-seed = %d\n", acnf.seed)
	_, _ = fmt.Fprintf(bw, "  dos-injection-prob = %g\n", acnf.injectionProb)
	_, _ = fmt.Fprintf(bw, "  dos-target-fraction = %g\n", acnf.targetFrac)
	_, _ = fmt.Fprintf(bw, "  dos-read-fraction = %g\n", acnf.readFrac)
	_, _ = fmt.Fprintf(bw, "  dos-batch-size = %d\n", acnf.dosBatchSize)
	_, _ = fmt.Fprintf(bw, "  dos-target-addresses = %s\n", acnf.targetAddresses)
	_, _ = fmt.Fprintf(bw, "  dos-seqno = %d\n", acnf.seqno)
}

func (acnf *adversaryConfig) UpdateAndCheckDefaults() {
	if acnf.seed == 0 {
		acnf.seed = time.Now().UTC().UnixNano()
	}
	if acnf.injectionProb < 0 || 1.0 <= acnf.injectionProb {
		panic(fmt.Sprintf("dos-injection-prob has to be in [0,1)."))
	}
	if acnf.readFrac < 0 || acnf.readFrac > 1.0 {
		panic(fmt.Sprintf("dos-read-fraction has to be in [0,1]."))
	}
	if acnf.dosBatchSize <= 0 {
		panic(fmt.Sprintf("dos-batch-size should be greater than 0 (is %d)",
			acnf.dosBatchSize))
	}
	targets, err := alg.LocationRangeSetFromString(alg.TestLocation(0), acnf.targetAddresses)
	if err != nil {
		panic(fmt.Sprintf("Target list misparse: '%s'.", acnf.targetAddresses))
	}
	acnf.targets = targets
}

var adversaryConfigFromFlags adversaryConfig

type schedulerConfig struct {
	name string

	// Buffer at most this many transactions before generating a schedule.
	maxPending int

	// Divisor used to compute new maxPending (1 + excessFraction) * previousBatchSize
	excessFraction float64

	// maxTime is per subgraph execution time, but post-schedule generation subgraph merging
	// will result in higher total execution times per compute committee.
	maxTime uint
}

// Show prints the schedulerConfig fields.  NB: not all schedulers will use all fields.
func (scnf *schedulerConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nScheduler Configuration Parameters\n")
	_, _ = fmt.Fprintf(bw, "  scheduler = \"%s\"\n", scnf.name)
	_, _ = fmt.Fprintf(bw, "  max-pending = %d\n", scnf.maxPending)
	_, _ = fmt.Fprintf(bw, "  excess-fraction = %g\n", scnf.excessFraction)
	_, _ = fmt.Fprintf(bw, "  max-subgraph-time = %d\n", scnf.maxTime)
}

// UpdateAndCheckDefaults sets the maxPending configuration based on other configuration
// values if it had not been set by a command-line flag.
func (scnf *schedulerConfig) UpdateAndCheckDefaults(xcnf executionConfig) {
	if scnf.maxPending < 0 {
		scnf.maxPending = 2 * int(scnf.maxTime) * xcnf.numCommittees
	}
	if scnf.excessFraction < 0 {
		panic(fmt.Sprintf("excess-fraction cannot be less than 0 (got %g)", scnf.excessFraction))
	}
}

var sconfigFromFlags schedulerConfig

// executionConfig contains configuration parameters for the execution environment.  For now,
// it only contains the number of execution committees.
type executionConfig struct {
	numCommittees int
}

// Show prints the executionConfig.
func (xcnf *executionConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nExecution Simulator Parameters\n")
	_, _ = fmt.Fprintf(bw, "  num-committees = %d\n", xcnf.numCommittees)
}

// UpdateAndCheckDefaults verifies that the executionConfig makes sense (positive numCommittee).
func (xcnf *executionConfig) UpdateAndCheckDefaults() {
	if xcnf.numCommittees < 1 {
		panic(fmt.Sprintf("Number of execution committees must be at least 1, not %d",
			xcnf.numCommittees))
	}
}

var xconfigFromFlags executionConfig

// Set up flag variables before main runs.
func init() {
	dconfigFromFlags = distributionConfig{}
	sconfigFromFlags = schedulerConfig{}
	lsconfigFromFlags = logicalShardingConfig{}
	adversaryConfigFromFlags = adversaryConfig{}
	xconfigFromFlags = executionConfig{}

	flag.IntVar(&verbosity, "verbosity", 0, "verbosity level for debug output")

	// Distribution generator parameters

	// seed is only important for reproducible RNG; inputFile/outputFile is another
	// mechanism for reproducibility
	flag.Int64Var(&dconfigFromFlags.seed, "seed", 0,
		"pseudorandom number generator seed for synthetic load generator (default: UnixNano)")

	flag.StringVar(&dconfigFromFlags.distributionName, "distribution", "zipf",
		"random location generation distribution (uniform, or zipf)")
	flag.StringVar(&dconfigFromFlags.inputFile, "input", "",
		"read transactions from file instead of generating")
	flag.StringVar(&dconfigFromFlags.outputFile, "output", "",
		"write transactions to file in addition to scheduling")
	flag.Float64Var(&dconfigFromFlags.alpha, "alpha", 1.0,
		"zipf distribution alpha parameter")
	// For the Ethereum world, the number of possible locations is 2^{160+256}, but it is
	// extremely sparse.  Furthermore, many locations are in (pseudo) equivalence classes,
	// i.e., if a contract reads one of the locations, then it is almost certainly going to
	// read the rest, and similarly for writes.
	flag.UintVar(&dconfigFromFlags.numLocations, "num-locations", 100000,
		"number of possible memory locations")
	flag.UintVar(&dconfigFromFlags.numReadLocs, "num-reads", 0,
		"number of read locations in a transaction")
	flag.UintVar(&dconfigFromFlags.numWriteLocs, "num-writes", 2,
		"number of write locations in a transaction")
	flag.UintVar(&dconfigFromFlags.numTransactions, "num-transactions", 1000000,
		"number of transactions to generate")

	// Logical sharding filter configuration parameters
	flag.Int64Var(&lsconfigFromFlags.seed, "shard-seed", 0,
		"pseudorandom number generator seed for logical sharding filter (default: UnixNano)")
	flag.IntVar(&lsconfigFromFlags.shardTopN, "shard-top", 0,
		"shard the highest <shard-top> probable locations")
	flag.IntVar(&lsconfigFromFlags.shardFactor, "shard-factor", 16,
		"number of new (negative) shards per original location")

	// Adversary configuration parameters

	flag.Int64Var(&adversaryConfigFromFlags.seed, "dos-seed", 0, "seed for rng used to randomize DOS-spam adversary actions")
	flag.Float64Var(&adversaryConfigFromFlags.injectionProb, "dos-injection-prob", 0.0, "probability of deciding to inject (possibly many) DOS transactions (0 disables adversary)")
	flag.Float64Var(&adversaryConfigFromFlags.targetFrac, "dos-target-fraction", 0.9, "fraction of DOS addresses that will be attacked")
	flag.Float64Var(&adversaryConfigFromFlags.readFrac, "dos-read-fraction", 0.0, "fraction of DOS addresses under attack that go to the read set (rest go to the write set)")
	flag.IntVar(&adversaryConfigFromFlags.dosBatchSize, "dos-batch-size", 100, "number of DOS transactions to inject, once decision to DOS spam is made")
	flag.StringVar(&adversaryConfigFromFlags.targetAddresses, "dos-target-addresses", "0:15,128:131", "comma-separated list of integers or start-end integer ranges")
	flag.UintVar(&adversaryConfigFromFlags.seqno, "dos-seqno", 1000000, "starting seqno/id for DOS spam transactions")

	// Scheduler configuration parameters

	flag.StringVar(&sconfigFromFlags.name, "scheduler", "greedy-subgraph",
		"scheduling algorithm (greedy-subgraph)")
	flag.IntVar(&sconfigFromFlags.maxPending, "max-pending", -1,
		"scheduling when there are this many transactions (default 2 * max-subgraph-time * num-committees")
	flag.Float64Var(&sconfigFromFlags.excessFraction, "excess-fraction", 0.75,
		"adaptive max-pending (default 4, updated max-pending = (1 + excessFraction) * previousBatchSize")
	// In the python simulator, this was 'block_size', and we may still want to have a
	// maximum transactions as well as maximum execution time.
	flag.UintVar(&sconfigFromFlags.maxTime, "max-subgraph-time", 20,
		"disallow adding to a subgraph if the total estimated execution time would exceed this")

	// Execution Committees configuration parameters
	flag.IntVar(&xconfigFromFlags.numCommittees, "num-committees", 40,
		"number of execution committees")
}

// transactionSourceFactory consults the distributionConfig arg to build and return a
// TransactionSource, which may be from a canned input data file, from random generator of
// transactions (with various memory access distributions), etc.
func transactionSourceFactory(cnf distributionConfig) simulator.TransactionSource {
	numLocations := int(cnf.numLocations)
	if numLocations <= 0 {
		panic("Number of memory locations overflowed")
	}

	var err error
	if cnf.distributionName == useInput {
		var fts simulator.TransactionSource
		fts, err = simulator.NewFileTransactionSource(cnf.inputFile)
		if err != nil {
			panic(fmt.Sprintf("Error: %s; cannot open \"%s\"", err.Error(), cnf.inputFile))
		}
		return fts
	}

	var rg randgen.Rng

	if cnf.distributionName == "uniform" {
		if rg, err = randgen.NewUniform(numLocations, rand.New(rand.NewSource(cnf.seed))); err != nil {
			panic(err.Error())
		}
	} else if cnf.distributionName == "zipf" {
		if rg, err = randgen.NewZipf(cnf.alpha, numLocations, rand.New(rand.NewSource(cnf.seed))); err != nil {
			panic(err.Error())
		}
	} else {
		panic(fmt.Sprintf("Random distribution name not recognized: %s", cnf.distributionName))
	}
	return simulator.NewRandomDistributionTransactionSource(cnf.numTransactions, cnf.numReadLocs, cnf.numWriteLocs, rg)
}

func adversaryFactory(acnf adversaryConfig, ts simulator.TransactionSource) simulator.TransactionSource {
	if acnf.injectionProb == 0.0 {
		if verbosity > 0 {
			fmt.Printf("No Adversarial transactions will be injected\n")
		}
		return ts
	}
	ats, err := simulator.NewAdversarialTransactionSource(
		acnf.seed,
		acnf.injectionProb,
		acnf.targetFrac,
		acnf.readFrac,
		acnf.targets,
		acnf.dosBatchSize,
		ts,
		acnf.seqno,
	)
	if err != nil {
		panic("adversaryFactory could not construct AdversarialTransactionSource")
	}
	fmt.Printf("Will inject adversarial transactions\n")
	return ats
}

func schedulerFactory(scnf schedulerConfig) alg.Scheduler {
	if scnf.name == "greedy-subgraph-adaptive" {
		return alg.NewGreedySubgraphsAdaptiveQueuing(scnf.maxPending, scnf.excessFraction, alg.ExecutionTime(scnf.maxTime))
	} else if scnf.name == "greedy-subgraph" {
		return alg.NewGreedySubgraphs(scnf.maxPending, alg.ExecutionTime(scnf.maxTime))
	}
	panic(fmt.Sprintf("Scheduler %s not recognized", scnf.name))
}

type committeeMember struct {
	batches       []*alg.Subgraph
	executionTime alg.ExecutionTime
}

type committeeMemberHeap []*committeeMember

func (h committeeMemberHeap) Len() int { return len(h) }

func (h committeeMemberHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h committeeMemberHeap) Less(i, j int) bool { return h[i].executionTime < h[j].executionTime }

func (h *committeeMemberHeap) Push(x interface{}) {
	*h = append(*h, x.(*committeeMember))
}

func (h *committeeMemberHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// nolint: gocyclo
//
// Run simulation: generate transactions and execute them -- and output results to |bw|.
// Caller is responsible for checking I/O errors via bw.Flush.  Other errors result in panic
// here.
func runSimulation(
	dcnf distributionConfig,
	acnf adversaryConfig,
	lscnf logicalShardingConfig,
	scnf schedulerConfig,
	xcnf executionConfig,
	bw *bufio.Writer) {

	totalExecutionTime := alg.ExecutionTime(0)
	linearExecutionTime := alg.ExecutionTime(0)

	ts := transactionSourceFactory(dcnf)
	sched := schedulerFactory(scnf)
	var err error

	// The adversary cannot override logical sharding, under the assumption that the
	// sharding is done by msg.sender address and that misdirected calls will either be
	// forwarded (thereby touching no local-shard state) or reverted.
	ts = adversaryFactory(acnf, ts)

	if dcnf.outputFile != "" {
		if ts, err = simulator.NewLoggingTransactionSource(dcnf.outputFile, ts); err != nil {
			panic(fmt.Sprintf("Could not open file %s for logging transactions", dcnf.outputFile))
		}
	}

	if lscnf.shardTopN > 0 {
		ts = simulator.NewLogicalShardingFilter(lscnf.seed, lscnf.shardTopN, lscnf.shardFactor, ts)
	}

	schedNum := 0
	tid := uint(0)
	trans := make([]*alg.Transaction, 1)
	flush := false
	for {
		var sgl []*alg.Subgraph
		if !flush {
			trans[0], err = ts.Get(tid)
			if err == nil {
				tid++
				if verbosity > 4 {
					trans[0].Write(bw)
					_, _ = bw.WriteRune('\n')
				}

				linearExecutionTime += trans[0].TimeCost

				sgl = sched.AddTransactions(trans)
			} else {
				flush = true
			}
		}
		if flush {
			sgl = sched.FlushSchedule()
		}
		if len(sgl) > 0 {
			schedNum++
			if verbosity > 3 {
				_, _ = fmt.Fprintf(bw, "\n\n")
				_, _ = fmt.Fprintf(bw, "Schedule %3d\n", schedNum)
				_, _ = fmt.Fprintf(bw, "------------\n")
				_, _ = fmt.Fprintf(bw, " deferred: %d\n", sched.NumDeferred())
				for _, sg := range sgl {
					sg.Write(bw)
					_, _ = bw.WriteRune('\n')
				}
			}
			// assign subgraphs to execution committees using first-free heuristic
			committee := make([]committeeMember, xcnf.numCommittees)
			h := &committeeMemberHeap{}
			heap.Init(h)
			for ix := 0; ix < xcnf.numCommittees; ix++ {
				heap.Push(h, &committee[ix])
			}
			for _, sg := range sgl {
				cmt := heap.Pop(h).(*committeeMember)
				cmt.executionTime += sg.EstExecutionTime()
				cmt.batches = append(cmt.batches, sg)
				heap.Push(h, cmt)
			}
			// Calculate execution time for this schedule (max over all members)
			schedExecutionTime := alg.ExecutionTime(0)
			for ix, cmt := range committee {
				if cmt.executionTime > schedExecutionTime {
					schedExecutionTime = cmt.executionTime
				}
				// Now show committee statistics
				if verbosity > 1 {
					_, _ = fmt.Fprintf(bw, "\n")
					_, _ = fmt.Fprintf(bw, "Committee member %d\n", ix)
					_, _ = fmt.Fprintf(bw, " est execution time = %d\n", uint64(cmt.executionTime))
					_, _ = fmt.Fprintf(bw, " number of batches = %d\n", len(cmt.batches))
					if verbosity > 2 {
						// show the subgraphs
						for _, sg := range cmt.batches {
							sg.Write(bw)
							_, _ = bw.WriteRune('\n')
						}
					}
				}
			}
			totalExecutionTime += schedExecutionTime
		}
		if flush && len(sgl) == 0 {
			break
		}
	}
	if err = ts.Close(); err != nil {
		panic(fmt.Sprintf("Transaction Source close error: %s", err.Error()))
	}

	_, _ = fmt.Fprintf(bw, "\n********\n")
	_, _ = fmt.Fprintf(bw, "Linear execution time:    %8d\n", uint64(linearExecutionTime))
	_, _ = fmt.Fprintf(bw, "Parallel execution time:  %8d\n", uint64(totalExecutionTime))
	_, _ = fmt.Fprintf(bw, "Speedup:                  %22.13f\n", float64(linearExecutionTime)/float64(totalExecutionTime))
}

func main() {
	flag.Parse()
	if verbosity > 0 {
		fmt.Println("verbosity has value ", verbosity)
	}

	bw := bufio.NewWriter(os.Stdout)
	defer func(bw *bufio.Writer) {
		if err := bw.Flush(); err != nil {
			panic(fmt.Sprintf("I/O error: %s", err.Error()))
		}
	}(bw)

	dconfigFromFlags.UpdateAndCheckDefaults()
	adversaryConfigFromFlags.UpdateAndCheckDefaults()
	lsconfigFromFlags.UpdateAndCheckDefaults()
	sconfigFromFlags.UpdateAndCheckDefaults(xconfigFromFlags)
	xconfigFromFlags.UpdateAndCheckDefaults()
	if verbosity > 0 {
		dconfigFromFlags.Show(bw)
		adversaryConfigFromFlags.Show(bw)
		lsconfigFromFlags.Show(bw)
		sconfigFromFlags.Show(bw)
		xconfigFromFlags.Show(bw)
		// Check for I/O errors _now_ instead of running the whole simulation and
		// catching it in the deferred function, since the simulation is relatively
		// expensive and we should abort early.
		if bw.Flush() != nil {
			panic("I/O error")
		}
	}

	runSimulation(dconfigFromFlags, adversaryConfigFromFlags, lsconfigFromFlags, sconfigFromFlags, xconfigFromFlags, bw)
}
