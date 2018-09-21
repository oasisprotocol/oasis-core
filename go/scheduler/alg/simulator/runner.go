package simulator

import (
	"bufio"
	"container/heap"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"time"

	"github.com/oasislabs/ekiden/go/scheduler/alg"
	"github.com/oasislabs/ekiden/go/scheduler/alg/iterflag"
	"github.com/oasislabs/ekiden/go/scheduler/alg/randgen"
)

// Verbosity is a single, global flag, and per-module flags are grouped together in *Config
// structs, with a *FromFlags global instance/singleton, just like verbosity.  The convention
// is that we use an init() function to provide initial values, help strings, etc, then in
// main() we invoke flag.Parse(), after which we run the UpdateAndCheckDefaults() method to
// check for contradictory flags, update defaults (e.g., if an input file is specified as the
// source of synthetic load data, then the distribution parameter that controls the
// pseudorandom synthetic load generation has to be unset or set to "input").  For simulation
// main programs that do not have a separate verbosity flag, this is a global.  (And this
// module is commandeering the "-verbosity" flag name anyway.)
var Verbosity int

// SimulationResults contains summary information about how well the scheduler performed.  We
// are primarily interested in the ActualExecutionTime vs LinearExecutionTime -- where
// ActualExecutionTime is based on the sum of the maximum execution times over all the
// committees per schedule, over all execution scheduled produced by the scheduler.  It does
// not include the work that must be done to verify conflict-freeness at the root hash, nor
// does it (currently) include any simulated data-dependency transaction reverts that cause an
// entire batch to have to be re-executed.
type SimulationResults struct {
	LinearExecutionTime int64
	ActualExecutionTime int64
	NumberOfSchedules   int
}

// DistributionConfig are distribution parameters, gathered into one struct.  When we add new
// distributions we should just add new fields.  The factory function for sources will only use
// the config value(s) appropriate for the selected TransactionSource.
type DistributionConfig struct {
	seed             int64
	seedRng          *rand.Rand
	distributionName string // "uniform", "zipf", "cryptokitties"
	inputFile        string // "-" means standard input
	outputFile       string
	alpha            float64
	numLocations     int
	numReadLocs      int
	readZipfAlpha    float64
	numWriteLocs     int
	writeZipfAlpha   float64
	writeZipfMin     int
	damZipfAlpha     float64
	sireZipfAlpha    float64
	numAutoBirthers  int
	numTransactions  int
}

const useInput = "input"

// Show prints the config parameters.  For verbosity level where execution parameters ought to
// be shown.  Use flag names instead of variable names.  Instead of flag.PrintDefaults(), what
// we want is a flag.PrintActual() for showing simulator initial state, after flag.Parse() is
// done, and any special case handling (e.g. seed, or SchedulerConfigFromFlags.maxPending
// below).
func (dcnf *DistributionConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nSynthetic Load Generator Parameters\n")
	_, _ = fmt.Fprintf(bw, "  seed = %d\n", dcnf.seed)
	_, _ = fmt.Fprintf(bw, "  distribution = \"%s\"\n", dcnf.distributionName)
	_, _ = fmt.Fprintf(bw, "  input = \"%s\"\n", dcnf.inputFile)
	_, _ = fmt.Fprintf(bw, "  output = \"%s\"\n", dcnf.outputFile)
	_, _ = fmt.Fprintf(bw, "  alpha = %f\n", dcnf.alpha)
	_, _ = fmt.Fprintf(bw, "  num-locations = %d\n", dcnf.numLocations)
	_, _ = fmt.Fprintf(bw, "  num-reads = %d\n", dcnf.numReadLocs)
	_, _ = fmt.Fprintf(bw, "  read-zipf-alpha = %f\n", dcnf.readZipfAlpha)
	_, _ = fmt.Fprintf(bw, "  num-writes = %d\n", dcnf.numWriteLocs)
	_, _ = fmt.Fprintf(bw, "  write-zipf-alpha = %f\n", dcnf.writeZipfAlpha)
	_, _ = fmt.Fprintf(bw, "  write-zipf-min = %d\n", dcnf.writeZipfMin)
	_, _ = fmt.Fprintf(bw, "  dam-zipf-alpha = %f\n", dcnf.damZipfAlpha)
	_, _ = fmt.Fprintf(bw, "  sire-zipf-alpha = %f\n", dcnf.sireZipfAlpha)
	_, _ = fmt.Fprintf(bw, "  num-auto-birthers = %d\n", dcnf.numAutoBirthers)
	_, _ = fmt.Fprintf(bw, "  num-transactions = %d\n", dcnf.numTransactions)
}

// UpdateAndCheckDefaults sets the RNG seed if unspecified by a command-line flag and ensures
// that the "input" distribution name is used when there is a file named via the -input-file
// flag.
//
// nolint: gocyclo
func (dcnf *DistributionConfig) UpdateAndCheckDefaults() {
	if dcnf.seed == 0 {
		dcnf.seed = time.Now().UTC().UnixNano()
	}
	dcnf.seedRng = rand.New(rand.NewSource(dcnf.seed))
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
	if dcnf.numLocations < 0 {
		panic("Number of memory/conflict locations (num-locations) cannot be negative")
	}
	if dcnf.numReadLocs < 0 {
		panic("Number of read locations per transaction (num-reads) cannot be negative")
	}
	// read-only transactions need not be scheduled
	if dcnf.numWriteLocs <= 0 {
		panic("Number of write locations per transaction (num-writes) must be positive")
	}
	if dcnf.numTransactions <= 0 {
		panic("Number of transactions to generate (num-transactions) must be positive")
	}
	if dcnf.numAutoBirthers <= 0 {
		panic("Number of auto-birthers must be positive")
	}
}

// DistributionConfigFromFlags is the random distribution generator configurations as set
// by command-line flags.  This is visible for the table-generator so that it can vary the
// simulation parameters to generate data showing how a particular algorithm responds to
// configuration parameters.
var DistributionConfigFromFlags DistributionConfig

// AdversaryConfig contains the configuration parameters for how an adversary may attempt to
// inject DOS transactions that contain (maximally) conflicting read/write-set locations.
type AdversaryConfig struct {
	seed            int64
	seedRng         *rand.Rand
	injectionProb   float64
	targetFrac      float64
	readFrac        float64
	dosBatchSize    int
	targetAddresses string
	seqno           int

	// not set via config, but during param validation to avoid dup work
	targets *alg.LocationRangeSet
}

// Show prints the AdversaryConfig configuration parameters.
func (acnf *AdversaryConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nAdversary (DOS) Transaction Generator Parameters\n")
	_, _ = fmt.Fprintf(bw, "  dos-seed = %d\n", acnf.seed)
	_, _ = fmt.Fprintf(bw, "  dos-injection-prob = %g\n", acnf.injectionProb)
	_, _ = fmt.Fprintf(bw, "  dos-target-fraction = %g\n", acnf.targetFrac)
	_, _ = fmt.Fprintf(bw, "  dos-read-fraction = %g\n", acnf.readFrac)
	_, _ = fmt.Fprintf(bw, "  dos-batch-size = %d\n", acnf.dosBatchSize)
	_, _ = fmt.Fprintf(bw, "  dos-target-addresses = %s\n", acnf.targetAddresses)
	_, _ = fmt.Fprintf(bw, "  dos-seqno = %d\n", acnf.seqno)
}

// UpdateAndCheckDefaults verifies that command-line flag values are sane.  Some are
// automatically set, viz, the PRNG seed, if unspecified at the command line, is set based on
// the time.
func (acnf *AdversaryConfig) UpdateAndCheckDefaults() {
	if acnf.seed == 0 {
		acnf.seed = time.Now().UTC().UnixNano()
	}
	acnf.seedRng = rand.New(rand.NewSource(acnf.seed))
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

// AdversaryConfigFromFlags is the adversarial (DOS) transaction generator configurations as
// set by command-line flags.  This is visible for the table-generator so that it can vary the
// simulation parameters to generate data showing how a particular algorithm responds to
// configuration parameters.
var AdversaryConfigFromFlags AdversaryConfig

// LogicalShardingConfig holds configuration variables that control how LogicalShardingFilter
// performs sharding.
type LogicalShardingConfig struct {
	seed        int64
	seedRng     *rand.Rand
	shardTopN   int
	shardFactor int
}

// Show prints the LogicalShardingConfig configuration parameters.
func (lcnf *LogicalShardingConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nLogical Sharding Parameters\n")
	_, _ = fmt.Fprintf(bw, "  shard-seed = %d\n", lcnf.seed)
	_, _ = fmt.Fprintf(bw, "  shard-top = %d\n", lcnf.shardTopN)
	_, _ = fmt.Fprintf(bw, "  shard-factor = %d\n", lcnf.shardFactor)
}

// UpdateAndCheckDefaults sets the RNG seed for the sharding RNG, if unspecified by a
// command-line flag.
func (lcnf *LogicalShardingConfig) UpdateAndCheckDefaults() {
	if lcnf.seed == 0 {
		lcnf.seed = time.Now().UTC().UnixNano()
	}
	lcnf.seedRng = rand.New(rand.NewSource(lcnf.seed))
}

// LogicalShardingConfigFromFlags is the logical sharding filter configurations as set by
// command-line flags.  This is visible for the table-generator so that it can vary the
// simulation parameters to generate data showing how a particular algorithm responds to
// configuration parameters.
var LogicalShardingConfigFromFlags LogicalShardingConfig

// SchedulerConfig contains the configuration parametres for the scheduler(s).  Since more than
// one scheduling algorithm may be chosen, this essentially contains the union of all
// configuration flags that these schedulers need.
type SchedulerConfig struct {
	name string

	// Buffer at most this many transactions before generating a schedule.
	maxPending int

	// Additional fraction of previous scheduled transactions to use in max-pending update
	excessFraction float64

	// maxTime is per subgraph execution time, but post-schedule generation subgraph merging
	// will result in higher total execution times per compute committee.
	maxTime int
}

// Show prints the SchedulerConfig fields.  NB: not all schedulers will use all fields.
func (scnf *SchedulerConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nScheduler Configuration Parameters\n")
	_, _ = fmt.Fprintf(bw, "  scheduler = \"%s\"\n", scnf.name)
	_, _ = fmt.Fprintf(bw, "  max-pending = %d\n", scnf.maxPending)
	_, _ = fmt.Fprintf(bw, "  excess-fraction = %g\n", scnf.excessFraction)
	_, _ = fmt.Fprintf(bw, "  max-subgraph-time = %d\n", scnf.maxTime)
}

// UpdateAndCheckDefaults sets the maxPending configuration based on other configuration
// values if it had not been set by a command-line flag.
func (scnf *SchedulerConfig) UpdateAndCheckDefaults(numCommittees int) {
	if scnf.maxPending < 0 {
		scnf.maxPending = 2 * scnf.maxTime * numCommittees
	}
}

// SchedulerConfigFromFlags is the transaction scheduler configurations as set by command-line
// flags.  This is visible for the table-generator so that it can vary the simulation
// parameters to generate data showing how a particular algorithm responds to configuration
// parameters.
var SchedulerConfigFromFlags SchedulerConfig

// ExecutionConfig contains configuration parameters for the execution environment.  For now,
// it only contains the number of execution committees.
type ExecutionConfig struct {
	numCommittees int
}

// Show prints the ExecutionConfig.
func (xcnf *ExecutionConfig) Show(bw io.Writer) {
	_, _ = fmt.Fprintf(bw, "\nExecution Simulator Parameters\n")
	_, _ = fmt.Fprintf(bw, "  num-committees = %d\n", xcnf.numCommittees)
}

// UpdateAndCheckDefaults verifies that the ExecutionConfig makes sense (positive numCommittee).
func (xcnf *ExecutionConfig) UpdateAndCheckDefaults() {
	if xcnf.numCommittees < 1 {
		panic(fmt.Sprintf("Number of execution committees must be at least 1, not %d",
			xcnf.numCommittees))
	}
}

// ExecutionConfigFromFlags is the execution configurations as set by command-line
// flags.  This is visible for the table-generator so that it can vary the simulation
// parameters to generate data showing how a particular algorithm responds to configuration
// parameters.
var ExecutionConfigFromFlags ExecutionConfig

// Set up flag variables with default values before main runs.  NB: some default values are
// indicators that the values should be updated when UpdateAndCheckDefaults for the flag group
// is invoked.
func init() {
	DistributionConfigFromFlags = DistributionConfig{}
	AdversaryConfigFromFlags = AdversaryConfig{}
	LogicalShardingConfigFromFlags = LogicalShardingConfig{}
	SchedulerConfigFromFlags = SchedulerConfig{}
	ExecutionConfigFromFlags = ExecutionConfig{}

	flag.IntVar(&Verbosity, "verbosity", 0, "verbosity level for debug output")

	// Distribution generator parameters

	// seed is only important for reproducible RNG; inputFile/outputFile is another
	// mechanism for reproducibility
	flag.Int64Var(&DistributionConfigFromFlags.seed, "seed", 0,
		"pseudorandom number generator seed for synthetic load generator (default: UnixNano)")

	flag.StringVar(&DistributionConfigFromFlags.distributionName, "distribution", "zipf",
		"random location generation distribution (uniform, or zipf)")
	flag.StringVar(&DistributionConfigFromFlags.inputFile, "input", "",
		"read transactions from file instead of generating")
	flag.StringVar(&DistributionConfigFromFlags.outputFile, "output", "",
		"write transactions to file in addition to scheduling")
	iterflag.Float64Var(&DistributionConfigFromFlags.alpha, "alpha", 0.6, 1.001, 0.2,
		"zipf distribution alpha parameter")
	// For the Ethereum world, the number of possible locations is 2^{160+256}, but it is
	// extremely sparse.  Furthermore, many locations are in (pseudo) equivalence classes,
	// i.e., if a contract reads one of the locations, then it is almost certainly going to
	// read the rest, and similarly for writes.
	iterflag.IntVar(&DistributionConfigFromFlags.numLocations, "num-locations",
		1000000, 1000000, 0, "number of possible memory locations")

	iterflag.IntVar(&DistributionConfigFromFlags.numReadLocs, "num-reads", 0, 0, 0,
		"number of read locations in a transaction")
	iterflag.Float64Var(&DistributionConfigFromFlags.readZipfAlpha, "read-zipf-alpha",
		0.0, 0.0, 0.0, "Zipf alpha parameter for num-reads Rng, from [0, num-reads+1); use 0.0 to use num-reads as a constant")

	iterflag.IntVar(&DistributionConfigFromFlags.numWriteLocs, "num-writes", 2, 2, 0,
		"number of write locations in a transaction")
	iterflag.Float64Var(&DistributionConfigFromFlags.writeZipfAlpha, "write-zipf-alpha",
		0.0, 0.0, 0.0, "Zipf alpha parameter for num-writes Rng, from zipf-write-min + [0, num-writes); use 0.0 to use num-writes as a constant")
	iterflag.IntVar(&DistributionConfigFromFlags.writeZipfMin, "write-zipf-min",
		2, 2, 0, "Zipf generation parameter for num-writes Rng, generating zipf-write-min + [0, num-writes)")

	iterflag.Float64Var(&DistributionConfigFromFlags.damZipfAlpha, "dam-zipf-alpha",
		0.5, 0.5, 0.0, "Zipf alpha parameter for cryptokitties distribution, dam kitties")
	iterflag.Float64Var(&DistributionConfigFromFlags.sireZipfAlpha, "sire-zipf-alpha",
		0.7, 0.7, 0.0, "Zipf alpha parameter for cryptokitties distribution, sire kitties")
	iterflag.IntVar(&DistributionConfigFromFlags.numAutoBirthers, "num-auto-birthers",
		1000, 1000, 0, "number of auto-birthers for cryptokitties distribution")

	iterflag.IntVar(&DistributionConfigFromFlags.numTransactions, "num-transactions",
		1000000, 1000000, 0, "number of transactions to generate")

	// Adversary configuration parameters

	flag.Int64Var(&AdversaryConfigFromFlags.seed, "dos-seed", 0, "seed for rng used to randomize DOS-spam adversary actions")
	iterflag.Float64Var(&AdversaryConfigFromFlags.injectionProb, "dos-injection-prob", 0.0, 0.0, 0.0, "probability of deciding to inject (possibly many) DOS transactions (0 disables adversary)")
	iterflag.Float64Var(&AdversaryConfigFromFlags.targetFrac, "dos-target-fraction", 0.9, 0.9, 0.0, "fraction of DOS addresses that will be attacked")
	iterflag.Float64Var(&AdversaryConfigFromFlags.readFrac, "dos-read-fraction", 0.0, 0.0, 0.0, "fraction of DOS addresses under attack that go to the read set (rest go to the write set)")
	iterflag.IntVar(&AdversaryConfigFromFlags.dosBatchSize, "dos-batch-size", 100, 100, 0, "number of DOS transactions to inject, once decision to DOS spam is made")
	flag.StringVar(&AdversaryConfigFromFlags.targetAddresses, "dos-target-addresses", "0:15,128:131", "comma-separated list of integers or start-end integer ranges")
	flag.IntVar(&AdversaryConfigFromFlags.seqno, "dos-seqno", 1000000, "starting seqno/id for DOS spam transactions")

	// Logical sharding filter configuration parameters

	flag.Int64Var(&LogicalShardingConfigFromFlags.seed, "shard-seed", 0,
		"pseudorandom number generator seed for logical sharding filter (default: UnixNano)")
	iterflag.IntVar(&LogicalShardingConfigFromFlags.shardTopN, "shard-top", 0, 33, 8,
		"shard the highest <shard-top> probable locations")
	iterflag.IntVar(&LogicalShardingConfigFromFlags.shardFactor, "shard-factor", 16, 16, 0,
		"number of new (negative) shards per original location")

	// Scheduler configuration parameters

	flag.StringVar(&SchedulerConfigFromFlags.name, "scheduler", "greedy-subgraph-adaptive",
		"scheduling algorithm (greedy-subgraph or greedy-subgraph-adaptive)")
	iterflag.IntVar(&SchedulerConfigFromFlags.maxPending, "max-pending", -1, -1, 0,
		"run scheduling when there are this many transactions (-1 means 2 * max-time * num-committees); for the greedy-subgraph-adaptive algorithm, this is just the initial value and will be dynamically adjusted")
	iterflag.Float64Var(&SchedulerConfigFromFlags.excessFraction, "excess-fraction",
		0.2, 0.2, 0.0,
		"additional fraction of actual number of transactions scheduled in previous batch to use for max-pending for the next batch")
	// In the python simulator, this was 'block_size', and we may still want to have a
	// maximum transactions as well as maximum execution time.
	iterflag.IntVar(&SchedulerConfigFromFlags.maxTime, "max-subgraph-time", 20, 20, 0,
		"disallow adding to a subgraph if the total estimated execution time would exceed this")

	// Execution Committees configuration parameters
	iterflag.IntVar(&ExecutionConfigFromFlags.numCommittees, "num-committees", 50, 451, 100,
		"number of execution committees")
}

// UpdateAndCheckConfigFlags updates and checks all command-line flag values for this module.
func UpdateAndCheckConfigFlags() {
	DistributionConfigFromFlags.UpdateAndCheckDefaults()
	AdversaryConfigFromFlags.UpdateAndCheckDefaults()
	LogicalShardingConfigFromFlags.UpdateAndCheckDefaults()
	SchedulerConfigFromFlags.UpdateAndCheckDefaults(ExecutionConfigFromFlags.numCommittees)
	ExecutionConfigFromFlags.UpdateAndCheckDefaults()
}

// ShowConfigFlags prints the current command-line flag values to the io.Writer stream.
func ShowConfigFlags(bw io.Writer, dcnf DistributionConfig, acnf AdversaryConfig, lcnf LogicalShardingConfig, scnf SchedulerConfig, xcnf ExecutionConfig) {
	dcnf.Show(bw)
	acnf.Show(bw)
	lcnf.Show(bw)
	scnf.Show(bw)
	xcnf.Show(bw)
}

// transactionSourceFactory consults the DistributionConfig arg to build and return a
// TransactionSource, which may be from a canned input data file, from random generator of
// transactions (with various memory access distributions), etc.
func transactionSourceFactory(cnf *DistributionConfig) TransactionSource {
	if cnf.distributionName == useInput {
		fts, err := NewFileTransactionSource(cnf.inputFile)
		if err != nil {
			panic(fmt.Sprintf("Error: %s; cannot open \"%s\"", err.Error(), cnf.inputFile))
		}
		return fts
	}

	if cnf.distributionName == "cryptokitties" {
		coinRng := rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))

		uniformRng := rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))
		damRng, err := randgen.NewZipf(cnf.damZipfAlpha, cnf.numLocations-1, uniformRng)
		if err != nil {
			panic(fmt.Sprintf("dam Rng: %s", err.Error()))
		}
		damRng = randgen.NewAdd([]randgen.Rng{damRng, randgen.NewFixed(1)})

		uniformRng = rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))
		sireRng, err := randgen.NewZipf(cnf.sireZipfAlpha, cnf.numLocations-1, uniformRng)
		if err != nil {
			panic(fmt.Sprintf("sire Rng: %s", err.Error()))
		}
		sireRng = randgen.NewAdd([]randgen.Rng{sireRng, randgen.NewFixed(1)})

		uniformRng = rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))
		birtherRng, err := randgen.NewUniform(cnf.numAutoBirthers, uniformRng)
		if err != nil {
			panic(fmt.Sprintf("birther Rand: %s", err.Error()))
		}

		return NewCryptoKittiesTransactionSource(cnf.numTransactions, coinRng, damRng, sireRng, birtherRng)
	}

	var err error
	var rg randgen.Rng

	rng := rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))
	if cnf.distributionName == "uniform" {
		if rg, err = randgen.NewUniform(cnf.numLocations, rng); err != nil {
			panic(err.Error())
		}
	} else if cnf.distributionName == "zipf" {
		if rg, err = randgen.NewZipf(cnf.alpha, cnf.numLocations, rng); err != nil {
			panic(err.Error())
		}
	} else {
		panic(fmt.Sprintf("Random distribution name not recognized: %s", cnf.distributionName))
	}

	var rdRng, wrRng randgen.Rng
	if cnf.readZipfAlpha == 0.0 {
		rdRng = randgen.NewFixed(cnf.numReadLocs)
	} else {
		uniformRng := rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))
		rdRng, err = randgen.NewZipf(cnf.readZipfAlpha, cnf.numReadLocs+1, uniformRng)
		if err != nil {
			panic(err.Error())
		}
	}
	if cnf.writeZipfAlpha == 0.0 {
		wrRng = randgen.NewFixed(cnf.numWriteLocs)
	} else {
		uniformRng := rand.New(rand.NewSource(int64(cnf.seedRng.Uint64())))
		wrRng, err = randgen.NewZipf(cnf.writeZipfAlpha, cnf.numWriteLocs, uniformRng)
		if err != nil {
			panic(err.Error())
		}
		// 1 + [0, numWriteLocs) since 0 write locations make no sense: a read-only
		// view transaction should not get scheduled.
		wrRng = randgen.NewAdd([]randgen.Rng{wrRng, randgen.NewFixed(cnf.writeZipfMin)})
	}

	return NewRandomDistributionRandNumLocationsTransactionSource(cnf.numTransactions, rdRng, wrRng, rg)
}

func adversaryFactory(acnf *AdversaryConfig, ts TransactionSource) TransactionSource {
	if acnf.injectionProb == 0.0 {
		if Verbosity > 2 {
			fmt.Printf("No Adversarial transactions will be injected\n")
		}
		return ts
	}
	seed := int64(acnf.seedRng.Uint64())
	ats, err := NewAdversarialTransactionSource(
		seed,
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

func schedulerFactory(scnf *SchedulerConfig) alg.Scheduler {
	if scnf.name == "greedy-subgraph-adaptive" {
		return alg.NewGreedySubgraphsAdaptiveQueuingScheduler(scnf.maxPending, scnf.excessFraction, alg.ExecutionTime(scnf.maxTime))
	} else if scnf.name == "greedy-subgraph" {
		return alg.NewGreedySubgraphsScheduler(scnf.maxPending, alg.ExecutionTime(scnf.maxTime))
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

// RunSimulationWithConfigs generate transactions and execute them, with the various
// transaction sources, etc configured according to the corresponding argument, and with
// verbosity output going to |bw|.  The caller is responsible for checking I/O errors via
// bw.Flush.  Other (configuration) errors result in panic here.
//
// Returns a SimulationResult, which gives summary data about the execution time (and parallel
// speedup achieved).
//
// nolint: gocyclo
func RunSimulationWithConfigs(
	dcnf *DistributionConfig,
	acnf *AdversaryConfig,
	lcnf *LogicalShardingConfig,
	scnf *SchedulerConfig,
	xcnf *ExecutionConfig,
	bw *bufio.Writer) SimulationResults {

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
		if ts, err = NewLoggingTransactionSource(dcnf.outputFile, ts); err != nil {
			panic(fmt.Sprintf("Could not open file %s for logging transactions", dcnf.outputFile))
		}
	}

	if lcnf.shardTopN > 0 {
		seed := int64(lcnf.seedRng.Uint64())
		ts = NewLogicalShardingFilter(seed, lcnf.shardTopN, lcnf.shardFactor, ts)
	}

	schedNum := 0
	tid := 0
	trans := make([]*alg.Transaction, 1)
	flush := false
	for {
		var sgl []*alg.Subgraph
		if !flush {
			trans[0], err = ts.Get(tid)
			if err == nil {
				tid++
				if Verbosity > 10 {
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
			if Verbosity > 5 {
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
				if Verbosity > 3 {
					_, _ = fmt.Fprintf(bw, "\n")
					_, _ = fmt.Fprintf(bw, "Committee member %d\n", ix)
					_, _ = fmt.Fprintf(bw, " est execution time = %d\n", uint64(cmt.executionTime))
					_, _ = fmt.Fprintf(bw, " number of batches = %d\n", len(cmt.batches))
					if Verbosity > 4 {
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
	return SimulationResults{
		LinearExecutionTime: int64(linearExecutionTime),
		ActualExecutionTime: int64(totalExecutionTime),
		NumberOfSchedules:   schedNum,
	}
}

// RunSimulation runs the simulator with the command-line provided flags.
func RunSimulation(bw *bufio.Writer) SimulationResults {
	return RunSimulationWithConfigs(&DistributionConfigFromFlags, &AdversaryConfigFromFlags, &LogicalShardingConfigFromFlags, &SchedulerConfigFromFlags, &ExecutionConfigFromFlags, bw)
}
