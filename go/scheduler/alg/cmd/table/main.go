package main

/*

Data table generator.

We use os/exec to do golang scripting: we run the driver with desired simulation parameters to
extract the speedup that is achievable.  Primarily we are interested in getting trend data:
suppose we hold the "normal" simulation parameters like zipf alpha, number of potential
conflict address locations, etc fixed, but varied the adversary's DOS injection probability
and/or batch size (i.e., change the expected number of DOS transactions); how will the system
parallelization ratio (increased throughput versus serial execution) respond?

*/

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/oasislabs/ekiden/go/scheduler/alg/simulator"
)

// IterationConfig is used to control how to step through various simulation parameters in
// table generator.
type IterationConfig struct {
	sortOrder           string
	alphaIter           string // from DistributionConfig
	numLocIter          string
	numReadIter         string
	numWriteIter        string
	numTransactionsIter string
	shardTopNIter       string // from LogicalShardingConfig
	shardFactorIter     string
}

var iterationConfig IterationConfig

// iteration order: list keys in odometric order, so when we iterate over the parameter space,
// we vary the right-most simulation parameter first, carry to the left, etc, just like a
// typical numeric counter.

const defaultIterationSortOrder string = "alpha,num-locations,num-reads,num-writes,shard-top,shard-factor"

func init() {
	iterationConfig = IterationConfig{}
	// if iterNameLocMap can have offset_of then it could be used more generally
	// for any IterationConfig.
	iterNameLocMap := make(map[string]*string)
	iterNameLocMap["alpha-iter"] = &iterationConfig.alphaIter
	iterNameLocMap["num-locations-iter"] = &iterationConfig.numLocIter
	iterNameLocMap["num-locations-iter"] = &iterationConfig.numLocIter
	iterNameLocMap["num-reads-iter"] = &iterationConfig.numReadIter
	iterNameLocMap["num-writes-iter"] = &iterationConfig.numWriteIter
	iterNameLocMap["num-transactions-iter"] = &iterationConfig.numTransactionsIter
	iterNameLocMap["shard-top-iter"] = &iterationConfig.shardTopNIter
	iterNameLocMap["shard-factor-iter"] = &iterationConfig.shardFactorIter

	flag.StringVar(&iterationConfig.sortOrder, "iterations-order", defaultIterationSortOrder, "the order in which to vary simulation parameters (odometric order)")

	flagSetter := func(name, descr string) {
		if _, found := iterNameLocMap[name]; !found {
			panic(fmt.Sprintf("iterNameLocMap[%s] not found", name))
		}
		flag.StringVar(iterNameLocMap[name], name, "", descr)
	}
	flagSetter("alpha-iter", "distribution (zipf) iteration control: step:end")

	flagSetter("num-locations-iter", "number of possible memory locations iteration control: step:end")
	flagSetter("num-reads-iter", "number of read locations in a transaction iteration control: step:end")
	flagSetter("num-writes-iter", "number of write locations in a transaction iteration control: step:end")
	flagSetter("num-transactions-iter", "number of transactions in a transaction iteration control: step:end")
	flagSetter("shard-top-iter", "number of highest-probability locations to shard iteration control: step:end")
	flagSetter("shard-factor-iter", "number of shards per original location iteration control: step:end")
}

// IterSortOrder takes a string representing the parameter positions in odometric order
// and return the mapping used for sorting the iterators.
func IterSortOrder(order string) (map[string]int, error) {
	words := strings.Split(order, ",") // split at comma delimiter
	insert := 0
	for _, w := range words {
		w = strings.Trim(w, " ") // remove leading/trailing spaces
		if w != "" {
			words[insert] = w
			insert++
		}
	}
	words = words[:insert]
	m := make(map[string]int)
	for ix, w := range words {
		if _, dup := m[w]; dup {
			return nil, fmt.Errorf("Duplicate entry %s found", w)
		}
		m[w] = ix
	}
	return m, nil
}

type iterOrder struct {
	data  []simulator.ParamIncr
	order map[string]int
}

func (a iterOrder) Len() int           { return len(a.data) }
func (a iterOrder) Swap(i, j int)      { a.data[i], a.data[j] = a.data[j], a.data[i] }
func (a iterOrder) Less(i, j int) bool { return a.order[a.data[i].Key()] < a.order[a.data[j].Key()] }

// SortParamIncrs sorts the entries referred to by the spi formal parameter in place, using the
// ordering specified by the order formal parameter, returning nil if successful or an error if
// there was a problem.
func SortParamIncrs(spi []simulator.ParamIncr, order map[string]int) error {
	for _, pi := range spi {
		if _, ok := order[pi.Key()]; !ok {
			return fmt.Errorf("Sort parameter %s not specified in enumeration order", pi.Key())
		}
	}
	sort.Sort(&iterOrder{data: spi, order: order})
	return nil
}

// templates or type erasure would be nice...
func addFloat64Iter(iters *[]simulator.ParamIncr, name, s string, builder func(float64, float64) simulator.ParamIncr) error {
	if s == "" {
		return nil
	}
	var inc, end float64
	if _, err := fmt.Sscanf(s, "%f:%f", &inc, &end); err != nil {
		return fmt.Errorf("%s float64 iterator config %s unparsable: %s", name, s, err)
	}
	*iters = append(*iters, builder(inc, end))
	return nil
}

func addIntIter(iters *[]simulator.ParamIncr, name, s string, builder func(int, int) simulator.ParamIncr) error {
	if s == "" {
		return nil
	}
	var inc, end int
	if _, err := fmt.Sscanf(s, "%d:%d", &inc, &end); err != nil {
		return fmt.Errorf("%s int iterator config %s unparsable: %s", name, s, err)
	}
	*iters = append(*iters, builder(inc, end))
	return nil
}

// This is not yet used since none of the iteration parameters other than seed are int64.
//
// nolint: deadcode, megacheck
func addInt64Iter(iters *[]simulator.ParamIncr, name, s string, builder func(int64, int64) simulator.ParamIncr) error {
	if s == "" {
		return nil
	}
	var inc, end int64
	if _, err := fmt.Sscanf(s, "%d:%d", &inc, &end); err != nil {
		return fmt.Errorf("%s int64 iterator config %s unparsable: %s", name, s, err)
	}
	*iters = append(*iters, builder(inc, end))
	return nil
}

// Iterators parse the iteration control flags from the receiver object and binds the
// iteration controls to the configuration objects in the formal parameter list.
//
// The idea is that the caller can iterate through the parameters by invoking Reset(),
// HasNext(), Incr() in a loop (odometric style) to go through the parameter space.
//
// The Iterators() must be called after UpdateAndCheckConfigFlags have verified that the
// initial state is okay and initialized seeds, etc.
func (ic *IterationConfig) Iterators(
	dcnf *simulator.DistributionConfig,
	lcnf *simulator.LogicalShardingConfig,
	//	acnf simulator.DistributionConfig,
) ([]simulator.ParamIncr, error) {
	iters := make([]simulator.ParamIncr, 0)
	var err error
	// var i64Inc, i64End int64
	if err = addFloat64Iter(&iters, "alpha-iter", ic.alphaIter, func(i, e float64) simulator.ParamIncr {
		return dcnf.AlphaIter(i, e)
	}); err != nil {
		return nil, err
	}
	if err = addIntIter(&iters, "num-locations-iter", ic.numLocIter, func(i, e int) simulator.ParamIncr {
		return dcnf.NumLocationsIter(i, e)
	}); err != nil {
		return nil, err
	}
	if err = addIntIter(&iters, "num-reads-iter", ic.numReadIter, func(i, e int) simulator.ParamIncr {
		return dcnf.NumReadLocationsIter(i, e)
	}); err != nil {
		return nil, err
	}
	if err = addIntIter(&iters, "num-writes-iter", ic.numWriteIter, func(i, e int) simulator.ParamIncr {
		return dcnf.NumWriteLocationsIter(i, e)
	}); err != nil {
		return nil, err
	}
	if err = addIntIter(&iters, "num-transactions-iter", ic.numTransactionsIter, func(i, e int) simulator.ParamIncr {
		return dcnf.NumTransactionsIter(i, e)
	}); err != nil {
		return nil, err
	}
	if err = addIntIter(&iters, "shard-top-iter", ic.shardTopNIter, func(i, e int) simulator.ParamIncr {
		return lcnf.ShardTopNIter(i, e)
	}); err != nil {
		return nil, err
	}
	if err = addIntIter(&iters, "shard-factor-iter", ic.shardFactorIter, func(i, e int) simulator.ParamIncr {
		return lcnf.ShardFactorIter(i, e)
	}); err != nil {
		return nil, err
	}
	return iters, nil
}

// nolint: gocyclo
func main() {
	flag.Parse()

	bw := bufio.NewWriter(os.Stdout)
	defer func(bw *bufio.Writer) {
		if err := bw.Flush(); err != nil {
			panic(fmt.Sprintf("I/O error: %s", err.Error()))
		}
	}(bw)

	// Initial values.
	simulator.UpdateAndCheckConfigFlags()

	dcnf := simulator.DistributionConfigFromFlags
	acnf := simulator.AdversaryConfigFromFlags
	lcnf := simulator.LogicalShardingConfigFromFlags
	scnf := simulator.SchedulerConfigFromFlags
	xcnf := simulator.ExecutionConfigFromFlags

	// Check for I/O errors _now_ instead of running the whole simulation and
	// catching it in the deferred function, since the simulation is relatively
	// expensive and we should abort early.
	if bw.Flush() != nil {
		panic("I/O error")
	}

	paramIncrs, err := iterationConfig.Iterators(&dcnf, &lcnf)
	if err != nil {
		panic(fmt.Sprintf("Iterator parsing error: %s", err.Error()))
	}
	iOrder, err := IterSortOrder(iterationConfig.sortOrder)
	if err != nil {
		panic(fmt.Sprintf("Iterator sort order parsing error: %s", err.Error()))
	}
	err = SortParamIncrs(paramIncrs, iOrder)
	if err != nil {
		panic(fmt.Sprintf("Iterator sort error: %s", err.Error()))
	}

	for {
		simulator.ShowConfigFlags(bw, dcnf, acnf, lcnf, scnf, xcnf)
		if bw.Flush() != nil {
			panic("I/O error for simulation configuration output")
		}

		res := simulator.RunSimulationWithConfigs(dcnf, acnf, lcnf, scnf, xcnf, bw)
		_, _ = fmt.Fprintf(bw, "Linear execution time:    %8d\n", res.LinearExecutionTime)
		_, _ = fmt.Fprintf(bw, "Actual execution time:    %8d\n", res.ActualExecutionTime)
		_, _ = fmt.Fprintf(bw, "Speedup:                  %22.13f\n", float64(res.LinearExecutionTime)/float64(res.ActualExecutionTime))
		_, _ = fmt.Fprintf(bw, "Number of schedules:      %8d\n", res.NumberOfSchedules)
		if bw.Flush() != nil {
			panic("I/O error during summary statistics")
		}

		ix := len(paramIncrs) - 1
		for {
			if ix < 0 {
				break
			}
			if paramIncrs[ix].HasNext() {
				paramIncrs[ix].Incr()
				break
			}
			paramIncrs[ix].Reset()
			ix--
		}
		if ix < 0 {
			break
		}
	}
}
