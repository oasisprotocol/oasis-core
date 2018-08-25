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

	"github.com/oasislabs/ekiden/go/scheduler/alg/simulator"
)

// IterationConfig is used to control how to step through various simulation parameters in
// table generator.
type IterationConfig struct {
	// from DistributionConfig
	alphaIter string
	numLocIter string
	numReadIter string
	numWriteIter string
}

var iterationConfig IterationConfig

func init() {
	iterationConfig = IterationConfig{}
	flag.StringVar(&iterationConfig.alphaIter, "alpha-iter", "",
		"distribution (zipf) iteration control: step:end")
	flag.StringVar(&iterationConfig.numLocIter, "num-locations-iter", "",
		"number of possible memory locations iteration control: step:end")
	flag.StringVar(&iterationConfig.numReadIter, "num-reads-iter", "",
		"number of read locations in a transaction iteration control: step:end")
	flag.StringVar(&iterationConfig.numWriteIter, "num-writes-iter", "",
		"number of write locations in a transaction iteration control: step:end")
}

// iteration order: list keys in odometric order, so when we iterate over the parameter space,
// we vary the right-most simulation parameter first, carry to the left, etc, just like a
// typical numeric counter.
const defaultIterationOrder = "alpha,num-locations,num-reads,num-writes"

func iterSortOrder(order string) (map[string]int, error) {
	words := strings.Split(order, ",") // split at comma delimiter
	insert := 0
	for _, w := range(words) {
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
	data []ParamIncr
	order map[string]int
}

func (a iterOrder) Len() int { return len(a.data) }
func (a iterOrder) Swap(i, j int) { a.data[i], a.data[j] = a.data[j], a.data[i] }
func (a iterOrder) Less(i, j int) bool { return order[a.data[i].Key()] < order[a.data[j].Key()] }

// Sorts the entries referred to by the spi formal parameter in place, using the ordering
// specified by the order formal parameter, returning nil if successful or an error if there
// was a problem.
func SortParamIncrs(spi []ParamIncr, order map[string]int) error {
	for _, pi := range(spi) {
		if _, ok := order[pi.Key()]; !ok {
			return fmt.Errorf("Sort parameter %s not specified in enumeration order", pi.Key())
		}
	}
	sort.Sort(&iterOrder{data: spi, order: order))
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
func (ic *IteratationConfig) Iterators(
	dcnf *simulator.DistributionConfig,
	acnf *simulator.DistributionConfig,
) ([]ParamIncr, error) {
	iters := make([]ParamIncr, 0)
	var fInc, fEnd float64
	var iInc, iEnd int
	// var i64Inc, i64End int64
	if ic.alphaIter != "" {
		if _, err := fmt.Sscanf("%f:%f", &fInc, &fEnd); err != nil {
			return nil, err
		}
		iters = append(iters, dcnf.AlphaIter(fInc, fEnd))
	}
	if ic.numLocIter != "" {
		if _, err := fmt.Sscanf("%f:%f", &iInc, &iEnd); err != nil {
			return nil, err
		}
		iters = append(iters, dcnf.NumLocationsIter(iInc, iEnd))
	}
	return iters
}

func main() {
	flag.Parse()

	bw := bufio.NewWriter(os.Stdout)
	defer func(bw *bufio.Writer) {
		if err := bw.Flush(); err != nil {
			panic(fmt.Sprintf("I/O error: %s", err.Error()))
		}
	}(bw)

	simulator.UpdateAndCheckConfigFlags()
	simulator.ShowConfigFlags(bw)

	// Check for I/O errors _now_ instead of running the whole simulation and
	// catching it in the deferred function, since the simulation is relatively
	// expensive and we should abort early.
	if bw.Flush() != nil {
		panic("I/O error")
	}

	// Initial values.
	dcnf := simulator.DistributionConfigFromFlags
	acnf := simulator.AdversaryConfigFromFlags
	lcnf := simulator.LogicalShardingConfigFromFlags
	scnf := simulator.SchedulerConfigFromFlags
	xcnf := simulator.ExecutionConfigFromFlags

	// TODO: run this in a loop, but varying one configuration parameter at a time...
	res := simulator.RunSimulationWithConfigs(dcnf, acnf, lcnf, scnf, xcnf, bw)
	_, _ = fmt.Printf("Linear execution time:    %8d\n", res.LinearExecutionTime)
	_, _ = fmt.Printf("Actual execution time:    %8d\n", res.ActualExecutionTime)
	_, _ = fmt.Printf("Speedup:                  %22.13f\n", float64(res.LinearExecutionTime)/float64(res.ActualExecutionTime))
	_, _ = fmt.Printf("Number of schedules:      %8d\n", res.NumberOfSchedules)
}
