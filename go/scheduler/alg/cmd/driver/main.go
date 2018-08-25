package main

/*

Scheduling algorithm driver.

Generate / read randomly generated sythetic transaction descriptions (or actual data extracted
from Parity) and feed into selected scheduling algorithm.

*/

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/oasislabs/ekiden/go/scheduler/alg/simulator"
)

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

	res := simulator.RunSimulation(bw)

	_, _ = fmt.Fprintf(bw, "\n********\n")
	_, _ = fmt.Fprintf(bw, "Linear execution time:    %8d\n", uint64(res.LinearExecutionTime))
	_, _ = fmt.Fprintf(bw, "Parallel execution time:  %8d\n", uint64(res.ActualExecutionTime))
	_, _ = fmt.Fprintf(bw, "Speedup:                  %22.13f\n", float64(res.LinearExecutionTime)/float64(res.ActualExecutionTime))
	_, _ = fmt.Fprintf(bw, "Number of schedules:      %8d\n", res.NumberOfSchedules)
}
