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
	"fmt"
	"os/exec"
)

type execParams {
	numCommittees int
}

func (ep *execParams) ParamList() []string {
	rv := make([]string, 0)
	rv = append(rv, fmt.Sprintf("-num-committees=%d", ep.numCommittees))
	return rv
}

func main() {
	ep execParams
	ep.numCommittees = 10
	cmd := exec.Command("./driver", ep.ParmList()...)
	err := cmd.Run()
	if err != nil {
		panic(fmt.Sprintf("driver run error: %s", err.Error()))
	}
	data, err := cmd.Output()
	if err != nil {
		panic(fmt.Sprintf("driver output error: %s", err.Error()))
	}
	_, _ = fmt.Printf("Output:", data)
}
