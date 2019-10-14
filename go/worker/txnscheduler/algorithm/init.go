package algorithm

import (
	"fmt"

	flag "github.com/spf13/pflag"

	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm/api"
	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/algorithm/batching"
)

// Flags has the configuration flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// New creates a new algorithm.
func New(name string) (api.Algorithm, error) {
	switch name {
	case batching.Name:
		return batching.New()
	default:
		return nil, fmt.Errorf("invalid transaction scheduler algorithm: %s", name)
	}
}

func init() {
	Flags.AddFlagSet(batching.Flags)
}
