package workload

import (
	"math/rand"

	"google.golang.org/grpc"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
)

type Workload interface {
	Run(rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, rtc runtimeClient.RuntimeClient) error
}

// ByName is the registry of workloads that you can access with `--workload <name>` on the command line.
var ByName = map[string]Workload{
	NameTransfer: transfer{},
}
