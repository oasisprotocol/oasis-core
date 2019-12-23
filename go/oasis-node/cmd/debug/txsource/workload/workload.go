package workload

import (
	"math/rand"

	"google.golang.org/grpc"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
)

type Runner func(rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, _ runtimeClient.RuntimeClient) error

var ByName = map[string]Runner{
	NameTransfer: runTransfer,
}
