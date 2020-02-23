package workload

import (
	"context"
	"math/rand"

	"google.golang.org/grpc"

	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
)

// Workload is a DRBG-backed schedule of transactions.
type Workload interface {
	// Run executes the workload.
	// If `gracefulExit`'s deadline passes, it is not an error.
	// Return `nil` after any short-ish amount of time in that case.
	// Prefer to do at least one "iteration" even so.
	Run(
		gracefulExit context.Context,
		rng *rand.Rand,
		conn *grpc.ClientConn,
		cnsc consensus.ClientBackend,
		rtc runtimeClient.RuntimeClient,
	) error
}

// ByName is the registry of workloads that you can access with `--workload <name>` on the command line.
var ByName = map[string]Workload{
	NameTransfer:  transfer{},
	NameOversized: oversized{},
}
