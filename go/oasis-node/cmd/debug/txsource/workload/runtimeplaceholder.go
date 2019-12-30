package workload

import (
	"context"
	"fmt"
	"math/rand"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
)

var (
	_ Workload = runtimePlaceholder{}

	runtimePlaceholderLogger = logging.GetLogger("cmd/txsource/workload/runtimeplaceholder")
)

type runtimePlaceholder struct{}

func (runtimePlaceholder) Run(_ context.Context, _ *rand.Rand, _ *grpc.ClientConn, _ consensus.ClientBackend, rtc runtimeClient.RuntimeClient) error {
	ctx := context.Background()
	var tx *runtimeClient.SubmitTxRequest
	// Placeholder for sending a runtime transaction from a workload.
	out, err := rtc.SubmitTx(ctx, tx)
	if err != nil {
		return fmt.Errorf("rtc.SubmitTx: %w", err)
	}
	runtimePlaceholderLogger.Debug("output", "out", out)
	return nil
}
