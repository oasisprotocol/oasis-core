package txnscheduler

import (
	"context"

	"github.com/oasislabs/oasis-core/go/worker/txnscheduler/api"
)

var _ api.TransactionScheduler = (*Worker)(nil)

// SubmitTx submits a new transaction to the transaction scheduler.
func (w *Worker) SubmitTx(ctx context.Context, rq *api.SubmitTxRequest) (*api.SubmitTxResponse, error) {
	runtime, ok := w.runtimes[rq.RuntimeID]
	if !ok {
		return nil, api.ErrUnknownRuntime
	}

	if err := runtime.QueueCall(ctx, rq.Data); err != nil {
		return nil, err
	}
	return &api.SubmitTxResponse{}, nil
}

// IsTransactionQueued checks if the given transaction is present in the
// transaction scheduler queue and is waiting to be dispatched to a
// compute committee.
func (w *Worker) IsTransactionQueued(ctx context.Context, rq *api.IsTransactionQueuedRequest) (*api.IsTransactionQueuedResponse, error) {
	runtime, ok := w.runtimes[rq.RuntimeID]
	if !ok {
		return nil, api.ErrUnknownRuntime
	}

	isQueued, err := runtime.IsTransactionQueued(ctx, rq.TxHash)
	if err != nil {
		return nil, err
	}

	return &api.IsTransactionQueuedResponse{
		IsQueued: isQueued,
	}, nil
}
