package beacon

import (
	"context"
	"sync"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
)

type txRetry struct {
	sync.Mutex

	logger *logging.Logger

	consensus consensus.Backend
	identity  *identity.Identity

	cancelFn context.CancelFunc
}

func (rtr *txRetry) newRetryCtx(ctx context.Context) context.Context {
	rtr.Lock()
	defer rtr.Unlock()

	if rtr.cancelFn != nil {
		rtr.cancelFn()
	}

	var subCtx context.Context
	subCtx, rtr.cancelFn = context.WithCancel(ctx)

	return subCtx
}

func (rtr *txRetry) Cancel() {
	rtr.Lock()
	defer rtr.Unlock()

	if rtr.cancelFn != nil {
		rtr.cancelFn()
		rtr.cancelFn = nil
	}
}

func (rtr *txRetry) SubmitTx(
	baseCtx context.Context,
	tx *transaction.Transaction,
	checkFn func(context.Context) error,
) {
	ctx := rtr.newRetryCtx(baseCtx)
	off := backoff.WithContext(cmnBackoff.NewExponentialBackOff(), ctx)

	fn := func() error {
		if err := checkFn(ctx); err != nil {
			return err
		}

		err := consensus.SignAndSubmitTx(
			ctx,
			rtr.consensus,
			rtr.identity.NodeSigner,
			tx,
		)
		if err == nil {
			rtr.logger.Debug("tx submitted",
				"method", tx.Method,
			)
		}

		return err
	}

	// Optimistically try to just submit the Tx in-line.
	if err := fn(); err != nil {
		rtr.logger.Debug("in-line tx submit failed, scheduling retries",
			"err", err,
			"method", tx.Method,
		)

		go backoff.Retry(fn, off) //nolint: errcheck
	}
}

func newTxRetry(
	logger *logging.Logger,
	consensus consensus.Backend,
	identity *identity.Identity,
) *txRetry {
	return &txRetry{
		logger:    logger,
		consensus: consensus,
		identity:  identity,
	}
}
