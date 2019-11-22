package api

import (
	"context"
	"time"

	"github.com/cenkalti/backoff"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/errors"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
)

const (
	maxSubmissionRetryElapsedTime = 60 * time.Second
	maxSubmissionRetryInterval    = 10 * time.Second
)

// SubmissionManager is a transaction submission manager interface.
type SubmissionManager interface {
	// SignAndSubmitTx populates the nonce of the transaction, signs it
	// with the passed signer and submits it to consensus backend.
	SignAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error
}

type submissionManager struct {
	backend Backend

	logger *logging.Logger
}

func (m *submissionManager) signAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	// Update transaction nonce.
	var err error
	tx.Nonce, err = m.backend.TransactionAuthHandler().GetSignerNonce(ctx, signer.Public(), 0)
	if err != nil {
		if errors.Is(err, ErrNoCommittedBlocks) {
			// No committed blocks available, retry submission.
			m.logger.Debug("retrying transaction submission due to no committed blocks")
			return err
		}
		return backoff.Permanent(err)
	}

	// Sign the transaction.
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		m.logger.Error("failed to sign transaction",
			"err", err,
		)
		return backoff.Permanent(err)
	}

	if err = m.backend.SubmitTx(ctx, sigTx); err != nil {
		if errors.Is(err, transaction.ErrInvalidNonce) {
			// Invalid nonce, retry submission.
			m.logger.Debug("retrying transaction submission due to invalid nonce",
				"account_id", signer.Public(),
				"nonce", tx.Nonce,
			)
			return err
		}
		return backoff.Permanent(err)
	}

	return nil
}

func (m *submissionManager) SignAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	sched := backoff.NewExponentialBackOff()
	sched.MaxInterval = maxSubmissionRetryInterval
	sched.MaxElapsedTime = maxSubmissionRetryElapsedTime

	return backoff.Retry(func() error {
		return m.signAndSubmitTx(ctx, signer, tx)
	}, backoff.WithContext(sched, ctx))
}

// NewSubmissionManager creates a new transaction submission manager.
func NewSubmissionManager(backend Backend) SubmissionManager {
	return &submissionManager{
		backend: backend,
		logger:  logging.GetLogger("consensus/submission"),
	}
}

// SignAndSubmitTx is a helper method that signs and submits a transaction to
// the consensus backend.
//
// If a nonce is set to zero, the transaction will be submitted by using the
// submission manager which will automatically use the correct nonce.
func SignAndSubmitTx(ctx context.Context, backend Backend, signer signature.Signer, tx *transaction.Transaction) error {
	if tx.Nonce == 0 {
		return backend.SubmissionManager().SignAndSubmitTx(ctx, signer, tx)
	}

	// Sign the transaction.
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		return err
	}
	return backend.SubmitTx(ctx, sigTx)
}
