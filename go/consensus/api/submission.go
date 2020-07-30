package api

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	maxSubmissionRetryElapsedTime = 60 * time.Second
	maxSubmissionRetryInterval    = 10 * time.Second
)

// PriceDiscovery is the consensus fee price discovery interface.
type PriceDiscovery interface {
	// GasPrice returns the current consensus gas price.
	GasPrice(ctx context.Context) (*quantity.Quantity, error)
}

type staticPriceDiscovery struct {
	price quantity.Quantity
}

// NewStaticPriceDiscovery creates a price discovery mechanism which always returns the same static
// price specified at construction time.
func NewStaticPriceDiscovery(price uint64) (PriceDiscovery, error) {
	pd := &staticPriceDiscovery{}
	if err := pd.price.FromUint64(price); err != nil {
		return nil, fmt.Errorf("submission: failed to convert gas price: %w", err)
	}
	return pd, nil
}

func (pd *staticPriceDiscovery) GasPrice(ctx context.Context) (*quantity.Quantity, error) {
	return pd.price.Clone(), nil
}

// SubmissionManager is a transaction submission manager interface.
type SubmissionManager interface {
	// SignAndSubmitTx populates the nonce and fee fields in the transaction, signs the transaction
	// with the passed signer and submits it to consensus backend.
	//
	// It also automatically handles retries in case the nonce was incorrectly estimated.
	SignAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error
}

type submissionManager struct {
	backend        ClientBackend
	priceDiscovery PriceDiscovery
	maxFee         quantity.Quantity

	logger *logging.Logger
}

func (m *submissionManager) signAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	// Update transaction nonce.
	var err error
	signerAddr := staking.NewAddress(signer.Public())

	tx.Nonce, err = m.backend.GetSignerNonce(ctx, &GetSignerNonceRequest{AccountAddress: signerAddr, Height: HeightLatest})
	if err != nil {
		if errors.Is(err, ErrNoCommittedBlocks) {
			// No committed blocks available, retry submission.
			m.logger.Debug("retrying transaction submission due to no committed blocks")
			return err
		}
		return backoff.Permanent(err)
	}

	// In case the fee is not specified, perform fee estimation.
	if tx.Fee == nil {
		// Estimate amount of gas needed to perform the update.
		var gas transaction.Gas
		gas, err = m.backend.EstimateGas(ctx, &EstimateGasRequest{Signer: signer.Public(), Transaction: tx})
		if err != nil {
			return fmt.Errorf("failed to estimate gas: %w", err)
		}

		// Fetch current consensus gas price and compute the fee.
		var amount *quantity.Quantity
		amount, err = m.priceDiscovery.GasPrice(ctx)
		if err != nil {
			return fmt.Errorf("failed to determine gas price: %w", err)
		}
		var gasQuantity quantity.Quantity
		if err = gasQuantity.FromUint64(uint64(gas)); err != nil {
			return fmt.Errorf("failed to compute fee amount: %w", err)
		}
		if err = amount.Mul(&gasQuantity); err != nil {
			return fmt.Errorf("failed to compute fee amount: %w", err)
		}

		// Verify that the fee doesn't exceed a configured ceiling.
		if !m.maxFee.IsZero() && amount.Cmp(&m.maxFee) == 1 {
			return fmt.Errorf("computed fee exceeds configured maximum: %s (max: %s)",
				amount,
				m.maxFee,
			)
		}

		tx.Fee = &transaction.Fee{
			Gas:    gas,
			Amount: *amount,
		}
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
				"account_address", signerAddr,
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
func NewSubmissionManager(backend ClientBackend, priceDiscovery PriceDiscovery, maxFee uint64) SubmissionManager {
	sm := &submissionManager{
		backend:        backend,
		priceDiscovery: priceDiscovery,
		logger:         logging.GetLogger("consensus/submission"),
	}
	_ = sm.maxFee.FromUint64(maxFee)

	return sm
}

// SignAndSubmitTx is a helper function that signs and submits a transaction to
// the consensus backend.
//
// If the nonce is set to zero, it will be automatically filled in based on the
// current consensus state.
//
// If the fee is set to nil, it will be automatically filled in based on gas
// estimation and current gas price discovery.
func SignAndSubmitTx(ctx context.Context, backend Backend, signer signature.Signer, tx *transaction.Transaction) error {
	return backend.SubmissionManager().SignAndSubmitTx(ctx, signer, tx)
}
