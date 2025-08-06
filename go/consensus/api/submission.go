package api

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"

	cmnBackoff "github.com/oasisprotocol/oasis-core/go/common/backoff"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	maxSubmissionRetryElapsedTime = time.Minute
	maxSubmissionRetryInterval    = 10 * time.Second
)

// PriceDiscovery is the consensus fee price discovery interface.
type PriceDiscovery interface {
	// GasPrice returns the current consensus gas price.
	GasPrice() (*quantity.Quantity, error)
}

// SubmissionManager is a transaction submission manager interface.
type SubmissionManager interface {
	// PriceDiscovery returns the configured price discovery mechanism instance.
	PriceDiscovery() PriceDiscovery

	// EstimateGasAndSetFee populates the fee field in the transaction if not already set.
	EstimateGasAndSetFee(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error

	// SignAndSubmitTx populates the nonce and fee fields in the transaction, signs the transaction
	// with the passed signer and submits it to consensus backend.
	//
	// It also automatically handles retries in case the nonce was incorrectly estimated.
	SignAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error

	// SignAndSubmitTxWithProof populates the nonce and fee fields in the transaction, signs
	// the transaction with the passed signer, submits it to consensus backend and creates
	// a proof of inclusion.
	//
	// It also automatically handles retries in case the nonce was incorrectly estimated.
	SignAndSubmitTxWithProof(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) (*transaction.SignedTransaction, *transaction.Proof, error)
}

type submissionManager struct {
	consensus      Services
	priceDiscovery PriceDiscovery
	maxFee         quantity.Quantity

	noncesLock sync.Mutex
	nonces     map[staking.Address]uint64

	logger *logging.Logger
}

// Implements SubmissionManager.
func (m *submissionManager) PriceDiscovery() PriceDiscovery {
	return m.priceDiscovery
}

// Implements SubmissionManager.
func (m *submissionManager) EstimateGasAndSetFee(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	if tx.Fee != nil {
		return nil
	}

	// Estimate amount of gas needed to perform the update.
	var (
		gas transaction.Gas
		err error
	)
	gas, err = m.consensus.Core().EstimateGas(ctx, &EstimateGasRequest{Signer: signer.Public(), Transaction: tx})
	if err != nil {
		return fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Fetch current consensus gas price and compute the fee.
	var amount *quantity.Quantity
	amount, err = m.priceDiscovery.GasPrice()
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
	return nil
}

func (m *submissionManager) getSignerNonce(ctx context.Context, signerAddr staking.Address) (uint64, error) {
	m.noncesLock.Lock()
	defer m.noncesLock.Unlock()

	nonce, ok := m.nonces[signerAddr]
	if !ok {
		// Query latest nonce when one is not available.
		account, err := m.consensus.Staking().Account(ctx, &staking.OwnerQuery{
			Height: HeightLatest,
			Owner:  signerAddr,
		})
		if err != nil {
			return 0, err
		}
		nonce = account.General.Nonce
	}

	m.nonces[signerAddr] = nonce + 1

	return nonce, nil
}

func (m *submissionManager) clearSignerNonce(signerAddr staking.Address) {
	m.noncesLock.Lock()
	defer m.noncesLock.Unlock()

	delete(m.nonces, signerAddr)
}

func (m *submissionManager) signAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction, withProof bool) (*transaction.SignedTransaction, *transaction.Proof, error) {
	// Update transaction nonce.
	var err error
	signerAddr := staking.NewAddress(signer.Public())

	tx.Nonce, err = m.getSignerNonce(ctx, signerAddr)
	if err != nil {
		if errors.Is(err, ErrNoCommittedBlocks) {
			// No committed blocks available, retry submission.
			m.logger.Debug("retrying transaction submission due to no committed blocks")
			return nil, nil, err
		}
		return nil, nil, backoff.Permanent(err)
	}

	// Estimate the fee.
	if err = m.EstimateGasAndSetFee(ctx, signer, tx); err != nil {
		return nil, nil, fmt.Errorf("failed to estimate fee: %w", err)
	}

	// Sign the transaction.
	sigTx, err := transaction.Sign(signer, tx)
	if err != nil {
		m.logger.Error("failed to sign transaction",
			"err", err,
		)
		return nil, nil, backoff.Permanent(err)
	}

	var proof *transaction.Proof
	if withProof {
		proof, err = m.consensus.Core().SubmitTxWithProof(ctx, sigTx)
	} else {
		err = m.consensus.Core().SubmitTx(ctx, sigTx)
	}
	if err != nil {
		// If the transaction check fails (which cannot be determined from
		// the error), the nonce in the cache should be either decremented
		// or cleared to ensure consistency.
		m.clearSignerNonce(signerAddr)

		switch {
		case errors.Is(err, transaction.ErrUpgradePending):
			// Pending upgrade, retry submission.
			m.logger.Debug("retrying transaction submission due to pending upgrade")
			return nil, nil, err
		case errors.Is(err, transaction.ErrInvalidNonce):
			// Invalid nonce, retry submission.
			m.logger.Debug("retrying transaction submission due to invalid nonce",
				"account_address", signerAddr,
				"nonce", tx.Nonce,
			)
			return nil, nil, err
		default:
			return nil, nil, backoff.Permanent(err)
		}
	}

	return sigTx, proof, nil
}

func (m *submissionManager) signAndSubmitTxWithRetry(ctx context.Context, signer signature.Signer, tx *transaction.Transaction, withProof bool) (*transaction.SignedTransaction, *transaction.Proof, error) {
	sched := cmnBackoff.NewExponentialBackOff()
	sched.MaxInterval = maxSubmissionRetryInterval
	sched.MaxElapsedTime = maxSubmissionRetryElapsedTime

	var (
		sigTx *transaction.SignedTransaction
		proof *transaction.Proof
	)

	f := func() error {
		var err error
		sigTx, proof, err = m.signAndSubmitTx(ctx, signer, tx, withProof)
		return err
	}

	if err := backoff.Retry(f, backoff.WithContext(sched, ctx)); err != nil {
		return nil, nil, err
	}

	return sigTx, proof, nil
}

// Implements SubmissionManager.
func (m *submissionManager) SignAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	_, _, err := m.signAndSubmitTxWithRetry(ctx, signer, tx, false)
	return err
}

// Implements SubmissionManager.
func (m *submissionManager) SignAndSubmitTxWithProof(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) (*transaction.SignedTransaction, *transaction.Proof, error) {
	return m.signAndSubmitTxWithRetry(ctx, signer, tx, true)
}

// NewSubmissionManager creates a new transaction submission manager.
func NewSubmissionManager(consensus Services, priceDiscovery PriceDiscovery, maxFee uint64) SubmissionManager {
	sm := &submissionManager{
		consensus:      consensus,
		priceDiscovery: priceDiscovery,
		nonces:         make(map[staking.Address]uint64),
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
func SignAndSubmitTx(ctx context.Context, consensus Service, signer signature.Signer, tx *transaction.Transaction) error {
	return consensus.SubmissionManager().SignAndSubmitTx(ctx, signer, tx)
}

// SignAndSubmitTxWithProof is a helper function that signs and submits
// a transaction to the consensus backend and creates a proof of inclusion.
//
// If the nonce is set to zero, it will be automatically filled in based on the
// current consensus state.
//
// If the fee is set to nil, it will be automatically filled in based on gas
// estimation and current gas price discovery.
func SignAndSubmitTxWithProof(ctx context.Context, consensus Service, signer signature.Signer, tx *transaction.Transaction) (*transaction.SignedTransaction, *transaction.Proof, error) {
	return consensus.SubmissionManager().SignAndSubmitTxWithProof(ctx, signer, tx)
}

type noOpPriceDiscovery struct{}

func (pd *noOpPriceDiscovery) GasPrice() (*quantity.Quantity, error) {
	return nil, transaction.ErrMethodNotSupported
}

// NoOpSubmissionManager implements a submission manager that doesn't support submitting transactions.
type NoOpSubmissionManager struct{}

// PriceDiscovery implements SubmissionManager.
func (m *NoOpSubmissionManager) PriceDiscovery() PriceDiscovery {
	return &noOpPriceDiscovery{}
}

// EstimateGasAndSetFee implements SubmissionManager.
func (m *NoOpSubmissionManager) EstimateGasAndSetFee(context.Context, signature.Signer, *transaction.Transaction) error {
	return transaction.ErrMethodNotSupported
}

// SignAndSubmitTx implements SubmissionManager.
func (m *NoOpSubmissionManager) SignAndSubmitTx(context.Context, signature.Signer, *transaction.Transaction) error {
	return transaction.ErrMethodNotSupported
}

// SignAndSubmitTxWithProof implements SubmissionManager.
func (m *NoOpSubmissionManager) SignAndSubmitTxWithProof(context.Context, signature.Signer, *transaction.Transaction) (*transaction.SignedTransaction, *transaction.Proof, error) {
	return nil, nil, transaction.ErrMethodNotSupported
}
