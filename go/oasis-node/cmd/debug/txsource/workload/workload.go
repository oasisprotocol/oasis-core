package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff/v4"
	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	maxSubmissionRetryElapsedTime = 120 * time.Second
	maxSubmissionRetryInterval    = 10 * time.Second

	fundAccountAmount = 10000000000
	// gasPrice should be at least the configured min gas prices of validators.
	gasPrice = 1
)

// FundAccountFromTestEntity funds an account from test entity.
func FundAccountFromTestEntity(
	ctx context.Context,
	logger *logging.Logger,
	cnsc consensus.ClientBackend,
	to signature.Signer,
) error {
	_, testEntitySigner, _ := entity.TestEntity()
	toAddr := staking.NewAddress(to.Public())
	return transferFunds(ctx, logger, cnsc, testEntitySigner, toAddr, fundAccountAmount)
}

func fundSignAndSubmitTx(
	ctx context.Context,
	logger *logging.Logger,
	cnsc consensus.ClientBackend,
	caller signature.Signer,
	tx *transaction.Transaction,
	fundingAccount signature.Signer,
) error {
	// Estimate gas needed if not set.
	if tx.Fee.Gas == 0 {
		gas, err := cnsc.EstimateGas(ctx, &consensus.EstimateGasRequest{
			Caller:      caller.Public(),
			Transaction: tx,
		})
		if err != nil {
			return fmt.Errorf("failed to estimate gas: %w", err)
		}
		tx.Fee.Gas = gas
	}

	// Fund caller to cover transaction fees.
	feeAmount := int64(tx.Fee.Gas) * gasPrice
	if err := tx.Fee.Amount.FromInt64(feeAmount); err != nil {
		return fmt.Errorf("fee amount from int64: %w", err)
	}
	callerAddr := staking.NewAddress(caller.Public())
	if err := transferFunds(ctx, logger, cnsc, fundingAccount, callerAddr, feeAmount); err != nil {
		return fmt.Errorf("account funding failure: %w", err)
	}

	// Sign tx.
	signedTx, err := transaction.Sign(caller, tx)
	if err != nil {
		return fmt.Errorf("transaction.Sign: %w", err)
	}

	logger.Debug("submitting transaction",
		"tx", tx,
		"signed_tx", signedTx,
		"tx_caller", caller.Public(),
	)

	// SubmitTx.
	// Wait for a maximum of 60 seconds to submit transaction.
	submitCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	err = cnsc.SubmitTx(submitCtx, signedTx)
	switch err {
	case nil:
		cancel()
		return nil
	default:
		cancel()
		logger.Error("failed to submit transaction",
			"err", err,
			"tx", tx,
			"signed_tx", signedTx,
			"tx_caller", caller.Public(),
		)
		return fmt.Errorf("cnsc.SubmitTx: %w", err)
	}
}

// transferFunds transfer funds between accounts.
func transferFunds(
	ctx context.Context,
	logger *logging.Logger,
	cnsc consensus.ClientBackend,
	from signature.Signer,
	to staking.Address,
	transferAmount int64,
) error {
	sched := backoff.NewExponentialBackOff()
	sched.MaxInterval = maxSubmissionRetryInterval
	sched.MaxElapsedTime = maxSubmissionRetryElapsedTime
	// Since multiple workloads run simultaneously (in separate processes)
	// there is a nonce race condition, in case of invalid nonce errors
	// submission should be retried. (similarly as it is done in the
	// SubmissionManager).
	// Maybe just expose the SignAndSubmit() method in the
	// consensus.ClientBackend?
	return backoff.Retry(func() error {
		// Get test entity nonce.
		nonce, err := cnsc.GetSignerNonce(ctx, &consensus.GetSignerNonceRequest{
			ID:     from.Public(),
			Height: consensus.HeightLatest,
		})
		if err != nil {
			return backoff.Permanent(fmt.Errorf("GetSignerNonce TestEntity error: %w", err))
		}

		transfer := staking.Transfer{
			To: to,
		}
		if err = transfer.Tokens.FromInt64(transferAmount); err != nil {
			return backoff.Permanent(fmt.Errorf("transfer tokens FromInt64 %d: %w", transferAmount, err))
		}
		logger.Debug("transfering funds", "from", from.Public(), "to", to, "amount", transferAmount, "nonce", nonce)

		var fee transaction.Fee
		tx := staking.NewTransferTx(nonce, &fee, &transfer)
		// Estimate fee.
		gas, err := cnsc.EstimateGas(ctx, &consensus.EstimateGasRequest{
			Caller:      from.Public(),
			Transaction: tx,
		})
		if err != nil {
			return fmt.Errorf("failed to estimate gas: %w", err)
		}
		tx.Fee.Gas = gas
		feeAmount := int64(gas) * gasPrice
		if err = tx.Fee.Amount.FromInt64(feeAmount); err != nil {
			return fmt.Errorf("fee amount from int64: %w", err)
		}

		signedTx, err := transaction.Sign(from, tx)
		if err != nil {
			return backoff.Permanent(fmt.Errorf("transaction.Sign: %w", err))
		}

		// Wait for a maximum of 5 seconds as submission may block forever in case the client node
		// is skipping all CheckTx checks.
		submitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err = cnsc.SubmitTx(submitCtx, signedTx); err != nil {
			// Expected errors are:
			// - invalid nonce
			// - timeout due to transaction being stuck due to invalid nonce (as client is skipping check-tx)
			// In any case no it doesn't hurt to retry on all submission errors.
			logger.Debug("SubmitTX error, retrying...",
				"err", err,
				"from", from.Public(),
				"to", to,
				"nonce", tx.Nonce,
			)
			return err
		}
		return nil
	}, backoff.WithContext(sched, ctx))
}

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
		fundingAccount signature.Signer,
	) error
}

// ByName is the registry of workloads that you can access with `--workload <name>` on the command line.
var ByName = map[string]Workload{
	NameCommission:   &commission{},
	NameDelegation:   &delegation{},
	NameOversized:    oversized{},
	NameParallel:     parallel{},
	NameQueries:      &queries{},
	NameRegistration: &registration{},
	NameRuntime:      &runtime{},
	NameTransfer:     &transfer{},
}

// Flags has the workload flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

func init() {
	Flags.AddFlagSet(QueriesFlags)
	Flags.AddFlagSet(RuntimeFlags)
}
