package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/cenkalti/backoff/v4"
	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	maxSubmissionRetryElapsedTime = 120 * time.Second
	maxSubmissionRetryInterval    = 10 * time.Second

	fundAccountAmount = 100000000
	// gasPrice should be at least the configured min gas prices of validators.
	gasPrice = 1
)

// FundAccountFromTestEntity funds an account from test entity.
func FundAccountFromTestEntity(ctx context.Context, logger *logging.Logger, cnsc consensus.ClientBackend, to signature.PublicKey) error {
	_, testEntitySigner, _ := entity.TestEntity()
	return transferFunds(ctx, logger, cnsc, testEntitySigner, to, fundAccountAmount)
}

// transferFunds transfer funds between accounts.
func transferFunds(ctx context.Context, logger *logging.Logger, cnsc consensus.ClientBackend, from signature.Signer, to signature.PublicKey, transferAmount int64) error {
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
		rtc runtimeClient.RuntimeClient,
		fundingAccount signature.Signer,
	) error
}

// ByName is the registry of workloads that you can access with `--workload <name>` on the command line.
var ByName = map[string]Workload{
	NameTransfer:     transfer{},
	NameOversized:    oversized{},
	NameRegistration: &registration{},
	NameParallel:     parallel{},
	NameDelegation:   &delegation{},
}
