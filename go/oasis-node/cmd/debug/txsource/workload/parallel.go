package workload

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/logging"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	// NameParallel is the name of the parallel workload.
	NameParallel = "parallel"

	parallelSendWaitTimeoutInterval = 30 * time.Second
	parallelSendTimeoutInterval     = 60 * time.Second
	parallelConcurency              = 200
	parallelTxGasAmount             = 10
	parallelTxTransferAmount        = 100
	parallelTxFundInterval          = 10
)

var parallelLogger = logging.GetLogger("cmd/txsource/workload/parallel")

type parallel struct{}

func (parallel) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	rtc runtimeClient.RuntimeClient,
	fundingAccount signature.Signer,
) error {
	ctx := context.Background()
	var err error

	accounts := make([]signature.Signer, parallelConcurency)
	fac := memorySigner.NewFactory()
	for i := range accounts {
		accounts[i], err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}

		// Initial funding of accounts.
		fundAmount := parallelTxTransferAmount + // self transfer amount
			parallelTxFundInterval*parallelTxGasAmount*gasPrice // gas for `parallelTxFundInterval` transfers.
		if err = transferFunds(ctx, parallelLogger, cnsc, fundingAccount, accounts[i].Public(), int64(fundAmount)); err != nil {
			return fmt.Errorf("account funding failure: %w", err)
		}
	}

	// A single global nonce is enough as we wait for all submissions to
	// complete before proceeding with a new batch.
	var nonce uint64
	fee := transaction.Fee{
		Gas: parallelTxGasAmount,
	}
	if err = fee.Amount.FromInt64(parallelTxGasAmount); err != nil {
		return fmt.Errorf("Fee amount error: %w", err)
	}

	for i := uint64(1); ; i++ {

		errCh := make(chan error, parallelConcurency)
		var wg sync.WaitGroup
		wg.Add(parallelConcurency)
		for c := 0; c < parallelConcurency; c++ {
			go func(txSigner signature.Signer, nonce uint64) {
				defer wg.Done()

				// Transfer tx.
				transfer := staking.Transfer{
					To: txSigner.Public(),
				}
				if err = transfer.Tokens.FromInt64(parallelTxTransferAmount); err != nil {
					errCh <- fmt.Errorf("transfer tokens FromInt64 %d: %w", parallelTxTransferAmount, err)
					return
				}

				tx := staking.NewTransferTx(nonce, &fee, &transfer)
				var signedTx *transaction.SignedTransaction
				signedTx, err = transaction.Sign(txSigner, tx)
				if err != nil {
					parallelLogger.Error("transaction.Sign error", "err", err)
					errCh <- fmt.Errorf("transaction.Sign: %w", err)
					return
				}

				parallelLogger.Debug("submitting self transfer",
					"account", txSigner.Public(),
				)
				if err = cnsc.SubmitTx(ctx, signedTx); err != nil {
					parallelLogger.Error("SubmitTx error", "err", err)
					errCh <- fmt.Errorf("cnsc.SubmitTx: %w", err)
					return
				}

			}(accounts[c], nonce)
		}

		// Wait for transactions.
		waitC := make(chan struct{})
		go func() {
			defer close(waitC)
			wg.Wait()
			nonce++
		}()

		select {
		case <-time.After(parallelSendWaitTimeoutInterval):
			parallelLogger.Error("transactions not completed within timeout")
			return fmt.Errorf("workload parallel: transactions not completed within timeout")

		case err = <-errCh:
			parallelLogger.Error("error subimit transaction",
				"err", err,
			)
			return fmt.Errorf("workload parallel: error submiting transaction: %w", err)

		case <-waitC:
			parallelLogger.Debug("all transfers successful",
				"concurency", parallelConcurency,
			)
		}

		if i%parallelTxFundInterval == 0 {
			// Re-fund accounts for next `parallelTxFundInterval` transfers.
			for i := range accounts {
				fundAmount := parallelTxFundInterval * parallelTxGasAmount * gasPrice // gas for `parallelTxFundInterval` transfers.
				if err = transferFunds(ctx, parallelLogger, cnsc, fundingAccount, accounts[i].Public(), int64(fundAmount)); err != nil {
					return fmt.Errorf("account funding failure: %w", err)
				}
			}
		}

		select {
		case <-time.After(parallelSendTimeoutInterval):
		case <-gracefulExit.Done():
			parallelLogger.Debug("time's up")
			return nil
		}
	}
}
