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
	NameParallel = "parallel"

	parallelSendWaitTimeoutInterval = 30 * time.Second
	parallelSendTimeoutInterval     = 60 * time.Second
	parallelConcurency              = 200
	parallelTxGasAmount             = 10
)

var parallelLogger = logging.GetLogger("cmd/txsource/workload/parallel")

type parallel struct{}

func (parallel) Run(gracefulExit context.Context, rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, rtc runtimeClient.RuntimeClient) error {
	ctx := context.Background()

	accounts := make([]signature.Signer, parallelConcurency)
	var err error
	fac := memorySigner.NewFactory()
	for i := range accounts {
		// NOTE: no balances are needed for now
		accounts[i], err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
	}

	// A single global nonce is enough as we wait for all submissions to
	// complete before proceeding with a new batch.
	var nonce uint64
	fee := transaction.Fee{
		Gas: parallelTxGasAmount,
	}

	for {
		errCh := make(chan error, parallelConcurency)
		var wg sync.WaitGroup
		wg.Add(parallelConcurency)

		for i := 0; i < parallelConcurency; i++ {
			go func(txSigner signature.Signer, nonce uint64) {
				defer wg.Done()

				// Transfer tx.
				transfer := staking.Transfer{
					To: txSigner.Public(),
				}
				tx := staking.NewTransferTx(nonce, &fee, &transfer)

				signedTx, err := transaction.Sign(txSigner, tx)
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

			}(accounts[i], nonce)
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

		case err := <-errCh:
			parallelLogger.Error("error subimit transaction",
				"err", err,
			)
			return fmt.Errorf("workload parallel: error submiting transaction: %w", err)

		case <-waitC:
			parallelLogger.Debug("all transfers successful",
				"concurency", parallelConcurency,
			)
		}

		select {
		case <-time.After(parallelSendTimeoutInterval):
		case <-gracefulExit.Done():
			parallelLogger.Debug("time's up")
			return nil
		}
	}
}
