package workload

import (
	"context"
	"fmt"
	"math/rand"
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
	NameOversized = "oversized"

	oversizedTxGasAmount = 10000
)

var oversizedLogger = logging.GetLogger("cmd/txsource/workload/oversized")

type oversized struct{}

func (oversized) Run(gracefulExit context.Context, rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, rtc runtimeClient.RuntimeClient) error {
	txSignerFactory := memorySigner.NewFactory()
	txSigner, err := txSignerFactory.Generate(signature.SignerEntity, rng)
	if err != nil {
		return fmt.Errorf("failed to generate signer key: %w", err)
	}

	ctx := context.Background()

	// Fetch genesis consensus parameters.
	// TODO: Don't dump everything, instead add a method to query just the parameters.
	genesisDoc, err := cnsc.StateToGenesis(ctx, 1)
	if err != nil {
		return fmt.Errorf("failed to query state at genesis: %w", err)
	}

	var nonce uint64
	fee := transaction.Fee{
		Gas: oversizedTxGasAmount,
	}
	for {
		// Generate a big transfer transaction which is valid, but oversized.
		type customTransfer struct {
			To   signature.PublicKey `json:"xfer_to"`
			Data []byte              `json:"xfer_data"`
		}
		xfer := customTransfer{
			// Send zero tokens to self, so the transaction will be valid.
			To: txSigner.Public(),
			// Include some extra random data so we are over the MaxTxSize limit.
			Data: make([]byte, genesisDoc.Consensus.Parameters.MaxTxSize),
		}
		if _, err = rng.Read(xfer.Data); err != nil {
			return fmt.Errorf("failed to generate bogus transaction: %w", err)
		}

		tx := transaction.NewTransaction(nonce, &fee, staking.MethodTransfer, &xfer)
		signedTx, err := transaction.Sign(txSigner, tx)
		if err != nil {
			return fmt.Errorf("transaction.Sign: %w", err)
		}
		oversizedLogger.Debug("submitting oversized transaction",
			"payload_size", len(xfer.Data),
		)

		// Wait for a maximum of 5 seconds as submission may block forever in case the client node
		// is skipping all CheckTx checks.
		submitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = cnsc.SubmitTx(submitCtx, signedTx)
		switch err {
		case nil:
			// This should never happen.
			cancel()
			return fmt.Errorf("successfully submitted an oversized transaction")
		case consensus.ErrOversizedTx:
			// Submitting an oversized transaction is an error, so we expect this to fail.
			oversizedLogger.Info("transaction rejected due to ErrOversizedTx")
		default:
			// Timeout is expected if the client node skips CheckTx checks.
			oversizedLogger.Warn("failed to submit oversized transaction",
				"err", err,
			)
		}
		cancel()

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			oversizedLogger.Debug("time's up")
			return nil
		}
	}
}
