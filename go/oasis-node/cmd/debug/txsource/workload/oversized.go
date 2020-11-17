package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// NameOversized is the name of the oversized workload.
const NameOversized = "oversized"

// Oversized is the oversized workload.
var Oversized = &oversized{
	BaseWorkload: NewBaseWorkload(NameOversized),
}

const (
	oversizedTxGasAmount = 10000
)

type oversized struct {
	BaseWorkload
}

// Implements Workload.
func (*oversized) NeedsFunds() bool {
	return true
}

// Implements Workload.
func (o *oversized) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
) error {
	// Initialize base workload.
	o.BaseWorkload.Init(cnsc, sm, fundingAccount)

	txSignerFactory := memorySigner.NewFactory()
	txSigner, err := txSignerFactory.Generate(signature.SignerEntity, rng)
	if err != nil {
		return fmt.Errorf("failed to generate signer key: %w", err)
	}
	txSignerAddr := staking.NewAddress(txSigner.Public())

	ctx := context.Background()

	// Fetch genesis consensus parameters.
	// TODO: Don't dump everything, instead add a method to query just the parameters.
	genesisDoc, err := cnsc.StateToGenesis(ctx, 1)
	if err != nil {
		return fmt.Errorf("failed to query state at genesis: %w", err)
	}
	params := genesisDoc.Consensus.Parameters

	gasPrice, err := sm.PriceDiscovery().GasPrice(ctx)
	if err != nil {
		return fmt.Errorf("failed to get gas price: %w", err)
	}

	var nonce uint64
	fee := transaction.Fee{
		Gas: oversizedTxGasAmount + transaction.Gas(params.MaxTxSize)*params.GasCosts[consensusGenesis.GasOpTxByte],
	}
	_ = fee.Amount.FromInt64(oversizedTxGasAmount)
	_ = fee.Amount.Mul(gasPrice)

	for {
		// Generate a big transfer transaction which is valid, but oversized.
		type customTransfer struct {
			To   staking.Address `json:"to"`
			Data []byte          `json:"data"`
		}
		xfer := customTransfer{
			// Send zero stake to self, so the transaction will be valid.
			To: txSignerAddr,
			// Include some extra random data so we are over the MaxTxSize limit.
			Data: make([]byte, genesisDoc.Consensus.Parameters.MaxTxSize),
		}
		if _, err = rng.Read(xfer.Data); err != nil {
			return fmt.Errorf("failed to generate bogus transaction: %w", err)
		}

		if err = o.TransferFundsQty(
			ctx,
			fundingAccount,
			txSignerAddr,
			&fee.Amount,
		); err != nil {
			return fmt.Errorf("workload/oversized: account funding failure: %w", err)
		}

		tx := transaction.NewTransaction(nonce, &fee, staking.MethodTransfer, &xfer)
		signedTx, err := transaction.Sign(txSigner, tx)
		if err != nil {
			return fmt.Errorf("transaction.Sign: %w", err)
		}
		o.Logger.Debug("submitting oversized transaction",
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
			o.Logger.Info("transaction rejected due to ErrOversizedTx")
		default:
			// Timeout is expected if the client node skips CheckTx checks.
			o.Logger.Warn("failed to submit oversized transaction",
				"err", err,
			)
		}
		cancel()

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			o.Logger.Debug("time's up")
			return nil
		}
	}
}
