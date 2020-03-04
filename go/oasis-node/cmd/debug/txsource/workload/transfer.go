package workload

import (
	"context"
	"fmt"
	"math/rand"

	"google.golang.org/grpc"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	runtimeClient "github.com/oasislabs/oasis-core/go/runtime/client/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

const (
	// NameTransfer is the name of the transfer workload.
	NameTransfer = "transfer"

	transferNumAccounts  = 10
	transferAmount       = 1
	transferFundInterval = 10
	transferGasCost      = 10
)

var transferLogger = logging.GetLogger("cmd/txsource/workload/transfer")

type transfer struct{}

func (transfer) Run(gracefulExit context.Context, rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, rtc runtimeClient.RuntimeClient, fundingAccount signature.Signer) error {
	var err error
	ctx := context.Background()

	fac := memorySigner.NewFactory()
	// Load all the keys up front. Like, how annoyed would you be if down the line one of them turned out to be
	// corrupted or something, ya know?
	accounts := make([]struct {
		signer          signature.Signer
		reckonedNonce   uint64
		reckonedBalance quantity.Quantity
	}, transferNumAccounts)
	for i := range accounts {
		accounts[i].signer, err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
	}

	// Read all the account info up front.
	stakingClient := staking.NewStakingClient(conn)
	for i := range accounts {
		fundAmount := transferAmount*transferFundInterval + // funds for `transferFundInterval` transfers
			transferGasCost*gasPrice*transferFundInterval // gas costs for `transferFundInterval` transfers
		if err = transferFunds(ctx, transferLogger, cnsc, fundingAccount, accounts[i].signer.Public(), int64(fundAmount)); err != nil {
			return fmt.Errorf("workload/transfer: account funding failure: %w", err)
		}
		var account *staking.Account
		account, err = stakingClient.AccountInfo(ctx, &staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  accounts[i].signer.Public(),
		})
		if err != nil {
			return fmt.Errorf("stakingClient.AccountInfo %s: %w", accounts[i].signer.Public(), err)
		}
		transferLogger.Debug("account info",
			"i", i,
			"pub", accounts[i].signer.Public(),
			"info", account,
		)
		accounts[i].reckonedNonce = account.General.Nonce
		accounts[i].reckonedBalance = account.General.Balance
	}

	fee := transaction.Fee{
		Gas: transferGasCost,
	}
	if err = fee.Amount.FromInt64(transferGasCost * gasPrice); err != nil {
		return fmt.Errorf("Fee amount error: %w", err)
	}

	var minBalance quantity.Quantity
	if err = minBalance.FromInt64(transferAmount); err != nil {
		return fmt.Errorf("min balance FromInt64 %d: %w", transferAmount, err)
	}
	if err = minBalance.Add(&fee.Amount); err != nil {
		return fmt.Errorf("min balance %v Add fee amount %v: %w", minBalance, fee.Amount, err)
	}
	for {
		perm := rng.Perm(transferNumAccounts)
		fromPermIdx := 0
		for ; fromPermIdx < transferNumAccounts; fromPermIdx++ {
			if accounts[perm[fromPermIdx]].reckonedBalance.Cmp(&minBalance) >= 0 {
				break
			}
		}
		if fromPermIdx >= transferNumAccounts {
			return fmt.Errorf("all accounts %#v have gone broke", accounts)
		}
		toPermIdx := (fromPermIdx + 1) % transferNumAccounts
		from := &accounts[perm[fromPermIdx]]
		to := &accounts[perm[toPermIdx]]

		transfer := staking.Transfer{
			To: to.signer.Public(),
		}
		if err = transfer.Tokens.FromInt64(transferAmount); err != nil {
			return fmt.Errorf("transfer tokens FromInt64 %d: %w", transferAmount, err)
		}
		tx := staking.NewTransferTx(from.reckonedNonce, &fee, &transfer)
		signedTx, err := transaction.Sign(from.signer, tx)
		if err != nil {
			return fmt.Errorf("transaction.Sign: %w", err)
		}
		transferLogger.Debug("submitting transfer",
			"from", from.signer.Public(),
			"to", to.signer.Public(),
		)
		if err = cnsc.SubmitTx(ctx, signedTx); err != nil {
			return fmt.Errorf("cnsc.SubmitTx: %w", err)
		}
		from.reckonedNonce++
		if err = from.reckonedBalance.Sub(&fee.Amount); err != nil {
			return fmt.Errorf("from reckoned balance %v Sub fee amount %v: %w", from.reckonedBalance, fee.Amount, err)
		}
		if err = from.reckonedBalance.Sub(&transfer.Tokens); err != nil {
			return fmt.Errorf("from reckoned balance %v Sub transfer tokens %v: %w", from.reckonedBalance, transfer.Tokens, err)
		}
		if err = to.reckonedBalance.Add(&transfer.Tokens); err != nil {
			return fmt.Errorf("to reckoned balance %v Add transfer tokens %v: %w", to.reckonedBalance, transfer.Tokens, err)
		}

		if from.reckonedNonce%transferFundInterval == 0 {
			// Re-fund account for next `transferFundInterval` transfers.
			fundAmount := transferGasCost * gasPrice * transferFundInterval // gas costs for `transferFundInterval` transfers.
			if err = transferFunds(ctx, parallelLogger, cnsc, fundingAccount, from.signer.Public(), int64(fundAmount)); err != nil {
				return fmt.Errorf("account funding failure: %w", err)
			}
			var fundAmountQ quantity.Quantity
			if err = fundAmountQ.FromInt64(int64(fundAmount)); err != nil {
				return fmt.Errorf("fundAmountQ FromInt64(%d): %w", fundAmount, err)
			}
			if err = from.reckonedBalance.Add(&fundAmountQ); err != nil {
				return fmt.Errorf("to reckoned balance %v Add fund amount %v: %w", to.reckonedBalance, fundAmountQ, err)
			}
		}

		select {
		case <-gracefulExit.Done():
			transferLogger.Debug("time's up")
			return nil
		default:
		}
	}
}
