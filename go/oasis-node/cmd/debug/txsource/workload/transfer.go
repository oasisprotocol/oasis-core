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
	NameTransfer        = "transfer"
	TransferNumAccounts = 10
	TransferAmount      = 1
)

var logger = logging.GetLogger("cmd/txsource/workload/transfer")

type transfer struct{}

func (transfer) Run(rng *rand.Rand, conn *grpc.ClientConn, cnsc consensus.ClientBackend, _ runtimeClient.RuntimeClient) error {
	// Load all the keys up front. Like, how annoyed would you be if down the line one of them turned out to be
	// corrupted or something, ya know?
	accounts := make([]struct {
		signer          signature.Signer
		reckonedNonce   uint64
		reckonedBalance quantity.Quantity
	}, TransferNumAccounts)
	var err error
	fac := memorySigner.NewFactory()
	for i := range accounts {
		accounts[i].signer, err = fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
	}

	// Read all the account info up front.
	ctx := context.Background()
	stakingClient := staking.NewStakingClient(conn)
	for i := range accounts {
		var account *staking.Account
		account, err = stakingClient.AccountInfo(ctx, &staking.OwnerQuery{
			Height: 0,
			Owner:  accounts[i].signer.Public(),
		})
		if err != nil {
			return fmt.Errorf("stakingClient.AccountInfo %s: %w", accounts[i].signer.Public(), err)
		}
		logger.Debug("account info",
			"i", i,
			"pub", accounts[i].signer.Public(),
			"info", account,
		)
		accounts[i].reckonedNonce = account.General.Nonce
		accounts[i].reckonedBalance = account.General.Balance
	}

	fee := transaction.Fee{
		Gas: 10,
	}
	var minBalance quantity.Quantity
	if err = minBalance.FromInt64(TransferAmount); err != nil {
		return fmt.Errorf("min balance FromInt64 %d: %w", TransferAmount, err)
	}
	if err = minBalance.Add(&fee.Amount); err != nil {
		return fmt.Errorf("min balance %v Add fee amount %v: %w", minBalance, fee.Amount, err)
	}
	for {
		perm := rng.Perm(TransferNumAccounts)
		fromPermIdx := 0
		for ; fromPermIdx < TransferNumAccounts; fromPermIdx++ {
			if accounts[perm[fromPermIdx]].reckonedBalance.Cmp(&minBalance) >= 0 {
				break
			}
		}
		if fromPermIdx >= TransferNumAccounts {
			return fmt.Errorf("all accounts %#v have gone broke", accounts)
		}
		toPermIdx := (fromPermIdx + 1) % TransferNumAccounts
		from := &accounts[perm[fromPermIdx]]
		to := &accounts[perm[toPermIdx]]

		transfer := staking.Transfer{
			To: to.signer.Public(),
		}
		if err = transfer.Tokens.FromInt64(TransferAmount); err != nil {
			return fmt.Errorf("transfer tokens FromInt64 %d: %w", TransferAmount, err)
		}
		tx := staking.NewTransferTx(from.reckonedNonce, &fee, &transfer)
		signedTx, err := transaction.Sign(from.signer, tx)
		if err != nil {
			return fmt.Errorf("transaction.Sign: %w", err)
		}
		logger.Debug("submitting transfer",
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
	}
}
