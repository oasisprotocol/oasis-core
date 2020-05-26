package workload

import (
	"context"
	"fmt"
	"math/rand"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	// NameTransfer is the name of the transfer workload.
	//
	// Transfer workload continiously submits transfer and burn transactions.
	NameTransfer = "transfer"

	transferNumAccounts = 10
	transferAmount      = 1
	transferBurnAmount  = 10
)

type transfer struct {
	logger *logging.Logger

	consensus consensus.ClientBackend

	accounts []struct {
		signer          signature.Signer
		address         staking.Address
		reckonedNonce   uint64
		reckonedBalance quantity.Quantity
	}
	fundingAccount signature.Signer
}

func (t *transfer) doTransferTx(ctx context.Context, fromIdx int, toIdx int) error {
	from := &t.accounts[fromIdx]
	to := &t.accounts[toIdx]

	transfer := staking.Transfer{To: to.address}
	if err := transfer.Tokens.FromInt64(transferAmount); err != nil {
		return fmt.Errorf("transfer tokens FromInt64 %d: %w", transferAmount, err)
	}
	tx := staking.NewTransferTx(from.reckonedNonce, &transaction.Fee{}, &transfer)
	from.reckonedNonce++

	t.logger.Debug("transfering tokens",
		"from", from.address,
		"to", to.address,
		"amount", transferAmount,
	)
	if err := fundSignAndSubmitTx(ctx, t.logger, t.consensus, from.signer, tx, t.fundingAccount); err != nil {
		t.logger.Error("failed to sign and submit transfer transaction",
			"tx", tx,
			"signer", from.signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	// Update reckoned state.
	if err := from.reckonedBalance.Sub(&transfer.Tokens); err != nil {
		return fmt.Errorf("from reckoned balance %v Sub transfer tokens %v: %w", from.reckonedBalance, transfer.Tokens, err)
	}
	if err := to.reckonedBalance.Add(&transfer.Tokens); err != nil {
		return fmt.Errorf("to reckoned balance %v Add transfer tokens %v: %w", to.reckonedBalance, transfer.Tokens, err)
	}

	return nil
}

func (t *transfer) doBurnTx(ctx context.Context, idx int) error {
	acc := &t.accounts[idx]

	// Fund account with tokens that will be burned.
	if err := transferFunds(ctx, t.logger, t.consensus, t.fundingAccount, acc.address, int64(transferBurnAmount)); err != nil {
		return fmt.Errorf("workload/transfer: account funding failure: %w", err)
	}

	burn := staking.Burn{}
	if err := burn.Tokens.FromInt64(transferBurnAmount); err != nil {
		return fmt.Errorf("burn tokens FromInt64 %d: %w", transferBurnAmount, err)
	}
	tx := staking.NewBurnTx(acc.reckonedNonce, &transaction.Fee{}, &burn)
	acc.reckonedNonce++

	t.logger.Debug("Burning tokens",
		"account", acc.address,
		"amount", transferBurnAmount,
	)
	if err := fundSignAndSubmitTx(ctx, t.logger, t.consensus, acc.signer, tx, t.fundingAccount); err != nil {
		t.logger.Error("failed to sign and submit transfer transaction",
			"tx", tx,
			"signer", acc.signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	return nil
}

func (t *transfer) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	fundingAccount signature.Signer,
) error {
	ctx := context.Background()

	t.logger = logging.GetLogger("cmd/txsource/workload/transfer")
	t.consensus = cnsc
	t.accounts = make([]struct {
		signer          signature.Signer
		address         staking.Address
		reckonedNonce   uint64
		reckonedBalance quantity.Quantity
	}, transferNumAccounts)
	t.fundingAccount = fundingAccount

	fac := memorySigner.NewFactory()
	// Load all the keys up front. Like, how annoyed would you be if down the line one of them turned out to be
	// corrupted or something, ya know?
	for i := range t.accounts {
		signer, err := fac.Generate(signature.SignerEntity, rng)
		if err != nil {
			return fmt.Errorf("memory signer factory Generate account %d: %w", i, err)
		}
		t.accounts[i].signer = signer
		t.accounts[i].address = staking.NewAddress(signer.Public())
	}

	// Read all the account info up front.
	stakingClient := staking.NewStakingClient(conn)
	for i := range t.accounts {
		fundAmount := transferAmount // funds for for a transfer
		if err := transferFunds(ctx, t.logger, cnsc, t.fundingAccount, t.accounts[i].address, int64(fundAmount)); err != nil {
			return fmt.Errorf("workload/transfer: account funding failure: %w", err)
		}
		var account *staking.Account
		account, err := stakingClient.AccountInfo(ctx, &staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  t.accounts[i].address,
		})
		if err != nil {
			return fmt.Errorf("stakingClient.AccountInfo %s: %w", t.accounts[i].address, err)
		}
		t.logger.Debug("account info",
			"i", i,
			"address", t.accounts[i].address,
			"info", account,
		)
		t.accounts[i].reckonedNonce = account.General.Nonce
		t.accounts[i].reckonedBalance = account.General.Balance
	}

	var minBalance quantity.Quantity
	if err := minBalance.FromInt64(transferAmount); err != nil {
		return fmt.Errorf("min balance FromInt64 %d: %w", transferAmount, err)
	}
	for {

		// Decide between doing a transfer or burn tx.
		switch rng.Intn(2) {
		case 0:
			// Transfer tx.
			perm := rng.Perm(transferNumAccounts)
			fromPermIdx := 0
			for ; fromPermIdx < transferNumAccounts; fromPermIdx++ {
				if t.accounts[perm[fromPermIdx]].reckonedBalance.Cmp(&minBalance) >= 0 {
					break
				}
			}
			if fromPermIdx >= transferNumAccounts {
				return fmt.Errorf("all accounts %#v have gone broke", t.accounts)
			}
			toPermIdx := (fromPermIdx + 1) % transferNumAccounts

			if err := t.doTransferTx(ctx, perm[fromPermIdx], perm[toPermIdx]); err != nil {
				return fmt.Errorf("transfer tx failure: %w", err)
			}
		case 1:
			// Burn tx.
			if err := t.doBurnTx(ctx, rng.Intn(transferNumAccounts)); err != nil {
				return fmt.Errorf("burn tx failure: %w", err)
			}

		default:
			return fmt.Errorf("unimplemented")
		}
		select {
		case <-gracefulExit.Done():
			t.logger.Debug("time's up")
			return nil
		default:
		}
	}
}
