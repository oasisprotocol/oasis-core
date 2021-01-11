package workload

import (
	"context"
	"fmt"
	"math/rand"

	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// NameTransfer is the name of the transfer workload.
//
// Transfer workload continuously submits transfer and burn transactions.
const NameTransfer = "transfer"

// Transfer is the transfer workload.
var Transfer = &transfer{
	BaseWorkload: NewBaseWorkload(NameTransfer),
}

const (
	transferNumAccounts    = 10
	transferAmount         = 1
	transferBurnAmount     = 10
	transferAllowMaxAmount = 20
)

type transferAccount struct {
	signer          signature.Signer
	address         staking.Address
	reckonedNonce   uint64
	reckonedBalance quantity.Quantity
}

type transfer struct {
	BaseWorkload

	consensus consensus.ClientBackend

	accounts       []transferAccount
	fundingAccount signature.Signer

	allowances map[staking.Address]map[staking.Address]quantity.Quantity
}

func (t *transfer) doTransferTx(ctx context.Context, from, to *transferAccount) error {
	transfer := staking.Transfer{To: to.address}
	if err := transfer.Amount.FromInt64(transferAmount); err != nil {
		return fmt.Errorf("transfer base units FromInt64 %d: %w", transferAmount, err)
	}
	tx := staking.NewTransferTx(from.reckonedNonce, nil, &transfer)
	from.reckonedNonce++

	t.Logger.Debug("transferring stake",
		"from", from.address,
		"to", to.address,
		"base_units", transferAmount,
	)
	if err := t.FundSignAndSubmitTx(ctx, from.signer, tx); err != nil {
		t.Logger.Error("failed to sign and submit transfer transaction",
			"tx", tx,
			"signer", from.signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	// Update reckoned state.
	if err := from.reckonedBalance.Sub(&transfer.Amount); err != nil {
		return fmt.Errorf("from reckoned balance %v Sub transfer amount %v: %w",
			from.reckonedBalance, transfer.Amount, err,
		)
	}
	if err := to.reckonedBalance.Add(&transfer.Amount); err != nil {
		return fmt.Errorf("to reckoned balance %v Add transfer amount %v: %w",
			to.reckonedBalance, transfer.Amount, err,
		)
	}

	return nil
}

func (t *transfer) doBurnTx(ctx context.Context, acc *transferAccount) error {
	// Fund account with stake that will be burned.
	if err := t.TransferFunds(ctx, t.fundingAccount, acc.address, transferBurnAmount); err != nil {
		return fmt.Errorf("workload/transfer: account funding failure: %w", err)
	}

	burn := staking.Burn{}
	if err := burn.Amount.FromInt64(transferBurnAmount); err != nil {
		return fmt.Errorf("burn base units FromInt64 %d: %w", transferBurnAmount, err)
	}
	tx := staking.NewBurnTx(acc.reckonedNonce, nil, &burn)
	acc.reckonedNonce++

	t.Logger.Debug("Burning stake",
		"account", acc.address,
		"base_units", transferBurnAmount,
	)
	if err := t.FundSignAndSubmitTx(ctx, acc.signer, tx); err != nil {
		t.Logger.Error("failed to sign and submit transfer transaction",
			"tx", tx,
			"signer", acc.signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit tx: %w", err)
	}

	return nil
}

func (t *transfer) doAllowTx(ctx context.Context, rng *rand.Rand, acct, beneficiary *transferAccount) error {
	allow := staking.Allow{
		Beneficiary: beneficiary.address,
	}
	// Generate random amount change.
	if err := allow.AmountChange.FromInt64(rng.Int63n(transferAllowMaxAmount)); err != nil {
		return fmt.Errorf("failed to set allow.AmountChange: %w", err)
	}
	// Generate random sign.
	switch rng.Intn(2) {
	case 0:
		allow.Negative = false
	case 1:
		allow.Negative = true
	}
	tx := staking.NewAllowTx(acct.reckonedNonce, nil, &allow)
	acct.reckonedNonce++

	t.Logger.Debug("updating allowance",
		"acct", acct.address,
		"beneficiary", beneficiary.address,
		"amount_change", allow.AmountChange,
	)
	if err := t.FundSignAndSubmitTx(ctx, acct.signer, tx); err != nil {
		t.Logger.Error("failed to sign and submit allow transaction",
			"tx", tx,
			"signer", acct.signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit allow tx: %w", err)
	}

	if t.allowances[acct.address] == nil {
		t.allowances[acct.address] = make(map[staking.Address]quantity.Quantity)
	}
	allowance := t.allowances[acct.address][beneficiary.address]
	var err error
	switch allow.Negative {
	case false:
		err = allowance.Add(&allow.AmountChange)
	case true:
		_, err = allowance.SubUpTo(&allow.AmountChange)
	}
	if err != nil {
		return fmt.Errorf("failed to update internal allowances map: %w", err)
	}
	t.allowances[acct.address][beneficiary.address] = allowance

	return nil
}

func (t *transfer) doWithdrawTx(ctx context.Context, rng *rand.Rand, from, to *transferAccount) error {
	withdraw := staking.Withdraw{
		From: from.address,
	}
	// Generate random amount up to the minimum of available balance and allowance.
	maxAmount := from.reckonedBalance
	if t.allowances[from.address] == nil {
		return nil
	}
	allowance := t.allowances[from.address][to.address]
	if allowance.IsZero() {
		return nil
	}
	if allowance.Cmp(&maxAmount) < 0 {
		maxAmount = allowance
	}
	if err := withdraw.Amount.FromInt64(rng.Int63n(maxAmount.ToBigInt().Int64())); err != nil {
		return fmt.Errorf("failed to set withdraw.Amount: %w", err)
	}
	tx := staking.NewWithdrawTx(to.reckonedNonce, nil, &withdraw)
	to.reckonedNonce++

	t.Logger.Debug("withdrawing stake",
		"from", from.address,
		"to", to.address,
		"amount", withdraw.Amount,
	)
	if err := t.FundSignAndSubmitTx(ctx, to.signer, tx); err != nil {
		t.Logger.Error("failed to sign and submit withdraw transaction",
			"tx", tx,
			"signer", to.signer.Public(),
		)
		return fmt.Errorf("failed to sign and submit withdraw tx: %w", err)
	}

	// Update reckoned state.
	if err := from.reckonedBalance.Sub(&withdraw.Amount); err != nil {
		return fmt.Errorf("from reckoned balance %v Sub withdraw amount %v: %w",
			from.reckonedBalance, withdraw.Amount, err,
		)
	}
	if err := to.reckonedBalance.Add(&withdraw.Amount); err != nil {
		return fmt.Errorf("to reckoned balance %v Add withdraw amount %v: %w",
			to.reckonedBalance, withdraw.Amount, err,
		)
	}
	// Update allowance.
	if err := allowance.Sub(&withdraw.Amount); err != nil {
		return fmt.Errorf("allowance %v Sub amount %v: %w",
			t.allowances[from.address][to.address], withdraw.Amount, err,
		)
	}
	t.allowances[from.address][to.address] = allowance

	return nil
}

func (t *transfer) getRandomAccountPairWithBalance(rng *rand.Rand, minBalance *quantity.Quantity) (from, to *transferAccount, err error) {
	perm := rng.Perm(transferNumAccounts)
	fromPermIdx := 0
	for ; fromPermIdx < transferNumAccounts; fromPermIdx++ {
		if t.accounts[perm[fromPermIdx]].reckonedBalance.Cmp(minBalance) >= 0 {
			break
		}
	}
	if fromPermIdx >= transferNumAccounts {
		return nil, nil, fmt.Errorf("all accounts %#v have gone broke", t.accounts)
	}
	toPermIdx := (fromPermIdx + 1) % transferNumAccounts

	from = &t.accounts[perm[fromPermIdx]]
	to = &t.accounts[perm[toPermIdx]]
	return
}

// Implements Workload.
func (t *transfer) NeedsFunds() bool {
	return true
}

// Implements Workload.
func (t *transfer) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
	validatorEntities []signature.Signer,
) error {
	// Initialize base workload.
	t.BaseWorkload.Init(cnsc, sm, fundingAccount)

	ctx := context.Background()

	t.consensus = cnsc
	t.accounts = make([]transferAccount, transferNumAccounts)
	t.allowances = make(map[staking.Address]map[staking.Address]quantity.Quantity)
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
		if err := t.TransferFunds(ctx, fundingAccount, t.accounts[i].address, transferAmount); err != nil {
			return fmt.Errorf("workload/transfer: account funding failure: %w", err)
		}
		var account *staking.Account
		account, err := stakingClient.Account(ctx, &staking.OwnerQuery{
			Height: consensus.HeightLatest,
			Owner:  t.accounts[i].address,
		})
		if err != nil {
			return fmt.Errorf("stakingClient.Account %s: %w", t.accounts[i].address, err)
		}
		t.Logger.Debug("account info",
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
		// Determine which transaction type to issue.
		switch rng.Intn(4) {
		case 0:
			// Transfer tx.
			from, to, err := t.getRandomAccountPairWithBalance(rng, &minBalance)
			if err != nil {
				return err
			}

			if err = t.doTransferTx(ctx, from, to); err != nil {
				return fmt.Errorf("transfer tx failure: %w", err)
			}
		case 1:
			// Burn tx.
			if err := t.doBurnTx(ctx, &t.accounts[rng.Intn(transferNumAccounts)]); err != nil {
				return fmt.Errorf("burn tx failure: %w", err)
			}
		case 2:
			// Allow tx.
			acct, beneficiary, err := t.getRandomAccountPairWithBalance(rng, quantity.NewQuantity())
			if err != nil {
				return err
			}

			if err = t.doAllowTx(ctx, rng, acct, beneficiary); err != nil {
				return fmt.Errorf("allow tx failure: %w", err)
			}
		case 3:
			// Withdraw tx.
			from, to, err := t.getRandomAccountPairWithBalance(rng, &minBalance)
			if err != nil {
				return err
			}

			if err = t.doWithdrawTx(ctx, rng, from, to); err != nil {
				return fmt.Errorf("withdraw tx failure: %w", err)
			}
		default:
			return fmt.Errorf("unimplemented")
		}

		// Finish once the time is up.
		select {
		case <-gracefulExit.Done():
			t.Logger.Debug("time's up")
			return nil
		default:
		}
	}
}
