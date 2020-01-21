package e2e

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	consensus "github.com/oasislabs/oasis-core/go/consensus/api"
	"github.com/oasislabs/oasis-core/go/consensus/api/transaction"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var (
	// GasFeesStaking is the staking gas fees scenario.
	GasFeesStaking scenario.Scenario = &gasFeesImpl{
		logger: logging.GetLogger("scenario/e2e/gas-fees/staking"),
	}

	// srcSigner is the signer for public key defined in the staking genesis
	// fixture used in this scenario.
	srcSigner    = memorySigner.NewTestSigner("oasis gas fees e2e test signer: src")
	escrowSigner = memorySigner.NewTestSigner("oasis gas fees e2e test signer: escrow")
)

type gasFeesImpl struct {
	net *oasis.Network

	logger *logging.Logger
}

func (sc *gasFeesImpl) Name() string {
	return "gas-fees/staking"
}

func (sc *gasFeesImpl) Fixture() (*oasis.NetworkFixture, error) {
	var tee node.TEEHardware
	err := tee.FromString(viper.GetString(cfgTEEHardware))
	if err != nil {
		return nil, err
	}
	var mrSigner *sgx.MrSigner
	if tee == node.TEEHardwareIntelSGX {
		mrSigner = &ias.FortanixTestMrSigner
	}

	return &oasis.NetworkFixture{
		TEE: oasis.TEEFixture{
			Hardware: tee,
			MrSigner: mrSigner,
		},
		Network: oasis.NetworkCfg{
			NodeBinary:                        viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary:               viper.GetString(cfgRuntimeLoader),
			EpochtimeMock:                     true,
			StakingGenesis:                    "tests/fixture-data/gas-fees/staking-genesis.json",
			DefaultLogWatcherHandlerFactories: DefaultBasicLogWatcherHandlerFactories,
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{},
			oasis.EntityCfg{},
			oasis.EntityCfg{},
		},
		Validators: []oasis.ValidatorFixture{
			// Create three validators, each with its own entity so we can test
			// if gas disbursement works correctly.
			oasis.ValidatorFixture{Entity: 1, MinGasPrice: 1},
			oasis.ValidatorFixture{Entity: 2, MinGasPrice: 1},
			oasis.ValidatorFixture{Entity: 3, MinGasPrice: 1},
		},
	}, nil
}

func (sc *gasFeesImpl) Init(childEnv *env.Env, net *oasis.Network) error {
	sc.net = net
	return nil
}

func (sc *gasFeesImpl) Run(childEnv *env.Env) error {
	if err := sc.net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	sc.logger.Info("waiting for network to come up")
	if err := sc.net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return err
	}

	// Determine initial entity balances.
	totalEntityBalance, err := sc.getTotalEntityBalance(ctx)
	if err != nil {
		return err
	}

	// Run some operations that charge fees.
	var totalFees quantity.Quantity
	for _, t := range []struct {
		name string
		fn   func(context.Context, signature.Signer) (*quantity.Quantity, error)
	}{
		{"Transfer", sc.testTransfer},
		{"Burn", sc.testBurn},
		{"AddEscrow", sc.testAddEscrow},
		{"ReclaimEscrow", sc.testReclaimEscrow},
	} {
		sc.logger.Info("testing operation", "op", t.name)

		var fees *quantity.Quantity
		if fees, err = t.fn(ctx, srcSigner); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
		_ = totalFees.Add(fees)
	}

	// Make sure that fees have been transferred out.
	newTotalEntityBalance, err := sc.getTotalEntityBalance(ctx)
	if err != nil {
		return err
	}
	_ = newTotalEntityBalance.Sub(totalEntityBalance)

	// Any fees that couldn't be transferred due to loss of precision should end
	// up in the common pool. Since in this scenario an operation costs 10 units,
	// there is only one operation per block and there are 3 validators, each
	// operation should put 1 unit to the common pool.
	st := sc.net.Controller().Staking
	commonPool, err := st.CommonPool(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}

	sc.logger.Info("making sure that fees have been disbursed",
		"total_fees", totalFees,
		"disbursed_fees", newTotalEntityBalance,
		"common_pool", commonPool,
	)

	// Ensure that at least some fees have been disbursed to entity accounts.
	if newTotalEntityBalance.IsZero() {
		return fmt.Errorf("no fees disbursed to entity accounts")
	}
	// Ensure that at least some fees ended up in the common pool due to loss
	// of precision (see comment above).
	if commonPool.IsZero() {
		return fmt.Errorf("no fees disbursed to the common pool")
	}
	// Ensure total (entities + common pool) is correct.
	_ = newTotalEntityBalance.Add(commonPool)
	if newTotalEntityBalance.Cmp(&totalFees) != 0 {
		return fmt.Errorf("fee disbursement incorrect (expected: %s actual: %s)",
			totalFees,
			newTotalEntityBalance,
		)
	}

	if err := sc.net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}

func (sc *gasFeesImpl) getTotalEntityBalance(ctx context.Context) (*quantity.Quantity, error) {
	st := sc.net.Controller().Staking

	var total quantity.Quantity
	for _, e := range sc.net.Entities()[1:] { // Only count entities with validators.
		ent, _ := e.Inner()

		acct, err := st.AccountInfo(ctx, &staking.OwnerQuery{Owner: ent.ID, Height: consensus.HeightLatest})
		if err != nil {
			return nil, fmt.Errorf("failed to get account info: %w", err)
		}

		sc.logger.Debug("fetched balance",
			"entity_id", ent.ID,
			"balance", acct.General.Balance,
		)

		_ = total.Add(&acct.General.Balance)
	}

	return &total, nil
}

func (sc *gasFeesImpl) testTransfer(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, true, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		// Generate random destination account.
		dstSigner, err := memorySigner.NewSigner(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate destination account: %w", err)
		}

		transfer := staking.Transfer{
			To: dstSigner.Public(),
		}
		_ = transfer.Tokens.FromInt64(amount)

		tx := staking.NewTransferTx(acct.General.Nonce, &fee, &transfer)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign transfer: %w", err)
		}
		return sc.net.Controller().Consensus.SubmitTx(ctx, sigTx)
	})
}

func (sc *gasFeesImpl) testBurn(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, true, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		var burn staking.Burn
		_ = burn.Tokens.FromInt64(amount)

		tx := staking.NewBurnTx(acct.General.Nonce, &fee, &burn)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign burn: %w", err)
		}
		return sc.net.Controller().Consensus.SubmitTx(ctx, sigTx)
	})
}

func (sc *gasFeesImpl) testAddEscrow(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, true, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		escrow := staking.Escrow{
			Account: escrowSigner.Public(),
		}
		_ = escrow.Tokens.FromInt64(amount)

		tx := staking.NewAddEscrowTx(acct.General.Nonce, &fee, &escrow)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign escrow: %w", err)
		}
		return sc.net.Controller().Consensus.SubmitTx(ctx, sigTx)
	})
}

func (sc *gasFeesImpl) testReclaimEscrow(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, false, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		escrow := staking.ReclaimEscrow{
			Account: escrowSigner.Public(),
		}
		_ = escrow.Shares.FromInt64(amount)

		tx := staking.NewReclaimEscrowTx(acct.General.Nonce, &fee, &escrow)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign reclaim escrow: %w", err)
		}
		if err = sc.net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
			return fmt.Errorf("failed to reclaim escrow: %w", err)
		}

		ch, sub, err := sc.net.Controller().Staking.WatchEscrows(ctx)
		if err != nil {
			return fmt.Errorf("failed to watch escrows: %w", err)
		}
		defer sub.Close()

		// Advance epochs to trigger reclaim processing.
		if err = sc.net.Controller().SetEpoch(ctx, 1); err != nil {
			return fmt.Errorf("failed to set epoch: %w", err)
		}

		for {
			select {
			case ev := <-ch:
				if ev.Reclaim != nil {
					return nil
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
}

func (sc *gasFeesImpl) testStakingGas(
	ctx context.Context,
	signer signature.Signer,
	subtract bool,
	op func(*staking.Account, transaction.Fee, int64) error,
) (*quantity.Quantity, error) {
	var amountOverBalance quantity.Quantity
	// This should be more than it is in the account.
	_ = amountOverBalance.FromInt64(1_000_000)

	var amountOk quantity.Quantity
	// This should be a reasonable amount that the account can pay.
	_ = amountOk.FromInt64(10)

	var amountLow quantity.Quantity
	// This amount gives a lower gas price than accepted by the validator.
	_ = amountLow.FromInt64(5)

	var totalFees quantity.Quantity
	for _, t := range []struct {
		name      string
		fee       transaction.Fee
		amount    int64
		checkOk   bool
		deliverOk bool
	}{
		// No fees.
		{"NoFees", transaction.Fee{}, 50, true, false},
		// Free transaction.
		{"FreeGas", transaction.Fee{Gas: 10}, 50, false, false},
		// Gas price too low.
		{"LowGasPrice", transaction.Fee{Amount: amountLow, Gas: 10}, 50, false, false},
		// Not enough transaction.
		{"OutOfGas", transaction.Fee{Amount: amountOk, Gas: 9}, 50, true, false},
		// No balance to pay for transaction.
		{"NoBalanceForGas", transaction.Fee{Amount: amountOverBalance, Gas: 10}, 50, false, false},
		// Enough balance to pay for gas, but not enough balance for operation
		// after you subtract the gas payment.
		{"NoBalanceForOp", transaction.Fee{Amount: amountOk, Gas: 10}, 1000, true, false},
		// Successful operation.
		{"Success", transaction.Fee{Amount: amountOk, Gas: 10}, 100, true, true},
	} {
		if err := sc.testStakingGasOp(ctx, signer, t.fee, t.amount, t.checkOk, t.deliverOk, subtract, op); err != nil {
			return nil, fmt.Errorf("%s: %w", t.name, err)
		}

		if t.checkOk {
			_ = totalFees.Add(&t.fee.Amount)
		}
	}

	return &totalFees, nil
}

func (sc *gasFeesImpl) testStakingGasOp(
	ctx context.Context,
	signer signature.Signer,
	fee transaction.Fee,
	amount int64,
	checkOk, deliverOk bool,
	subtract bool,
	op func(*staking.Account, transaction.Fee, int64) error,
) error {
	st := sc.net.Controller().Staking

	// Fetch initial account info.
	acct, err := st.AccountInfo(ctx, &staking.OwnerQuery{Owner: signer.Public(), Height: consensus.HeightLatest})
	if err != nil {
		return fmt.Errorf("failed to get account info: %w", err)
	}

	// Perform the staking operation.
	err = op(acct, fee, amount)

	var expectedNonce uint64
	var expectedBalance *quantity.Quantity
	switch deliverOk {
	case true:
		// Operation should have succeeded.
		if err != nil {
			return fmt.Errorf("operation failed: %w", err)
		}

		// Nonce should be incremented.
		expectedNonce = acct.General.Nonce + 1
		// Balance should be correct.
		expectedBalance = acct.General.Balance.Clone()
		_ = expectedBalance.Sub(&fee.Amount)

		var amt quantity.Quantity
		_ = amt.FromInt64(amount)
		if subtract {
			_ = expectedBalance.Sub(&amt)
		} else {
			_ = expectedBalance.Add(&amt)
		}
	case false:
		// Operation should have failed.
		if err == nil {
			return fmt.Errorf("operation should have failed but it succeeded")
		}

		switch checkOk {
		case true:
			// Nonce should be incremented.
			expectedNonce = acct.General.Nonce + 1
			// Balance should stay the same (minus gas fees).
			expectedBalance = acct.General.Balance.Clone()
			_ = expectedBalance.Sub(&fee.Amount)
		case false:
			// Nonce should not be incremented.
			expectedNonce = acct.General.Nonce
			// Balance should stay the same.
			expectedBalance = acct.General.Balance.Clone()
		}

	}

	// Check account after the (failed) operation.
	newAcct, err := st.AccountInfo(ctx, &staking.OwnerQuery{Owner: signer.Public(), Height: consensus.HeightLatest})
	if err != nil {
		return fmt.Errorf("failed to get account info: %w", err)
	}

	if newAcct.General.Nonce != expectedNonce {
		return fmt.Errorf("unexpected nonce (expected: %d got: %d)",
			expectedNonce,
			newAcct.General.Nonce,
		)
	}
	if newAcct.General.Balance.Cmp(expectedBalance) != 0 {
		return fmt.Errorf("unexpected balance (expected: %s got: %s)",
			expectedBalance,
			newAcct.General.Balance,
		)
	}

	return nil
}
