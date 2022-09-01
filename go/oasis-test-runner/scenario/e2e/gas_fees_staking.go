package e2e

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	// GasFeesStaking is the staking gas fees scenario.
	GasFeesStaking scenario.Scenario = &gasFeesImpl{
		E2E: *NewE2E("gas-fees/staking"),
	}

	// GasFeesStakingDumpRestore is the staking gas fees scenario with
	// dump-restore.
	GasFeesStakingDumpRestore scenario.Scenario = &gasFeesImpl{
		E2E:         *NewE2E("gas-fees/staking-dump-restore"),
		dumpRestore: true,
	}

	// Signer for the staking account address defined in the staking genesis
	// fixture used in this scenario.
	srcSigner = memorySigner.NewTestSigner("oasis gas fees e2e test signer: src")

	// Testing destination account address.
	dstAddr = staking.NewAddress(
		signature.NewPublicKey("badfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)
	// Testing escrow account address.
	escrowAddr = staking.NewAddress(
		signature.NewPublicKey("badbadffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
	)
)

type gasFeesImpl struct {
	E2E

	dumpRestore bool
}

func (sc *gasFeesImpl) Clone() scenario.Scenario {
	return &gasFeesImpl{
		E2E:         sc.E2E.Clone(),
		dumpRestore: sc.dumpRestore,
	}
}

func (sc *gasFeesImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	ff := &oasis.NetworkFixture{
		Network: oasis.NetworkCfg{
			NodeBinary: f.Network.NodeBinary,
			StakingGenesis: &staking.Genesis{
				Parameters: staking.ConsensusParameters{
					DebondingInterval: 1,
					GasCosts: transaction.Costs{
						staking.GasOpTransfer:      10,
						staking.GasOpBurn:          10,
						staking.GasOpAddEscrow:     10,
						staking.GasOpReclaimEscrow: 10,
					},
					FeeSplitWeightPropose:     *quantity.NewFromUint64(1),
					FeeSplitWeightVote:        *quantity.NewFromUint64(2),
					FeeSplitWeightNextPropose: *quantity.NewFromUint64(2),
				},
				TotalSupply:   *quantity.NewFromUint64(1200),
				CommonPool:    *quantity.NewFromUint64(150),
				LastBlockFees: *quantity.NewFromUint64(50),
				Ledger: map[staking.Address]*staking.Account{
					TestEntityAccount: {
						General: staking.GeneralAccount{
							Balance: *quantity.NewFromUint64(1000),
						},
					},
				},
			},
			Consensus: consensusGenesis.Genesis{
				Parameters: consensusGenesis.Parameters{
					GasCosts: transaction.Costs{
						consensusGenesis.GasOpTxByte: 0, // So we can control gas more easily.
					},
				},
			},
		},
		Entities: []oasis.EntityCfg{
			{IsDebugTestEntity: true},
			{},
			{},
			{},
		},
		Validators: []oasis.ValidatorFixture{
			// Create three validators, each with its own entity so we can test
			// if gas disbursement works correctly.
			{Entity: 1, Consensus: oasis.ConsensusFixture{MinGasPrice: 1, SupplementarySanityInterval: 1}},
			{Entity: 2, Consensus: oasis.ConsensusFixture{MinGasPrice: 1}},
			{Entity: 3, Consensus: oasis.ConsensusFixture{MinGasPrice: 1}},
		},
		Seeds: []oasis.SeedFixture{{}},
	}

	ff.Network.SetMockEpoch()
	ff.Network.SetInsecureBeacon()

	return ff, nil
}

func (sc *gasFeesImpl) Run(childEnv *env.Env) error {
	ctx := context.Background()

	if err := sc.runTests(ctx); err != nil {
		return err
	}

	if sc.dumpRestore {
		// Do a dump-restore of the network and re-run the test.
		fixture, err := sc.Fixture()
		if err != nil {
			return err
		}
		if err := sc.DumpRestoreNetwork(childEnv, fixture, false, nil, nil); err != nil {
			return err
		}
		if err := sc.runTests(ctx); err != nil {
			return fmt.Errorf("error after dump restore: %w", err)
		}
	}

	return nil
}

func (sc *gasFeesImpl) runTests(ctx context.Context) error {
	if err := sc.Net.Start(); err != nil {
		return err
	}

	sc.Logger.Info("waiting for network to come up")

	if err := sc.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return err
	}

	// Determine initial entity balances.
	totalEntityBalance, err := sc.getTotalEntityBalance(ctx)
	if err != nil {
		return err
	}

	// Include common pool from genesis.
	totalFees, err := sc.getInitialCommonPoolBalance(ctx)
	if err != nil {
		return err
	}

	// Run some operations that charge fees.
	for _, t := range []struct {
		name string
		fn   func(context.Context, signature.Signer) (*quantity.Quantity, error)
	}{
		{"Transfer", sc.testTransfer},
		{"Burn", sc.testBurn},
		{"AddEscrow", sc.testAddEscrow},
		{"ReclaimEscrow", sc.testReclaimEscrow},
	} {
		sc.Logger.Info("testing operation", "op", t.name)

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
	st := sc.Net.Controller().Staking
	commonPool, err := st.CommonPool(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}

	// As of the last time this comment was updated:
	// - total fees has 150 base units from genesis common pool (different in dump-restore variant)
	// - total fees has 50 base units from genesis last block fees (different in dump-restore variant)
	// - for each of 12 transactions that pay for gas:
	//   - 10 base units paid for gas in a block on its own
	//   - (2+2)/(1+2+2) = 80% => 8 base units persisted for VQ share
	//   - 10 - 8 = 2 base units paid to P
	//   - VQ share divided into 3 validator portions, for 2 base units each
	//   - (2)/(2+2) = 50% => 1 base unit per validator for Q
	//   - 2 - 1 = 1 base unit per validator for V
	//   - remaining 2 base units moved to common pool
	// - 150 + 50 + 12 * 10 = 320 base units `total_fees` (different in dump-restore variant)
	// - 12 * 2 = 24 base units paid for P role
	// - 12 * 1 * 3 = 36 base units paid for V roles
	// - 12 * 1 * 3 = 36 base units paid for Q role
	// - 24 + 36 + 36 = 96 base units `disbursed_fees`
	sc.Logger.Info("making sure that fees have been disbursed",
		"total_fees", totalFees,
		"disbursed_fees", newTotalEntityBalance,
		"common_pool", commonPool,
	)

	// Ensure that the correct fees have been disbursed to entity accounts.
	var referenceDisbursement quantity.Quantity
	if err := referenceDisbursement.FromUint64(96); err != nil {
		return fmt.Errorf("import reference disbursement: %w", err)
	}
	if newTotalEntityBalance.Cmp(&referenceDisbursement) != 0 {
		return fmt.Errorf("total disbursed fees %v wrong (should be %v)", newTotalEntityBalance, &referenceDisbursement)
	}

	// Ensure that at least some fees ended up in the common pool due to loss
	// of precision (see comment above).
	if commonPool.IsZero() {
		return fmt.Errorf("no fees disbursed to the common pool")
	}
	// Ensure total (entities + common pool) is correct.
	_ = newTotalEntityBalance.Add(commonPool)
	if newTotalEntityBalance.Cmp(totalFees) != 0 {
		return fmt.Errorf("fee disbursement incorrect (expected: %s actual: %s)",
			totalFees,
			newTotalEntityBalance,
		)
	}

	if err := sc.Net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}

func (sc *gasFeesImpl) getInitialCommonPoolBalance(ctx context.Context) (*quantity.Quantity, error) {
	st := sc.Net.Controller().Staking

	cmnPool, err := st.CommonPool(ctx, consensus.HeightLatest)
	if err != nil {
		return nil, fmt.Errorf("failed to get initial common pool info: %w", err)
	}

	sc.Logger.Debug("fetched common pool balance",
		"balance", cmnPool,
	)

	return cmnPool, nil
}

func (sc *gasFeesImpl) getTotalEntityBalance(ctx context.Context) (*quantity.Quantity, error) {
	st := sc.Net.Controller().Staking

	var total quantity.Quantity
	for _, e := range sc.Net.Entities()[1:] { // Only count entities with validators.
		ent, _ := e.Inner()
		addr := staking.NewAddress(ent.ID)

		acct, err := st.Account(ctx, &staking.OwnerQuery{Owner: addr, Height: consensus.HeightLatest})
		if err != nil {
			return nil, fmt.Errorf("failed to get account info for %s: %w", addr, err)
		}

		sc.Logger.Debug("fetched balance",
			"entity", ent.ID,
			"address", addr,
			"balance", acct.General.Balance,
		)

		_ = total.Add(&acct.General.Balance)
	}

	return &total, nil
}

func (sc *gasFeesImpl) testTransfer(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, true, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		transfer := staking.Transfer{
			To: dstAddr,
		}
		_ = transfer.Amount.FromInt64(amount)

		tx := staking.NewTransferTx(acct.General.Nonce, &fee, &transfer)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign transfer: %w", err)
		}
		return sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	})
}

func (sc *gasFeesImpl) testBurn(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, true, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		var burn staking.Burn
		_ = burn.Amount.FromInt64(amount)

		tx := staking.NewBurnTx(acct.General.Nonce, &fee, &burn)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign burn: %w", err)
		}
		return sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	})
}

func (sc *gasFeesImpl) testAddEscrow(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, true, func(acct *staking.Account, fee transaction.Fee, amount int64) error {
		escrow := staking.Escrow{
			Account: escrowAddr,
		}
		_ = escrow.Amount.FromInt64(amount)

		tx := staking.NewAddEscrowTx(acct.General.Nonce, &fee, &escrow)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign escrow: %w", err)
		}
		return sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx)
	})
}

func (sc *gasFeesImpl) testReclaimEscrow(ctx context.Context, signer signature.Signer) (*quantity.Quantity, error) {
	return sc.testStakingGas(ctx, signer, false, func(acct *staking.Account, fee transaction.Fee, shares int64) error {
		escrow := staking.ReclaimEscrow{
			Account: escrowAddr,
		}
		_ = escrow.Shares.FromInt64(shares)

		tx := staking.NewReclaimEscrowTx(acct.General.Nonce, &fee, &escrow)
		sigTx, err := transaction.Sign(signer, tx)
		if err != nil {
			return fmt.Errorf("failed to sign reclaim escrow: %w", err)
		}
		if err = sc.Net.Controller().Consensus.SubmitTx(ctx, sigTx); err != nil {
			return fmt.Errorf("failed to reclaim escrow: %w", err)
		}

		ch, sub, err := sc.Net.Controller().Staking.WatchEvents(ctx)
		if err != nil {
			return fmt.Errorf("failed to watch escrows: %w", err)
		}
		defer sub.Close()

		// Advance epochs to trigger reclaim processing.
		if err = sc.Net.Controller().SetEpoch(ctx, 1); err != nil {
			return fmt.Errorf("failed to set epoch: %w", err)
		}

		for {
			select {
			case ev := <-ch:
				if ev.Escrow != nil && ev.Escrow.Reclaim != nil {
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
	st := sc.Net.Controller().Staking

	// Fetch initial account info.
	addr := staking.NewAddress(signer.Public())
	acct, err := st.Account(ctx, &staking.OwnerQuery{Owner: addr, Height: consensus.HeightLatest})
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
	newAcct, err := st.Account(ctx, &staking.OwnerQuery{Owner: addr, Height: consensus.HeightLatest})
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
