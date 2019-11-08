package e2e

import (
	"context"
	"crypto/rand"
	"fmt"

	"github.com/spf13/viper"

	"github.com/oasislabs/oasis-core/go/common/consensus/gas"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/logging"
	"github.com/oasislabs/oasis-core/go/common/node"
	"github.com/oasislabs/oasis-core/go/common/quantity"
	"github.com/oasislabs/oasis-core/go/common/sgx"
	"github.com/oasislabs/oasis-core/go/common/sgx/ias"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/env"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasislabs/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
)

var (
	// GasFees is the gas fees scenario.
	GasFees scenario.Scenario = &gasFeesImpl{
		logger: logging.GetLogger("scenario/e2e/gas_fees"),
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
	return "gas-fees"
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
			NodeBinary:          viper.GetString(cfgNodeBinary),
			RuntimeLoaderBinary: viper.GetString(cfgRuntimeLoader),
			EpochtimeMock:       true,
			StakingGenesis:      "tests/fixture-data/gas-fees/staking-genesis.json",
			LogWatcherHandlers:  DefaultBasicLogWatcherHandlers,
		},
		Entities: []oasis.EntityCfg{
			oasis.EntityCfg{IsDebugTestEntity: true},
			oasis.EntityCfg{AllowEntitySignedNodes: true},
		},
		Validators: []oasis.ValidatorFixture{
			oasis.ValidatorFixture{Entity: 1, MinGasPrice: 1},
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

	// Grab the staking client.
	ctx := context.Background()
	st := sc.net.Controller().Staking

	for _, t := range []struct {
		name string
		fn   func(context.Context, signature.Signer, staking.Backend) error
	}{
		{"Transfer", sc.testTransfer},
		{"Burn", sc.testBurn},
		{"AddEscrow", sc.testAddEscrow},
		{"ReclaimEscrow", sc.testReclaimEscrow},
	} {
		sc.logger.Info("testing operation", "op", t.name)

		if err := t.fn(ctx, srcSigner, st); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
	}

	if err := sc.net.CheckLogWatchers(); err != nil {
		return err
	}

	return nil
}

func (sc *gasFeesImpl) testTransfer(ctx context.Context, signer signature.Signer, st staking.Backend) error {
	return testStakingGas(ctx, signer, st, true, func(acct *staking.Account, fee gas.Fee, amount int64) error {
		// Generate random destination account.
		dstSigner, err := memorySigner.NewSigner(rand.Reader)
		if err != nil {
			return fmt.Errorf("failed to generate destination account: %w", err)
		}

		transfer := staking.Transfer{
			Nonce: acct.General.Nonce,
			Fee:   fee,
			To:    dstSigner.Public(),
		}
		_ = transfer.Tokens.FromInt64(amount)
		signedXfer, err := staking.SignTransfer(signer, &transfer)
		if err != nil {
			return fmt.Errorf("failed to sign transfer: %w", err)
		}
		return st.Transfer(ctx, signedXfer)
	})
}

func (sc *gasFeesImpl) testBurn(ctx context.Context, signer signature.Signer, st staking.Backend) error {
	return testStakingGas(ctx, signer, st, true, func(acct *staking.Account, fee gas.Fee, amount int64) error {
		burn := staking.Burn{
			Nonce: acct.General.Nonce,
			Fee:   fee,
		}
		_ = burn.Tokens.FromInt64(amount)
		signedBurn, err := staking.SignBurn(signer, &burn)
		if err != nil {
			return fmt.Errorf("failed to sign burn: %w", err)
		}
		return st.Burn(ctx, signedBurn)
	})
}

func (sc *gasFeesImpl) testAddEscrow(ctx context.Context, signer signature.Signer, st staking.Backend) error {
	return testStakingGas(ctx, signer, st, true, func(acct *staking.Account, fee gas.Fee, amount int64) error {
		escrow := staking.Escrow{
			Nonce:   acct.General.Nonce,
			Fee:     fee,
			Account: escrowSigner.Public(),
		}
		_ = escrow.Tokens.FromInt64(amount)
		signedEscrow, err := staking.SignEscrow(signer, &escrow)
		if err != nil {
			return fmt.Errorf("failed to sign escrow: %w", err)
		}
		return st.AddEscrow(ctx, signedEscrow)
	})
}

func (sc *gasFeesImpl) testReclaimEscrow(ctx context.Context, signer signature.Signer, st staking.Backend) error {
	return testStakingGas(ctx, signer, st, false, func(acct *staking.Account, fee gas.Fee, amount int64) error {
		escrow := staking.ReclaimEscrow{
			Nonce:   acct.General.Nonce,
			Fee:     fee,
			Account: escrowSigner.Public(),
		}
		_ = escrow.Shares.FromInt64(amount)
		signedEscrow, err := staking.SignReclaimEscrow(signer, &escrow)
		if err != nil {
			return fmt.Errorf("failed to sign escrow: %w", err)
		}
		if err = st.ReclaimEscrow(ctx, signedEscrow); err != nil {
			return fmt.Errorf("failed to reclaim escrow: %w", err)
		}

		ch, sub, err := st.WatchEscrows(ctx)
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
				if _, ok := ev.(*staking.ReclaimEscrowEvent); ok {
					return nil
				}
			case <-ctx.Done():
				return nil
			}
		}
	})
}

func testStakingGas(
	ctx context.Context,
	signer signature.Signer,
	st staking.Backend,
	subtract bool,
	op func(*staking.Account, gas.Fee, int64) error,
) error {
	var amountOverBalance quantity.Quantity
	// This should be more than it is in the account.
	_ = amountOverBalance.FromInt64(1_000_000)

	var amountOk quantity.Quantity
	// This should be a reasonable amount that the account can pay.
	_ = amountOk.FromInt64(10)

	var amountLow quantity.Quantity
	// This amount gives a lower gas price than accepted by the validator.
	_ = amountLow.FromInt64(5)

	for _, t := range []struct {
		name      string
		fee       gas.Fee
		amount    int64
		checkOk   bool
		deliverOk bool
	}{
		// No fees.
		{"NoFees", gas.Fee{}, 50, false, false},
		// Free gas.
		{"FreeGas", gas.Fee{Gas: 10}, 50, false, false},
		// Gas price too low.
		{"LowGasPrice", gas.Fee{Amount: amountLow, Gas: 10}, 50, false, false},
		// Not enough gas.
		{"OutOfGas", gas.Fee{Amount: amountOk, Gas: 9}, 50, true, false},
		// No balance to pay for gas.
		{"NoBalanceForGas", gas.Fee{Amount: amountOverBalance, Gas: 10}, 50, false, false},
		// Enough balance to pay for gas, but not enough balance for operation
		// after you subtract the gas payment.
		{"NoBalanceForOp", gas.Fee{Amount: amountOk, Gas: 10}, 1000, true, false},
		// Successful operation.
		{"Success", gas.Fee{Amount: amountOk, Gas: 10}, 100, true, true},
	} {
		if err := testStakingGasOp(ctx, signer, st, t.fee, t.amount, t.checkOk, t.deliverOk, subtract, op); err != nil {
			return fmt.Errorf("%s: %w", t.name, err)
		}
	}

	return nil
}

func testStakingGasOp(
	ctx context.Context,
	signer signature.Signer,
	st staking.Backend,
	fee gas.Fee,
	amount int64,
	checkOk, deliverOk bool,
	subtract bool,
	op func(*staking.Account, gas.Fee, int64) error,
) error {
	// Fetch initial account info.
	acct, err := st.AccountInfo(ctx, signer.Public(), 0)
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
	newAcct, err := st.AccountInfo(ctx, signer.Public(), 0)
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
