package e2e

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	tmbeacon "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/beacon"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

var (
	MinTransactBalance scenario.Scenario = &minTransactBalanceImpl{
		E2E: *NewE2E("min-transact-balance"),
	}
	a1Signer = memorySigner.NewTestSigner("e2e/min-transact-balance: a1")
	a1Addr   = staking.NewAddress(a1Signer.Public())
)

type minTransactBalanceImpl struct {
	E2E
}

func (mtb *minTransactBalanceImpl) signAndSubmitTx(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	signed, err := transaction.Sign(signer, tx)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	if mtb.Net.Controller().Consensus.SubmitTx(ctx, signed) != nil {
		return fmt.Errorf("submit tx: %w", err)
	}
	return nil
}

func (mtb *minTransactBalanceImpl) signAndSubmitTxShouldFail(ctx context.Context, signer signature.Signer, tx *transaction.Transaction) error {
	signed, err := transaction.Sign(signer, tx)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	err = mtb.Net.Controller().Consensus.SubmitTx(ctx, signed)
	if err == nil {
		return fmt.Errorf("transaction succeeded but should not have")
	}
	mtb.Logger.Info("transaction failed as expected",
		"err", err,
	)
	return nil
}

func (mtb *minTransactBalanceImpl) fundFromTestEntity(ctx context.Context, nonce uint64, to staking.Address, amount uint64) error {
	_, teSigner, err := entity.TestEntity()
	if err != nil {
		return fmt.Errorf("test entity: %w", err)
	}
	if err = mtb.signAndSubmitTx(ctx, teSigner, staking.NewTransferTx(nonce, &transaction.Fee{
		Gas: 1300,
	}, &staking.Transfer{
		To:     to,
		Amount: *quantity.NewFromUint64(amount),
	})); err != nil {
		return err
	}
	return nil
}

func (mtb *minTransactBalanceImpl) getAccountAndCheckNonce(ctx context.Context, addr staking.Address, expected uint64) (*staking.Account, error) {
	query := staking.OwnerQuery{
		Owner:  addr,
		Height: consensus.HeightLatest,
	}
	acct, err := mtb.Net.Controller().Staking.Account(ctx, &query)
	if err != nil {
		return nil, fmt.Errorf("account: %w", err)
	}
	return acct, nil
}

func (mtb *minTransactBalanceImpl) Clone() scenario.Scenario {
	return &minTransactBalanceImpl{
		E2E: mtb.E2E.Clone(),
	}
}

func (mtb *minTransactBalanceImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := mtb.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	beaconSignerAddr := staking.NewAddress(tmbeacon.TestSigner.Public())
	f.Network.StakingGenesis = &staking.Genesis{
		Parameters: staking.ConsensusParameters{
			MinTransactBalance: *quantity.NewFromUint64(1000),
		},
		TotalSupply: *quantity.NewFromUint64(1000),
		Ledger: map[staking.Address]*staking.Account{
			beaconSignerAddr: {
				General: staking.GeneralAccount{
					Balance: *quantity.NewFromUint64(1000),
				},
			},
		},
	}

	// Use mock epoch so we can test node re-registration.
	f.Network.SetMockEpoch()

	return f, nil
}

func (mtb *minTransactBalanceImpl) Run(childEnv *env.Env) error {
	// Start the network
	if err := mtb.Net.Start(); err != nil {
		return err
	}

	ctx := context.Background()

	mtb.Logger.Info("waiting for network to come up")
	if err := mtb.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("WaitNodesRegistered: %w", err)
	}

	var teNonce uint64
	for i, validator := range mtb.Net.Validators() {
		mtb.Logger.Info("funding validator",
			"validator_index", i,
		)
		identity, err := validator.LoadIdentity()
		if err != nil {
			return fmt.Errorf("funding validator %d LoadIdentity: %w", i, err)
		}
		nodeAddr := staking.NewAddress(identity.NodeSigner.Public())
		if err = mtb.fundFromTestEntity(ctx, teNonce, nodeAddr, 1000); err != nil {
			return fmt.Errorf("funding validator %d: %w", i, err)
		}
		teNonce++
	}

	// Advance epoch to make sure node can re-register.
	mtb.Logger.Info("moving to epoch 1")
	if err := mtb.Net.Controller().SetEpoch(ctx, 1); err != nil {
		return fmt.Errorf("SetEpoch 1: %w", err)
	}
	// In the genesis file, nodes are registered to expire at epoch 1, which
	// should make it impossible to elect validators for epoch 2 if they never
	// re-register successfully.
	mtb.Logger.Info("moving to epoch 2")
	if err := mtb.Net.Controller().SetEpoch(ctx, 2); err != nil {
		return fmt.Errorf("SetEpoch 2: %w", err)
	}
	mtb.Logger.Info("epoch transitions succeeded")

	// Start with no account.
	mtb.Logger.Info("checking nonce")
	var a1Nonce uint64
	if _, err := mtb.getAccountAndCheckNonce(ctx, a1Addr, a1Nonce); err != nil {
		return fmt.Errorf("a1 before burn below min: %w", err)
	}

	// Try a transaction with no balance.
	mtb.Logger.Info("burning below min")
	if err := mtb.signAndSubmitTxShouldFail(ctx, a1Signer, staking.NewBurnTx(a1Nonce, &transaction.Fee{
		Gas: 1300,
	}, &staking.Burn{
		Amount: *quantity.NewFromUint64(0),
	})); err != nil {
		return fmt.Errorf("burn below min: %w", err)
	}

	// Account should not be created as a result.
	mtb.Logger.Info("checking nonce")
	if _, err := mtb.getAccountAndCheckNonce(ctx, a1Addr, a1Nonce); err != nil {
		return fmt.Errorf("a1 after burn below min: %w", err)
	}

	// Bring account up to minimum balance.
	mtb.Logger.Info("bringing account up to min")
	if err := mtb.fundFromTestEntity(ctx, teNonce, a1Addr, 1000); err != nil {
		return fmt.Errorf("bringup: %w", err)
	}
	teNonce++

	// Try a transaction at minimum balance.
	mtb.Logger.Info("burning at min")
	if err := mtb.signAndSubmitTx(ctx, a1Signer, staking.NewBurnTx(a1Nonce, &transaction.Fee{
		Gas: 1300,
	}, &staking.Burn{
		Amount: *quantity.NewFromUint64(0),
	})); err != nil {
		return fmt.Errorf("burn at min: %w", err)
	}
	a1Nonce++

	// Nonce should go up.
	mtb.Logger.Info("checking nonce")
	if _, err := mtb.getAccountAndCheckNonce(ctx, a1Addr, a1Nonce); err != nil {
		return fmt.Errorf("a1 after burn at min: %w", err)
	}

	// Try a transaction with fee that would bring balance below minimum.
	mtb.Logger.Info("burning with fee that would bring an account below min")
	if err := mtb.signAndSubmitTxShouldFail(ctx, a1Signer, staking.NewBurnTx(a1Nonce, &transaction.Fee{
		Gas:    1300,
		Amount: *quantity.NewFromUint64(1),
	}, &staking.Burn{
		Amount: *quantity.NewFromUint64(0),
	})); err != nil {
		return fmt.Errorf("burn with fee: %w", err)
	}

	// Nonce should stay the same.
	mtb.Logger.Info("checking nonce")
	if _, err := mtb.getAccountAndCheckNonce(ctx, a1Addr, a1Nonce); err != nil {
		return fmt.Errorf("a1 after burn with fee: %w", err)
	}

	// Bring up the balance some more.
	mtb.Logger.Info("brining account up above min")
	if err := mtb.fundFromTestEntity(ctx, teNonce, a1Addr, 1); err != nil {
		return fmt.Errorf("extra: %w", err)
	}

	// Try a transaction that fails.
	mtb.Logger.Info("burning in a way that would fail")
	if err := mtb.signAndSubmitTxShouldFail(ctx, a1Signer, staking.NewBurnTx(a1Nonce, &transaction.Fee{
		Gas:    1300,
		Amount: *quantity.NewFromUint64(1),
	}, &staking.Burn{
		Amount: *quantity.NewFromUint64(2),
	})); err != nil {
		return fmt.Errorf("burn that fails: %w", err)
	}
	a1Nonce++

	// Nonce should go up.
	mtb.Logger.Info("checking nonce")
	a1Acct, err := mtb.getAccountAndCheckNonce(ctx, a1Addr, a1Nonce)
	if err != nil {
		return fmt.Errorf("a1 after burn that fails: %w", err)
	}

	// Failed transaction should have no effect, but fee should be taken.
	balanceRef := quantity.NewFromUint64(1000)
	if a1Acct.General.Balance.Cmp(balanceRef) != 0 {
		return fmt.Errorf("a1 after burn that fails wrong balance %v, expected %v", a1Acct.General.Balance, balanceRef)
	}

	return nil
}
