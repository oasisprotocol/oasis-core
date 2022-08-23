package e2e

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	fileSigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/file"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/prettyprint"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/consensus"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/grpc"
	cmdSigner "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/signer"
	"github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/stake"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
)

const (
	// Init balance in the genesis block.
	initBalance = 1_000_000_000_000_000

	// Test transfer amount.
	transferAmount = 1000

	// Test burn amount.
	burnAmount = 2000

	// Test escrow amount.
	escrowAmount = 3000

	// Test reclaim escrow shares.
	reclaimEscrowShares = 1234

	// Test allowance amount.
	allowAmount = 1000

	// Test withdraw amount.
	withdrawAmount = 500

	// Transaction fee amount.
	feeAmount = 10

	// Transaction fee gas.
	feeGas = 10000

	// Testing source account public key (hex-encoded).
	srcPubkeyHex = "4ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35"

	// Testing escrow account public key (hex-encoded).
	escrowPubkeyHex = "6ea5328f943ef6f66daaed74cb0e99c3b1c45f76307b425003dbc7cb3638ed35"
)

var (
	// Testing source account address.
	srcAddress = api.NewAddress(signature.NewPublicKey(srcPubkeyHex))

	// Testing escrow account address.
	escrowAddress = api.NewAddress(signature.NewPublicKey(escrowPubkeyHex))

	// StakeCLI is the staking scenario.
	StakeCLI scenario.Scenario = &stakeCLIImpl{
		E2E: *NewE2E("stake-cli"),
	}

	qZero = mustInitQuantity(0)

	// We are the first who put stake into the escrow account, so the number of shares equals the
	// amount of base units in the escrow account.
	escrowShares int64 = escrowAmount
	// Since we are the only ones who put stake into the escrow account and there was no slashing,
	// we can expect the amount of reclaimed base units to equal the number of reclaimed escrow
	// shares.
	reclaimEscrowAmount int64 = reclaimEscrowShares
)

func mustInitQuantity(i int64) (q quantity.Quantity) {
	if err := q.FromInt64(i); err != nil {
		panic(fmt.Sprintf("FromInt64: %+v", err))
	}
	return
}

// Return a context with values of token's ticker symbol and token's value base-10 exponent.
func contextWithTokenInfo() context.Context {
	ctx := context.Background()
	ctx = context.WithValue(
		ctx,
		prettyprint.ContextKeyTokenSymbol,
		genesisTestHelpers.TestStakingTokenSymbol,
	)
	ctx = context.WithValue(
		ctx,
		prettyprint.ContextKeyTokenValueExponent,
		genesisTestHelpers.TestStakingTokenValueExponent,
	)
	return ctx
}

type stakeCLIImpl struct {
	E2E
}

func (sc *stakeCLIImpl) Clone() scenario.Scenario {
	return &stakeCLIImpl{
		E2E: sc.E2E.Clone(),
	}
}

func (sc *stakeCLIImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.E2E.Fixture()
	if err != nil {
		return nil, err
	}

	// We will mock epochs for reclaiming the escrow.
	f.Network.SetMockEpoch()
	f.Network.SetInsecureBeacon()

	// Enable some features in the staking system that we'll test.
	f.Network.StakingGenesis = &api.Genesis{
		Parameters: api.ConsensusParameters{
			CommissionScheduleRules: api.CommissionScheduleRules{
				RateChangeInterval: 10,
				RateBoundLead:      30,
				MaxRateSteps:       4,
				MaxBoundSteps:      12,
			},
			MaxAllowances: 32,
		},
	}

	return f, nil
}

func (sc *stakeCLIImpl) Run(childEnv *env.Env) error {
	// Generate beneficiary entity.
	beneficiaryEntityDir, err := childEnv.NewSubDir("beneficiary-entity")
	if err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	signerFactory, err := fileSigner.NewFactory(beneficiaryEntityDir.String(), signature.SignerEntity)
	if err != nil {
		return fmt.Errorf("failed to generate beneficiary entity: %w", err)
	}
	_, beneficiarySigner, err := entity.Generate(beneficiaryEntityDir.String(), signerFactory, nil)
	if err != nil {
		return fmt.Errorf("failed to generate beneficiary entity: %w", err)
	}
	beneficiaryAddress := api.NewAddress(beneficiarySigner.Public())

	// Start the network.
	if err = sc.Net.Start(); err != nil {
		return err
	}

	ctx := context.Background()
	sc.Logger.Info("waiting for nodes to register")
	if err = sc.Net.Controller().WaitNodesRegistered(ctx, 3); err != nil {
		return fmt.Errorf("waiting for nodes to register: %w", err)
	}
	sc.Logger.Info("nodes registered")

	cli := cli.New(childEnv, sc.Net, sc.Logger)

	// Common staking info.
	if err = sc.getInfo(childEnv); err != nil {
		return err
	}

	// List of account addresses.
	addresses, err := sc.listAccountAddresses(childEnv)
	if err != nil {
		return err
	}
	// In the genesis block, only one account should have a balance.
	if len(addresses) < 1 {
		return fmt.Errorf(
			"wrong number of accounts in initial list: %d, expected at least: %d. Accounts: %s",
			len(addresses), 1, addresses,
		)
	}

	// Ensure the source account address is in the list.
	var found bool
	for _, addr := range addresses {
		if bytes.Equal(addr[:], srcAddress[:]) {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("src account address not found in initial list: %s", srcAddress)
	}

	// Run the tests

	// Ensure converting public keys to staking account addresses works.
	pubkey2AddressTestVectors := []struct {
		publicKeyText string
		addressText   string
		expectError   bool
	}{
		{signature.NewPublicKey(srcPubkeyHex).String(), srcAddress.String(), false},
		{signature.NewPublicKey(escrowPubkeyHex).String(), escrowAddress.String(), false},
		// Empty public key.
		{"", "", true},
		// Invalid public key.
		{"BadPubKey=", "", true},
	}
	sc.Logger.Info("test converting public keys to staking account addresses")
	for _, vector := range pubkey2AddressTestVectors {
		err = sc.testPubkey2Address(childEnv, vector.publicKeyText, vector.addressText)
		if err != nil && !vector.expectError {
			return fmt.Errorf("unexpected pubkey2address error: %w", err)
		}
		if err == nil && vector.expectError {
			return fmt.Errorf("pubkey2address for public key '%s' should error", vector.publicKeyText)
		}
	}

	// Ensure validating account addresses works.
	addressWithSpaces := "oasis1 qzm9 xjzq gsdc zc64 v3zp 8jkf ekx7 n8kh y502 pxwq"
	validateAddressTestVectors := []struct {
		addressText string
		expectError bool
	}{
		{srcAddress.String(), false},
		{escrowAddress.String(), false},
		// Empty address should be invalid.
		{"", true},
		// Address with spaces should be invalid.
		{addressWithSpaces, true},
		// Same address without spaces should be valid.
		{strings.ReplaceAll(addressWithSpaces, " ", ""), false},
		// Hex-formatted public keys should be invalid.
		{srcPubkeyHex, true},
		{escrowPubkeyHex, true},
	}
	sc.Logger.Info("test validation of staking account addresses")
	for _, vector := range validateAddressTestVectors {
		err = sc.testValidateAddress(childEnv, vector.addressText)
		if err != nil && !vector.expectError {
			return fmt.Errorf("unexpected validate_address error: %w", err)
		}
		if err == nil && vector.expectError {
			return fmt.Errorf("validate_address for address '%s' should error", vector.addressText)
		}
	}

	// Transfer
	if err = sc.testTransfer(childEnv, cli, srcAddress, beneficiaryAddress); err != nil {
		return fmt.Errorf("error while running Transfer test: %w", err)
	}

	// Burn
	if err = sc.testBurn(childEnv, cli, srcAddress); err != nil {
		return fmt.Errorf("error while running Burn test: %w", err)
	}

	// Escrow
	if err = sc.testEscrow(childEnv, cli, srcAddress, escrowAddress); err != nil {
		return fmt.Errorf("error while running Escrow test: %w", err)
	}

	// ReclaimEscrow
	if err = sc.testReclaimEscrow(childEnv, cli, srcAddress, escrowAddress); err != nil {
		return fmt.Errorf("error while running ReclaimEscrow test: %w", err)
	}

	// AmendCommissionSchedule
	if err = sc.testAmendCommissionSchedule(childEnv, cli, srcAddress); err != nil {
		return fmt.Errorf("error while running AmendCommissionSchedule test: %w", err)
	}

	// Allow and Withdraw
	if err = sc.testAllowWithdraw(childEnv, cli, srcAddress, beneficiaryAddress, beneficiaryEntityDir.String()); err != nil {
		return fmt.Errorf("error while running AllowWithdraw test: %w", err)
	}

	// Stop the network.
	sc.Logger.Info("stopping the network")
	sc.Net.Stop()

	return nil
}

func (sc *stakeCLIImpl) testPubkey2Address(childEnv *env.Env, publicKeyText, addressText string) error {
	args := []string{
		"stake", "pubkey2address",
		"--" + stake.CfgPublicKey, publicKeyText,
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "info", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("failed to convert public key to address: error: %w output: %s", err, out.String())
	}

	var addr api.Address
	if err = addr.UnmarshalText(bytes.TrimSpace(out.Bytes())); err != nil {
		return err
	}

	if addr.String() != addressText {
		return fmt.Errorf("pubkey2address converted public key %s to address %s (expected address: %s)",
			publicKeyText, addr, addressText,
		)
	}

	return nil
}

func (sc *stakeCLIImpl) testValidateAddress(childEnv *env.Env, addressText string) error {
	args := []string{
		"stake", "account", "validate_address",
		"--verbose",
		"--" + stake.CfgAccountAddr, addressText,
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "info", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("failed to validate account address: error: %w output: %s", err, out.String())
	}

	return nil
}

// testTransfer tests transfer of transferAmount base units from src to dst.
func (sc *stakeCLIImpl) testTransfer(childEnv *env.Env, cli *cli.Helpers, src, dst api.Address) error {
	srcNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	dstNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for destination account %s: %w", dst, err)
	}
	ctx := contextWithTokenInfo()

	unsignedTransferTxPath := filepath.Join(childEnv.Dir(), "stake_transfer_unsigned.cbor")
	if err = sc.genUnsignedTransferTx(childEnv, transferAmount, srcNonce, dst, unsignedTransferTxPath); err != nil {
		return fmt.Errorf("genUnsignedTransferTx: %w", err)
	}
	_, teSigner, err := entity.TestEntity()
	if err != nil {
		return fmt.Errorf("obtain test entity: %w", err)
	}

	expectedGasEstimate := transaction.Gas(262)
	gas, err := cli.Consensus.EstimateGas(unsignedTransferTxPath, teSigner.Public())
	if err != nil {
		return fmt.Errorf("estimate gas on unsigned transfer tx: %w", err)
	}
	if gas != expectedGasEstimate {
		return fmt.Errorf("wrong gas estimate: expected %d, got %d", expectedGasEstimate, gas)
	}

	transferTxPath := filepath.Join(childEnv.Dir(), "stake_transfer.json")
	if err = sc.genTransferTx(childEnv, transferAmount, srcNonce, dst, transferTxPath); err != nil {
		return err
	}
	if err = sc.showTx(childEnv, transferTxPath); err != nil {
		return err
	}

	expectedSrcBalance := mustInitQuantity(initBalance)
	if err = sc.checkGeneralAccount(ctx, childEnv, src, &api.GeneralAccount{
		Balance: expectedSrcBalance, Nonce: srcNonce,
	}); err != nil {
		return err
	}
	if err = sc.checkGeneralAccount(
		ctx, childEnv, dst, &api.GeneralAccount{Balance: qZero, Nonce: dstNonce},
	); err != nil {
		return err
	}

	if err = cli.Consensus.SubmitTx(transferTxPath); err != nil {
		return err
	}

	expectedSrcBalance = mustInitQuantity(initBalance - transferAmount - feeAmount)
	if err = sc.checkGeneralAccount(ctx, childEnv, src, &api.GeneralAccount{
		Balance: expectedSrcBalance, Nonce: srcNonce + 1,
	},
	); err != nil {
		return err
	}
	expectedDstBalance := mustInitQuantity(transferAmount)
	if err = sc.checkGeneralAccount(ctx, childEnv, dst, &api.GeneralAccount{
		Balance: expectedDstBalance, Nonce: dstNonce,
	},
	); err != nil {
		return err
	}

	accounts, err := sc.listAccountAddresses(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 2 {
		return fmt.Errorf("post-transfer stake list wrong number of accounts: %d, expected at least: %d. Accounts: %s", len(accounts), 2, accounts)
	}

	return nil
}

// testBurn tests burning of burnAmount base units owned by src.
func (sc *stakeCLIImpl) testBurn(childEnv *env.Env, cli *cli.Helpers, src api.Address) error {
	srcNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	ctx := contextWithTokenInfo()

	burnTxPath := filepath.Join(childEnv.Dir(), "stake_burn.json")
	if err = sc.genBurnTx(childEnv, burnAmount, srcNonce, burnTxPath); err != nil {
		return err
	}
	if err = sc.showTx(childEnv, burnTxPath); err != nil {
		return err
	}

	if err = cli.Consensus.SubmitTx(burnTxPath); err != nil {
		return err
	}

	expectedBalance := mustInitQuantity(initBalance - transferAmount - burnAmount - 2*feeAmount)
	if err = sc.checkGeneralAccount(
		ctx, childEnv, src, &api.GeneralAccount{Balance: expectedBalance, Nonce: srcNonce + 1},
	); err != nil {
		return err
	}
	accounts, err := sc.listAccountAddresses(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 2 {
		return fmt.Errorf("post-burn stake list wrong number of accounts: %d, expected at least: %d", len(accounts), 2)
	}

	return nil
}

// testEscrow tests escrowing escrowAmount base units from src to dst.
func (sc *stakeCLIImpl) testEscrow(childEnv *env.Env, cli *cli.Helpers, src, escrow api.Address) error {
	srcNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	ctx := contextWithTokenInfo()

	escrowTxPath := filepath.Join(childEnv.Dir(), "stake_escrow.json")
	if err = sc.genEscrowTx(childEnv, escrowAmount, srcNonce, escrow, escrowTxPath); err != nil {
		return err
	}
	if err = sc.showTx(childEnv, escrowTxPath); err != nil {
		return err
	}

	if err = cli.Consensus.SubmitTx(escrowTxPath); err != nil {
		return err
	}

	expectedGeneralBalance := mustInitQuantity(
		initBalance - transferAmount - burnAmount - escrowAmount - 3*feeAmount,
	)
	if err = sc.checkGeneralAccount(
		ctx, childEnv, src, &api.GeneralAccount{Balance: expectedGeneralBalance, Nonce: srcNonce + 1},
	); err != nil {
		return err
	}
	expectedEscrowActiveBalance := mustInitQuantity(escrowAmount)
	expectedActiveShares := mustInitQuantity(escrowShares)
	if err = sc.checkEscrowAccountSharePool(
		ctx, childEnv, escrow, "Active", &api.SharePool{
			Balance: expectedEscrowActiveBalance, TotalShares: expectedActiveShares,
		},
	); err != nil {
		return err
	}

	accounts, err := sc.listAccountAddresses(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 3 {
		return fmt.Errorf("post-escrow stake list wrong number of accounts: %d, expected at least: %d", len(accounts), 3)
	}

	return nil
}

// testReclaimEscrow test reclaiming reclaimEscrowShares shares from an escrow account.
func (sc *stakeCLIImpl) testReclaimEscrow(childEnv *env.Env, cli *cli.Helpers, src, escrow api.Address) error {
	srcNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	ctx := contextWithTokenInfo()

	reclaimEscrowTxPath := filepath.Join(childEnv.Dir(), "stake_reclaim_escrow.json")
	if err = sc.genReclaimEscrowTx(childEnv, reclaimEscrowShares, srcNonce, escrow, reclaimEscrowTxPath); err != nil {
		return err
	}
	if err = sc.showTx(childEnv, reclaimEscrowTxPath); err != nil {
		return err
	}
	if err = sc.checkEscrowAccountSharePool(
		ctx, childEnv, escrow, "Debonding", &api.SharePool{Balance: qZero, TotalShares: qZero},
	); err != nil {
		return err
	}

	if err = cli.Consensus.SubmitTx(reclaimEscrowTxPath); err != nil {
		return err
	}

	expectedEscrowDebondingBalance := mustInitQuantity(reclaimEscrowAmount)
	expectedEscrowDebondingShares := mustInitQuantity(reclaimEscrowShares)
	if err = sc.checkEscrowAccountSharePool(
		ctx, childEnv, escrow, "Debonding", &api.SharePool{
			Balance: expectedEscrowDebondingBalance, TotalShares: expectedEscrowDebondingShares,
		},
	); err != nil {
		return err
	}

	expectedEscrowActiveBalance := mustInitQuantity(escrowAmount - reclaimEscrowAmount)
	expectedEscrowActiveShares := mustInitQuantity(escrowShares - reclaimEscrowShares)
	if err = sc.checkEscrowAccountSharePool(
		ctx, childEnv, escrow, "Active", &api.SharePool{
			Balance: expectedEscrowActiveBalance, TotalShares: expectedEscrowActiveShares,
		},
	); err != nil {
		return err
	}

	// Advance epochs to trigger reclaim processing.
	if err = sc.Net.Controller().SetEpoch(context.Background(), 1); err != nil {
		return fmt.Errorf("failed to set epoch: %w", err)
	}

	if err = sc.checkEscrowAccountSharePool(
		ctx, childEnv, escrow, "Debonding", &api.SharePool{Balance: qZero, TotalShares: qZero}); err != nil {
		return err
	}

	expectedGeneralBalance := mustInitQuantity(
		initBalance - transferAmount - burnAmount - escrowAmount + reclaimEscrowAmount - 4*feeAmount,
	)
	if err = sc.checkGeneralAccount(
		ctx, childEnv, src, &api.GeneralAccount{Balance: expectedGeneralBalance, Nonce: srcNonce + 1},
	); err != nil {
		return err
	}

	accounts, err := sc.listAccountAddresses(childEnv)
	if err != nil {
		return err
	}
	if len(accounts) < 3 {
		return fmt.Errorf("post-reclaim-escrow stake list wrong number of accounts: %d, expected: %d", len(accounts), 3)
	}

	return nil
}

func (sc *stakeCLIImpl) testAmendCommissionSchedule(childEnv *env.Env, cli *cli.Helpers, src api.Address) error {
	rates := []api.CommissionRateStep{
		{
			Start: 40,
			Rate:  mustInitQuantity(50_000),
		},
		{
			Start: 60,
			Rate:  mustInitQuantity(40_000),
		},
		{
			Start: 80,
			Rate:  mustInitQuantity(30_000),
		},
	}
	bounds := []api.CommissionRateBoundStep{
		{
			Start:   40,
			RateMin: mustInitQuantity(0),
			RateMax: mustInitQuantity(100_000),
		},
		{
			Start:   80,
			RateMin: mustInitQuantity(0),
			RateMax: mustInitQuantity(50_000),
		},
	}
	srcNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	ctx := contextWithTokenInfo()

	amendCommissionScheduleTxPath := filepath.Join(childEnv.Dir(), "amend_commission_schedule.json")
	if err := sc.genAmendCommissionScheduleTx(childEnv, srcNonce, &api.CommissionSchedule{
		Rates:  rates,
		Bounds: bounds,
	}, amendCommissionScheduleTxPath); err != nil {
		return err
	}
	if err := sc.showTx(childEnv, amendCommissionScheduleTxPath); err != nil {
		return err
	}

	if err := cli.Consensus.SubmitTx(amendCommissionScheduleTxPath); err != nil {
		return err
	}

	if err := sc.checkCommissionScheduleRates(ctx, childEnv, src, rates); err != nil {
		return err
	}
	if err := sc.checkCommissionScheduleRateBounds(ctx, childEnv, src, bounds); err != nil {
		return err
	}

	return nil
}

// testAllowWithdraw tests setting an allowance and withdrawing.
func (sc *stakeCLIImpl) testAllowWithdraw(childEnv *env.Env, cli *cli.Helpers, src, beneficiary api.Address, beneficiaryEntityDir string) error {
	srcNonce, err := sc.getAccountNonce(childEnv, src)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	beneficiaryNonce, err := sc.getAccountNonce(childEnv, beneficiary)
	if err != nil {
		return fmt.Errorf("getAccountNonce for source account %s: %w", src, err)
	}
	ctx := contextWithTokenInfo()

	// Set allowance.
	allowTxPath := filepath.Join(childEnv.Dir(), "stake_allow.json")
	if err = sc.genAllowTx(childEnv, allowAmount, srcNonce, beneficiary, allowTxPath); err != nil {
		return err
	}
	if err = sc.showTx(childEnv, allowTxPath); err != nil {
		return err
	}

	if err = cli.Consensus.SubmitTx(allowTxPath); err != nil {
		return fmt.Errorf("failed to submit Allow tx: %w", err)
	}

	// Withdraw.
	withdrawTxPath := filepath.Join(childEnv.Dir(), "stake_withdraw.json")
	if err = sc.genWithdrawTx(childEnv, withdrawAmount, beneficiaryNonce, src, beneficiaryEntityDir, withdrawTxPath); err != nil {
		return err
	}
	if err = sc.showTx(childEnv, withdrawTxPath); err != nil {
		return err
	}

	if err = cli.Consensus.SubmitTx(withdrawTxPath); err != nil {
		return fmt.Errorf("failed to submit Withdraw tx: %w", err)
	}

	// Check source general balance.
	expectedGeneralBalance := mustInitQuantity(
		initBalance - transferAmount - burnAmount - escrowAmount + reclaimEscrowAmount - withdrawAmount - 6*feeAmount,
	)
	if err = sc.checkGeneralAccount(ctx, childEnv, src, &api.GeneralAccount{
		Balance: expectedGeneralBalance,
		Nonce:   srcNonce + 1,
		Allowances: map[api.Address]quantity.Quantity{
			beneficiary: mustInitQuantity(allowAmount - withdrawAmount),
		},
	}); err != nil {
		return err
	}
	// Check beneficiary general balance.
	expectedGeneralBalance = mustInitQuantity(
		transferAmount - feeAmount + withdrawAmount,
	)
	if err = sc.checkGeneralAccount(
		ctx, childEnv, beneficiary, &api.GeneralAccount{Balance: expectedGeneralBalance, Nonce: 1},
	); err != nil {
		return err
	}

	return nil
}

func (sc *stakeCLIImpl) getInfo(childEnv *env.Env) error {
	sc.Logger.Info("querying common staking info")
	args := []string{
		"stake", "info",
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "info", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return fmt.Errorf("failed to query common staking info: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) listAccountAddresses(childEnv *env.Env) ([]api.Address, error) {
	sc.Logger.Info("listing all account addresses")
	args := []string{
		"stake", "list",
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}
	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "list", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return nil, fmt.Errorf("failed to list account addresses: error: %w output: %s",
			err, out.String(),
		)
	}
	addressesText := strings.Split(out.String(), "\n")

	var addresses []api.Address
	for _, addrText := range addressesText {
		// Ignore last newline.
		if addrText == "" {
			continue
		}

		var addr api.Address
		if err = addr.UnmarshalText([]byte(addrText)); err != nil {
			return nil, fmt.Errorf("failed to unmarshal account address: %w", err)
		}
		addresses = append(addresses, addr)
	}

	return addresses, nil
}

func (sc *stakeCLIImpl) getAccountInfo(childEnv *env.Env, src api.Address) (string, error) {
	sc.Logger.Info("checking account balance", stake.CfgAccountAddr, src.String())
	args := []string{
		"stake", "account", "info",
		"--" + stake.CfgAccountAddr, src.String(),
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "info", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return "", fmt.Errorf("failed to check account info: error: %w output: %s", err, out.String())
	}

	return out.String(), nil
}

func (sc *stakeCLIImpl) getAccountNonce(childEnv *env.Env, src api.Address) (uint64, error) {
	sc.Logger.Info("checking account nonce", stake.CfgAccountAddr, src.String())
	args := []string{
		"stake", "account", "nonce",
		"--" + stake.CfgAccountAddr, src.String(),
		"--" + grpc.CfgAddress, "unix:" + sc.Net.Validators()[0].SocketPath(),
	}

	out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "info", sc.Net.Config().NodeBinary, args)
	if err != nil {
		return 0, fmt.Errorf("failed to check account nonce: error: %w output: %s", err, out.String())
	}

	nonce, err := strconv.ParseUint(strings.TrimSpace(out.String()), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse account nonce: error: %w output: %s", err, out.String())
	}

	return nonce, nil
}

func (sc *stakeCLIImpl) checkGeneralAccount(
	ctx context.Context,
	childEnv *env.Env,
	src api.Address,
	expectedAccount *api.GeneralAccount,
) error {
	accountInfo, err := sc.getAccountInfo(childEnv, src)
	if err != nil {
		return err
	}

	var b bytes.Buffer
	fmt.Fprint(&b, "Available: ")
	token.PrettyPrintAmount(ctx, expectedAccount.Balance, &b)
	regexPattern := regexp.QuoteMeta(b.String())
	match := regexp.MustCompile(regexPattern).FindStringSubmatch(accountInfo)
	if match == nil {
		return fmt.Errorf(
			"checkGeneralAccount: couldn't find expected substring:\n\n%s\n\nin account info's output:\n\n%s",
			b.String(), accountInfo,
		)
	}

	nonce := fmt.Sprintf("Nonce: %d", expectedAccount.Nonce)
	match = regexp.MustCompile(nonce).FindStringSubmatch(accountInfo)
	if match == nil {
		return fmt.Errorf(
			"checkGeneralAccount: couldn't find expected substring:\n\n%s\n\nin account info's output:\n\n%s",
			nonce, accountInfo,
		)
	}

	return nil
}

func (sc *stakeCLIImpl) checkEscrowAccountSharePool(
	ctx context.Context,
	childEnv *env.Env,
	src api.Address,
	sharePoolName string,
	expectedSharePool *api.SharePool,
) error {
	accountInfo, err := sc.getAccountInfo(childEnv, src)
	if err != nil {
		return err
	}
	balanceZero := expectedSharePool.Balance.IsZero()

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s Delegations to this Account:\n", sharePoolName)
	if !balanceZero {
		prefix := "  "
		fmt.Fprintf(&b, "%sTotal: ", prefix)
		token.PrettyPrintAmount(ctx, expectedSharePool.Balance, &b)
		fmt.Fprintf(&b, " (%s shares)", expectedSharePool.TotalShares)
	}
	regexPattern := regexp.QuoteMeta(b.String())
	match := regexp.MustCompile(regexPattern).FindStringSubmatch(accountInfo)
	switch {
	case !balanceZero && match == nil:
		return fmt.Errorf(
			"checkEscrowAccountSharePool: couldn't find expected substring:\n\n%s\n\nin account info's output:\n\n%s",
			b.String(), accountInfo,
		)
	case balanceZero && match != nil:
		return fmt.Errorf(
			"checkEscrowAccountSharePool: shouldn't find expected substring:\n\n%s\n\nin account info's output:\n\n%s",
			b.String(), accountInfo,
		)
	default:
		return nil
	}
}

func (sc *stakeCLIImpl) checkCommissionScheduleRates(
	ctx context.Context,
	childEnv *env.Env,
	src api.Address,
	expectedRates []api.CommissionRateStep,
) error {
	accountInfo, err := sc.getAccountInfo(childEnv, src)
	if err != nil {
		return err
	}

	for i, expectedRate := range expectedRates {
		var b bytes.Buffer
		ctx = context.WithValue(ctx, prettyprint.ContextKeyCommissionScheduleIndex, i)
		expectedRate.PrettyPrint(ctx, "    ", &b)
		regexPattern := regexp.QuoteMeta(b.String())
		match := regexp.MustCompile(regexPattern).FindStringSubmatch(accountInfo)
		if match == nil {
			return fmt.Errorf(
				"checkCommissionScheduleRates: couldn't find an expected substring:\n\n%s\n\nin account info's output:\n\n%s",
				b.String(), accountInfo,
			)
		}
	}

	return nil
}

func (sc *stakeCLIImpl) checkCommissionScheduleRateBounds(
	ctx context.Context,
	childEnv *env.Env,
	src api.Address,
	expectedRateBounds []api.CommissionRateBoundStep,
) error {
	accountInfo, err := sc.getAccountInfo(childEnv, src)
	if err != nil {
		return err
	}

	for i, expectedBound := range expectedRateBounds {
		var b bytes.Buffer
		ctx = context.WithValue(ctx, prettyprint.ContextKeyCommissionScheduleIndex, i)
		expectedBound.PrettyPrint(ctx, "    ", &b)
		regexPattern := regexp.QuoteMeta(b.String())
		match := regexp.MustCompile(regexPattern).FindStringSubmatch(accountInfo)
		if match == nil {
			return fmt.Errorf(
				"checkCommissionScheduleRateBounds: couldn't find an expected substring:\n\n%s\n\nin account info's output:\n\n%s",
				b.String(), accountInfo,
			)
		}
	}

	return nil
}

func (sc *stakeCLIImpl) showTx(childEnv *env.Env, txPath string) error {
	sc.Logger.Info("pretty printing generated transaction")

	args := []string{
		"consensus", "show_tx",
		"--" + consensus.CfgTxFile, txPath,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "show_tx", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("showTx: failed to show tx: error: %w, output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genUnsignedTransferTx(childEnv *env.Env, amount int, nonce uint64, dst api.Address, txPath string) error {
	sc.Logger.Info("generating unsigned stake transfer tx", stake.CfgTransferDestination, dst)

	args := []string{
		"stake", "account", "gen_transfer",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgTransferDestination, dst.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + consensus.CfgTxUnsigned,
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_transfer", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genUnsignedTransferTx: failed to generate transfer tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genTransferTx(childEnv *env.Env, amount int, nonce uint64, dst api.Address, txPath string) error {
	sc.Logger.Info("generating stake transfer tx", stake.CfgTransferDestination, dst)

	args := []string{
		"stake", "account", "gen_transfer",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgTransferDestination, dst.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_transfer", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genTransferTx: failed to generate transfer tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genBurnTx(childEnv *env.Env, amount int, nonce uint64, txPath string) error {
	sc.Logger.Info("generating stake burn tx")

	args := []string{
		"stake", "account", "gen_burn",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_burn", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genBurnTx: failed to generate burn tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genEscrowTx(childEnv *env.Env, amount int, nonce uint64, escrow api.Address, txPath string) error {
	sc.Logger.Info("generating stake escrow tx", stake.CfgEscrowAccount, escrow)

	args := []string{
		"stake", "account", "gen_escrow",
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgEscrowAccount, escrow.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_escrow", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genEscrowTx: failed to generate escrow tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genReclaimEscrowTx(childEnv *env.Env, shares int, nonce uint64, escrow api.Address, txPath string) error {
	sc.Logger.Info("generating stake reclaim escrow tx", stake.CfgEscrowAccount, escrow)

	args := []string{
		"stake", "account", "gen_reclaim_escrow",
		"--" + stake.CfgShares, strconv.Itoa(shares),
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgEscrowAccount, escrow.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_reclaim_escrow", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genReclaimEscrowTx: failed to generate reclaim escrow tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genAmendCommissionScheduleTx(childEnv *env.Env, nonce uint64, cs *api.CommissionSchedule, txPath string) error {
	sc.Logger.Info("generating stake amend commission schedule tx", "commission_schedule", cs)

	args := []string{
		"stake", "account", "gen_amend_commission_schedule",
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	for _, step := range cs.Rates {
		args = append(args, "--"+stake.CfgCommissionScheduleRates, fmt.Sprintf("%d/%d", step.Start, step.Rate.ToBigInt()))
	}
	for _, step := range cs.Bounds {
		args = append(args, "--"+stake.CfgCommissionScheduleBounds, fmt.Sprintf("%d/%d/%d", step.Start, step.RateMin.ToBigInt(), step.RateMax.ToBigInt()))
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_amend_commission_schedule", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genAmendCommissionScheduleTx: failed to generate amend commission schedule tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genAllowTx(childEnv *env.Env, amount int, nonce uint64, beneficiary api.Address, txPath string) error {
	sc.Logger.Info("generating stake allow tx", stake.CfgAllowBeneficiary, beneficiary)

	args := []string{
		"stake", "account", "gen_allow",
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgAllowAmountChange, strconv.Itoa(amount),
		"--" + stake.CfgAllowBeneficiary, beneficiary.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + flags.CfgDebugTestEntity,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_allow", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genAllowTx: failed to generate allow tx: error: %w output: %s", err, out.String())
	}
	return nil
}

func (sc *stakeCLIImpl) genWithdrawTx(childEnv *env.Env, amount int, nonce uint64, src api.Address, entityDir, txPath string) error {
	sc.Logger.Info("generating stake withdraw tx", stake.CfgWithdrawSource, src)

	args := []string{
		"stake", "account", "gen_withdraw",
		"--" + consensus.CfgTxNonce, strconv.FormatUint(nonce, 10),
		"--" + consensus.CfgTxFile, txPath,
		"--" + stake.CfgAmount, strconv.Itoa(amount),
		"--" + stake.CfgWithdrawSource, src.String(),
		"--" + consensus.CfgTxFeeAmount, strconv.Itoa(feeAmount),
		"--" + consensus.CfgTxFeeGas, strconv.Itoa(feeGas),
		"--" + flags.CfgDebugDontBlameOasis,
		"--" + common.CfgDebugAllowTestKeys,
		"--" + cmdSigner.CfgCLISignerDir, entityDir,
		"--" + flags.CfgGenesisFile, sc.Net.GenesisPath(),
	}
	if out, err := cli.RunSubCommandWithOutput(childEnv, sc.Logger, "gen_withdraw", sc.Net.Config().NodeBinary, args); err != nil {
		return fmt.Errorf("genAllowTx: failed to generate withdraw tx: error: %w output: %s", err, out.String())
	}
	return nil
}
