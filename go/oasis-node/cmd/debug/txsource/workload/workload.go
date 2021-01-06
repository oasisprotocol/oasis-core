package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	flag "github.com/spf13/pflag"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/logging"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/api/transaction"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

const (
	maxSubmissionRetryElapsedTime = 120 * time.Second

	fundAccountAmount = 10000000000
)

// ByName is the registry of workloads that you can access with `--workload <name>` on the command line.
var ByName = map[string]Workload{
	NameCommission:   Commission,
	NameDelegation:   Delegation,
	NameOversized:    Oversized,
	NameParallel:     Parallel,
	NameQueries:      Queries,
	NameRegistration: Registration,
	NameRuntime:      Runtime,
	NameTransfer:     Transfer,
	NameGovernance:   Governance,
}

// Flags has the workload flags.
var Flags = flag.NewFlagSet("", flag.ContinueOnError)

// Workload is a DRBG-backed schedule of transactions.
type Workload interface {
	// NeedsFunds should return true if the workload requires funding.
	NeedsFunds() bool

	// Run executes the workload.
	// If `gracefulExit`'s deadline passes, it is not an error.
	// Return `nil` after any short-ish amount of time in that case.
	// Prefer to do at least one "iteration" even so.
	Run(
		gracefulExit context.Context,
		rng *rand.Rand,
		conn *grpc.ClientConn,
		cnsc consensus.ClientBackend,
		sm consensus.SubmissionManager,
		fundingAccount signature.Signer,
		validatorEntities []signature.Signer,
	) error
}

// BaseWorkload provides common methods for a workload.
type BaseWorkload struct {
	// Logger is the logger for the workload.
	Logger *logging.Logger

	cc consensus.ClientBackend
	sm consensus.SubmissionManager

	fundingAccount signature.Signer
}

// Init initializes the base workload.
func (bw *BaseWorkload) Init(
	cc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
) {
	bw.cc = cc
	bw.sm = sm
	bw.fundingAccount = fundingAccount
}

// Consensus returns the consensus client backend.
func (bw *BaseWorkload) Consensus() consensus.ClientBackend {
	return bw.cc
}

// GasPrice returns the configured consensus gas price.
func (bw *BaseWorkload) GasPrice() uint64 {
	// NOTE: This cannot fail as workloads use static price discovery.
	gasPrice, _ := bw.sm.PriceDiscovery().GasPrice(context.Background())
	return gasPrice.ToBigInt().Uint64()
}

// FundSignAndSubmitTx funds the caller to cover transaction fees, signs the transaction and submits
// it to the consensus layer.
func (bw *BaseWorkload) FundSignAndSubmitTx(ctx context.Context, caller signature.Signer, tx *transaction.Transaction) error {
	// Estimate fee.
	if err := bw.sm.EstimateGasAndSetFee(ctx, caller, tx); err != nil {
		return fmt.Errorf("failed to estimate fee: %w", err)
	}

	// Fund caller to cover transaction fees.
	callerAddr := staking.NewAddress(caller.Public())
	if err := bw.TransferFundsQty(ctx, bw.fundingAccount, callerAddr, &tx.Fee.Amount); err != nil {
		return fmt.Errorf("account funding failure: %w", err)
	}

	bw.Logger.Debug("submitting transaction",
		"tx", tx,
		"tx_caller", caller.Public(),
	)

	submitCtx, cancel := context.WithTimeout(ctx, maxSubmissionRetryElapsedTime)
	defer cancel()
	if err := bw.sm.SignAndSubmitTx(submitCtx, caller, tx); err != nil {
		bw.Logger.Error("failed to submit transaction",
			"err", err,
			"tx", tx,
			"tx_caller", caller.Public(),
		)
		return fmt.Errorf("failed to submit transaction: %w", err)
	}
	return nil
}

// TransferFunds transfers funds from one account to the other.
func (bw *BaseWorkload) TransferFunds(ctx context.Context, from signature.Signer, to staking.Address, amount uint64) error {
	return bw.TransferFundsQty(ctx, from, to, quantity.NewFromUint64(amount))
}

// TransferFundsQty transfers funds from one account to the other, taking a Quantity amount.
func (bw *BaseWorkload) TransferFundsQty(ctx context.Context, from signature.Signer, to staking.Address, amount *quantity.Quantity) error {
	tx := staking.NewTransferTx(0, nil, &staking.Transfer{
		To:     to,
		Amount: *amount,
	})

	submitCtx, cancel := context.WithTimeout(ctx, maxSubmissionRetryElapsedTime)
	defer cancel()
	if err := bw.sm.SignAndSubmitTx(submitCtx, from, tx); err != nil {
		bw.Logger.Error("failed to submit transaction",
			"err", err,
			"tx", tx,
			"tx_caller", from.Public(),
		)
		return fmt.Errorf("failed to submit transaction: %w", err)
	}
	return nil
}

// NewBaseWorkload creates a new BaseWorkload.
func NewBaseWorkload(name string) BaseWorkload {
	return BaseWorkload{
		Logger: logging.GetLogger("cmd/txsource/workload/" + name),
	}
}

// FundAccountFromTestEntity funds an account from test entity.
func FundAccountFromTestEntity(
	ctx context.Context,
	cc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	to signature.Signer,
) error {
	_, testEntitySigner, _ := entity.TestEntity()
	toAddr := staking.NewAddress(to.Public())

	bw := NewBaseWorkload("funding")
	bw.Init(cc, sm, testEntitySigner)
	return bw.TransferFunds(ctx, testEntitySigner, toAddr, fundAccountAmount)
}

func init() {
	Flags.AddFlagSet(QueriesFlags)
	Flags.AddFlagSet(RuntimeFlags)
}
