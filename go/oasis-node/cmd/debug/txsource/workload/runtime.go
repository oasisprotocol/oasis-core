package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// NameRuntime is the name of the runtime workload.
const NameRuntime = "runtime"

// Runtime is the runtime workload.
var Runtime = &runtime{
	BaseWorkload: NewBaseWorkload(NameRuntime),
}

const (
	// CfgRuntimeID is the runtime workload runtime ID.
	CfgRuntimeID = "runtime.runtime_id"

	// Ratio of insert requests that should be an upsert.
	runtimeInsertExistingRatio = 0.3
	// Ratio of get requests that should get an existing key.
	runtimeGetExistingRatio = 0.9
	// Ratio of remove requests that should delete an existing key.
	runtimeRemoveExistingRatio = 0.5

	runtimeRequestTimeout = 240 * time.Second
)

// Possible request types.
type runtimeRequest uint8

const (
	runtimeRequestInsert        runtimeRequest = 0
	runtimeRequestGet           runtimeRequest = 1
	runtimeRequestRemove        runtimeRequest = 2
	runtimeRequestWithdraw      runtimeRequest = 3
	runtimeRequestTransfer      runtimeRequest = 4
	runtimeRequestAddEscrow     runtimeRequest = 5
	runtimeRequestReclaimEscrow runtimeRequest = 6
	runtimeRequestInMsg         runtimeRequest = 7
)

// Weights to select between requests types.
var runtimeRequestWeights = map[runtimeRequest]int{
	runtimeRequestInsert:        3,
	runtimeRequestGet:           2,
	runtimeRequestRemove:        3,
	runtimeRequestWithdraw:      2,
	runtimeRequestTransfer:      1,
	runtimeRequestAddEscrow:     1,
	runtimeRequestReclaimEscrow: 1,
	runtimeRequestInMsg:         1,
}

// RuntimeFlags are the runtime workload flags.
var RuntimeFlags = flag.NewFlagSet("", flag.ContinueOnError)

// TxnCall is a transaction call in the test runtime.
type TxnCall struct {
	// Method is the called method name.
	Method string `json:"method"`
	// Args are the method arguments.
	Args interface{} `json:"args"`
}

// TxnOutput is a transaction call output in the test runtime.
type TxnOutput struct {
	// Success can be of any type.
	Success cbor.RawMessage
	// Error is a string describing the error message.
	Error *string
}

type runtime struct {
	BaseWorkload

	runtimeID             common.Namespace
	reckonedKeyValueState map[string]string

	testAddress staking.Address

	testInitialBalance quantity.Quantity
	testInitialEscrow  quantity.Quantity

	runtimeReclaimed   quantity.Quantity
	runtimeWithdrawn   quantity.Quantity
	runtimeTransferred quantity.Quantity
	runtimeEscrowed    quantity.Quantity
}

func (r *runtime) generateVal(rng *rand.Rand, existingKey bool) string {
	if existingKey && len(r.reckonedKeyValueState) > 0 {
		// Select existing key to be used.
		keyIdx := rng.Intn(len(r.reckonedKeyValueState))
		i := 0
		for k := range r.reckonedKeyValueState {
			if i == keyIdx {
				return k
			}
			i++
		}
	}

	// Generate random value.
	b := make([]byte, rng.Intn(128/2)+1)
	rng.Read(b)
	return fmt.Sprintf("%X", b)
}

func (r *runtime) validateResponse(key string, rsp *TxnOutput) error {
	var keyExists bool
	if _, ok := r.reckonedKeyValueState[key]; ok {
		keyExists = true
	}

	// Validate response.
	switch keyExists {
	case true:
		// If existing key was inserted/deleted/queried, existing value is
		// expected in response.
		var prev string
		if err := cbor.Unmarshal(rsp.Success, &prev); err != nil {
			return fmt.Errorf("expected valid response: %w", err)
		}
		if prev != r.reckonedKeyValueState[key] {
			return fmt.Errorf("invalid response value, expected: '%s', got: '%s'", r.reckonedKeyValueState[key], prev)
		}
	case false:
		// If a non existing key was inserted/deleted/queried, empty response is
		// expected.
		var prev *string
		if err := cbor.Unmarshal(rsp.Success, &prev); err != nil {
			return fmt.Errorf("expected valid response: %w", err)
		}
		if prev != nil {
			return fmt.Errorf("expected nil response, got: '%s'", rsp.Success)
		}
	}

	return nil
}

func (r *runtime) validateEvents(ctx context.Context, rtc runtimeClient.RuntimeClient, round uint64, op, key string) error {
	evs, err := rtc.GetEvents(ctx, &runtimeClient.GetEventsRequest{
		RuntimeID: r.runtimeID,
		Round:     round,
	})
	if err != nil {
		return fmt.Errorf("failed to fetch events: %w", err)
	}

	if len(evs) != 2 {
		r.Logger.Error("unexpected number of events",
			"events", evs,
			"expected_op", op,
			"expected_key", key,
		)
		return fmt.Errorf("unexpected number of events (expected: %d got: %d)", 2, len(evs))
	}
	for _, ev := range evs {
		switch string(ev.Key) {
		case "kv_op":
			if string(ev.Value) != op {
				return fmt.Errorf("unexpected kv_op event value (expected: %s got: %s)", op, string(ev.Value))
			}
		case "kv_key":
			if string(ev.Value) != key {
				return fmt.Errorf("unexpected kv_key event value (expected: %s got: %s)", key, string(ev.Value))
			}
		default:
			return fmt.Errorf("unexpected event type: %s", ev.Key)
		}
	}
	return nil
}

func (r *runtime) submitRuntimeRquest(ctx context.Context, rtc runtimeClient.RuntimeClient, req *TxnCall) (*TxnOutput, uint64, error) {
	var rsp TxnOutput
	rtx := &runtimeClient.SubmitTxRequest{
		RuntimeID: r.runtimeID,
		Data:      cbor.Marshal(req),
	}

	r.Logger.Debug("submitting request",
		"request", req,
	)

	// Wait for a maximum of 'runtimeRequestTimeout' as invalid submissions may block
	// forever.
	submitCtx, cancel := context.WithTimeout(ctx, runtimeRequestTimeout)
	// Start the watch timeout now, so that the request time is included in the timeout.
	out, err := rtc.SubmitTxMeta(submitCtx, rtx)
	cancel()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to submit runtime transaction: %w", err)
	}
	if out.CheckTxError != nil {
		return nil, 0, fmt.Errorf("SubmitTxWithMeta check tx error: %w", errors.FromCode(out.CheckTxError.Module, out.CheckTxError.Code, out.CheckTxError.Message))
	}
	if err = cbor.Unmarshal(out.Output, &rsp); err != nil {
		return nil, 0, fmt.Errorf("malformed tx output from runtime: %w", err)
	}
	if rsp.Error != nil {
		return nil, 0, fmt.Errorf("runtime tx failed: %s", *rsp.Error)
	}
	return &rsp, out.Round, nil
}

func (r *runtime) doInsertRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient, existing bool) error {
	key := r.generateVal(rng, existing)
	value := r.generateVal(rng, false)

	// Submit request.
	req := &TxnCall{
		Method: "insert",
		Args: struct {
			Key   string `json:"key"`
			Value string `json:"value"`
			Nonce uint64 `json:"nonce"`
		}{
			Key:   key,
			Value: value,
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit insert request failure",
			"request", req,
			"existing_key", existing,
			"err", err,
		)
		return fmt.Errorf("submit insert request failed: %w", err)
	}

	if err := r.validateResponse(key, rsp); err != nil {
		r.Logger.Error("Insert response validation failure",
			"request", req,
			"response", rsp,
			"existing_key", existing,
			"err", err,
		)
		return fmt.Errorf("invalid response: %w", err)
	}

	if err := r.validateEvents(ctx, rtc, round, "insert", key); err != nil {
		return err
	}

	r.Logger.Debug("insert request success",
		"request", req,
		"response", rsp,
		"existing_key", existing,
		"round", round,
	)

	// Update local state.
	r.reckonedKeyValueState[key] = value

	return nil
}

func (r *runtime) doGetRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient, existing bool) error {
	key := r.generateVal(rng, existing)

	// Submit request.
	req := &TxnCall{
		Method: "get",
		Args: struct {
			Key   string `json:"key"`
			Nonce uint64 `json:"nonce"`
		}{
			Key:   key,
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit get request failure",
			"request", req,
			"existing_key", existing,
			"err", err,
		)
		return fmt.Errorf("submit get request failed: %w", err)
	}

	if err := r.validateResponse(key, rsp); err != nil {
		r.Logger.Error("Get response validation failure",
			"request", req,
			"response", rsp,
			"existing_key", existing,
			"err", err,
		)
		return fmt.Errorf("invalid response: %w", err)
	}

	if err := r.validateEvents(ctx, rtc, round, "get", key); err != nil {
		return err
	}

	r.Logger.Debug("get request success",
		"request", req,
		"response", rsp,
		"existing_key", existing,
		"round", round,
	)

	return nil
}

func (r *runtime) doRemoveRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient, existing bool) error {
	key := r.generateVal(rng, existing)

	// Submit request.
	req := &TxnCall{
		Method: "remove",
		Args: struct {
			Key   string `json:"key"`
			Nonce uint64 `json:"nonce"`
		}{
			Key:   key,
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit remove request failure",
			"request", req,
			"existing_key", existing,
			"err", err,
		)
		return fmt.Errorf("submit remove request failed: %w", err)
	}

	if err := r.validateResponse(key, rsp); err != nil {
		r.Logger.Error("Submit request validation failure",
			"request", req,
			"response", rsp,
			"existing_key", existing,
			"err", err,
		)
		return fmt.Errorf("invalid response: %w", err)
	}

	if err := r.validateEvents(ctx, rtc, round, "remove", key); err != nil {
		return err
	}

	r.Logger.Debug("remove request success",
		"request", req,
		"response", rsp,
		"existing_key", existing,
		"round", round,
	)

	// Update local state.
	delete(r.reckonedKeyValueState, key)

	return nil
}

func (r *runtime) doInMsgRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	key := r.generateVal(rng, false)
	value := r.generateVal(rng, false)

	tx := roothash.NewSubmitMsgTx(0, nil, &roothash.SubmitMsg{
		ID:  r.runtimeID,
		Tag: 42,
		Data: cbor.Marshal(&TxnCall{
			Method: "insert",
			Args: struct {
				Key   string `json:"key"`
				Value string `json:"value"`
				Nonce uint64 `json:"nonce"`
			}{
				Key:   key,
				Value: value,
				Nonce: rng.Uint64(),
			},
		}),
	})

	// Start watching roothash events.
	ch, sub, err := r.Consensus().RootHash().WatchEvents(ctx, r.runtimeID)
	if err != nil {
		return fmt.Errorf("failed to watch events: %w", err)
	}
	defer sub.Close()

	r.Logger.Debug("submitting incoming message",
		"tx", tx,
	)

	submitCtx, cancel := context.WithTimeout(ctx, runtimeRequestTimeout)
	defer cancel()

	signer := memorySigner.NewTestSigner("oasis in msg test signer: " + time.Now().String())
	err = r.FundSignAndSubmitTx(submitCtx, signer, tx)
	if err != nil {
		r.Logger.Error("failed to submit incoming message",
			"err", err,
			"tx", tx,
		)
		return fmt.Errorf("failed to submit incoming message: %w", err)
	}

	// Wait for processed event.
	r.Logger.Debug("waiting for incoming message processed event")
	callerAddr := staking.NewAddress(signer.Public())
	for {
		select {
		case ev := <-ch:
			if ev.InMsgProcessed == nil {
				continue
			}

			if !ev.InMsgProcessed.Caller.Equal(callerAddr) {
				continue
			}
			if ev.InMsgProcessed.Tag != 42 {
				continue
			}
		case <-submitCtx.Done():
			r.Logger.Error("timed out waiting for incoming message to be processed")
			return ctx.Err()
		}

		break
	}

	r.Logger.Debug("insert via incoming message success",
		"key", key,
		"value", value,
	)

	// Update local state.
	r.reckonedKeyValueState[key] = value

	return nil
}

func (r *runtime) balanceIsZero(ctx context.Context, address staking.Address) (bool, error) {
	acct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  address,
	})
	if err != nil {
		return false, fmt.Errorf("failed to query account: %w", err)
	}

	return acct.General.Balance.IsZero(), nil
}

func (r *runtime) escrowIsZero(ctx context.Context, address staking.Address) (bool, error) {
	acct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  address,
	})
	if err != nil {
		return false, fmt.Errorf("failed to query account: %w", err)
	}

	return acct.Escrow.Active.Balance.IsZero(), nil
}

// assertBalanceInvariants asserts some balance invariants that should hold true
// at every iteration of the test.
func (r *runtime) assertBalanceInvariants(ctx context.Context) error {
	// Use a consistent height for querying balances.
	blk, err := r.Consensus().GetBlock(ctx, consensus.HeightLatest)
	if err != nil {
		return err
	}
	height := blk.Height

	testAcct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: height,
		Owner:  r.testAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to query test account: %w", err)
	}

	rtAcct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: height,
		Owner:  staking.NewRuntimeAddress(r.runtimeID),
	})
	if err != nil {
		return fmt.Errorf("failed to query runtime account: %w", err)
	}

	r.Logger.Debug("asserting balance invariants",
		"test_account_balance", testAcct.General.Balance,
		"test_account_escrow", testAcct.Escrow.Active,
		"test_account_debonding", testAcct.Escrow.Debonding,
		"runtime_account_balance", rtAcct.General.Balance,
	)

	// Test account balance should match: initial balance + transferred - withdrawn.
	expectedTestAcctBalance := r.testInitialBalance.Clone()
	if err = expectedTestAcctBalance.Add(&r.runtimeTransferred); err != nil {
		return fmt.Errorf("expectedTestAcctBalance.Add(runtimeTransferred): %w", err)
	}
	if err = expectedTestAcctBalance.Sub(&r.runtimeWithdrawn); err != nil {
		return fmt.Errorf("expectedTestAcctBalance.Sub(runtimeWithdrawn): %w", err)
	}
	if testAcct.General.Balance.Cmp(expectedTestAcctBalance) != 0 {
		return fmt.Errorf("unexpected balance in test account (expected: %s got: %s)", expectedTestAcctBalance, testAcct.General.Balance)
	}

	// Test account escrow should match: initial escrowed + escrowed - reclaimed.
	expectedTestAcctEscrow := r.testInitialEscrow.Clone()
	if err = expectedTestAcctEscrow.Add(&r.runtimeEscrowed); err != nil {
		return fmt.Errorf("expectedTestAcctEscrow.Add(runtimeEscrowed): %w", err)
	}
	if err = expectedTestAcctEscrow.Sub(&r.runtimeReclaimed); err != nil {
		return fmt.Errorf("expectedTestAcctEscrow.Sub(runtimeReclaimed): %w", err)
	}
	if testAcct.Escrow.Active.Balance.Cmp(expectedTestAcctEscrow) != 0 {
		return fmt.Errorf("unexpected escrow in test account (expected: %s got: %s)", expectedTestAcctEscrow, testAcct.Escrow.Active.Balance)
	}

	// Runtime account balance + test account debonding, should match: widthdrawn + reclaimed - transferred - escrowed.
	// NOTE: since reclaim escrow effect to the runtime account is delayed (debonding period), we cannot
	// check runtime account balance directly.
	rtAcctAndDebonding := rtAcct.General.Balance.Clone()
	if err = rtAcctAndDebonding.Add(&testAcct.Escrow.Debonding.Balance); err != nil {
		return fmt.Errorf("rtAcctAndDebonding.Add(testAcct.Escrow): %w", err)
	}

	expectedRtAndDebonding := r.runtimeWithdrawn.Clone()
	if err = expectedRtAndDebonding.Add(&r.runtimeReclaimed); err != nil {
		return fmt.Errorf("expectedRtAndDebonding.Add(runtimeReclaimed): %w", err)
	}
	if err = expectedRtAndDebonding.Sub(&r.runtimeTransferred); err != nil {
		return fmt.Errorf("expectedRtAndDebonding.Sub(runtimeTransferred): %w", err)
	}
	if err = expectedRtAndDebonding.Sub(&r.runtimeEscrowed); err != nil {
		return fmt.Errorf("expectedRtAndDebonding.Sub(runtimeEscrowed): %w", err)
	}
	if rtAcctAndDebonding.Cmp(expectedRtAndDebonding) != 0 {
		return fmt.Errorf("unexpected balance + debonding of runtime account (expected: %s got: %s)", expectedRtAndDebonding, rtAcctAndDebonding)
	}

	return nil
}

func (r *runtime) doWithdrawRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	// Submit message request.
	amount := *quantity.NewFromUint64(1)
	req := &TxnCall{
		Method: "consensus_withdraw",
		Args: struct {
			Withdraw staking.Withdraw `json:"withdraw"`
			Nonce    uint64           `json:"nonce"`
		}{
			Withdraw: staking.Withdraw{
				From:   r.testAddress,
				Amount: amount,
			},
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit withdraw request failure",
			"request", req,
			"err", err,
		)
		return fmt.Errorf("submit withdraw request failed: %w", err)
	}

	r.Logger.Debug("withdraw request success",
		"request", req,
		"response", rsp,
		"round", round,
	)

	if err = r.runtimeWithdrawn.Add(&amount); err != nil {
		return fmt.Errorf("error updating runtimeWidthdrawn: %w", err)
	}
	return r.assertBalanceInvariants(ctx)
}

func (r *runtime) doTransferRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	zero, err := r.balanceIsZero(ctx, staking.NewRuntimeAddress(r.runtimeID))
	if err != nil {
		return err
	}
	if zero {
		return nil
	}

	// Submit message request.
	amount := *quantity.NewFromUint64(1)
	req := &TxnCall{
		Method: "consensus_transfer",
		Args: struct {
			Transfer staking.Transfer `json:"transfer"`
			Nonce    uint64           `json:"nonce"`
		}{
			Transfer: staking.Transfer{
				To:     r.testAddress,
				Amount: amount,
			},
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit transfer request failure",
			"request", req,
			"err", err,
		)
		return fmt.Errorf("submit transfer request failed: %w", err)
	}

	r.Logger.Debug("transfer request success",
		"request", req,
		"response", rsp,
		"round", round,
	)

	if err = r.runtimeTransferred.Add(&amount); err != nil {
		return fmt.Errorf("error updating runtimeTransferred: %w", err)
	}
	return r.assertBalanceInvariants(ctx)
}

func (r *runtime) doAddEscrowRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	zero, err := r.balanceIsZero(ctx, staking.NewRuntimeAddress(r.runtimeID))
	if err != nil {
		return err
	}
	if zero {
		return nil
	}

	// Submit message request.
	amount := *quantity.NewFromUint64(1)
	req := &TxnCall{
		Method: "consensus_add_escrow",
		Args: struct {
			Escrow staking.Escrow `json:"escrow"`
			Nonce  uint64         `json:"nonce"`
		}{
			Escrow: staking.Escrow{
				Account: r.testAddress,
				Amount:  amount,
			},
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit add escrow request failure",
			"request", req,
			"err", err,
		)
		return fmt.Errorf("submit add escrow request failed: %w", err)
	}

	r.Logger.Debug("add escrow request success",
		"request", req,
		"response", rsp,
		"round", round,
	)

	if err = r.runtimeEscrowed.Add(&amount); err != nil {
		return fmt.Errorf("error updating runtimeEscrowed: %w", err)
	}
	return r.assertBalanceInvariants(ctx)
}

func (r *runtime) doReclaimEscrowRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	zero, err := r.escrowIsZero(ctx, r.testAddress)
	if err != nil {
		return err
	}
	if zero {
		return nil
	}

	// Submit message request.
	// Shares should match balance in the test account, as the account is not
	// getting any rewards or is being slashed.
	amount := *quantity.NewFromUint64(1)
	req := &TxnCall{
		Method: "consensus_reclaim_escrow",
		Args: struct {
			ReclaimEscrow staking.ReclaimEscrow `json:"reclaim_escrow"`
			Nonce         uint64                `json:"nonce"`
		}{
			ReclaimEscrow: staking.ReclaimEscrow{
				Account: r.testAddress,
				Shares:  amount,
			},
			Nonce: rng.Uint64(),
		},
	}
	rsp, round, err := r.submitRuntimeRquest(ctx, rtc, req)
	if err != nil {
		r.Logger.Error("Submit reclaim escrow request failure",
			"request", req,
			"err", err,
		)
		return fmt.Errorf("submit reclaim escrow request failed: %w", err)
	}

	r.Logger.Debug("reclaim escrow request success",
		"request", req,
		"response", rsp,
		"round", round,
	)

	if err = r.runtimeReclaimed.Add(&amount); err != nil {
		return fmt.Errorf("error updating runtimeReclaimed: %w", err)
	}
	return r.assertBalanceInvariants(ctx)
}

// Implements Workload.
func (r *runtime) NeedsFunds() bool {
	return true
}

func (r *runtime) initAccounts(ctx context.Context, fundingAccount signature.Signer) error {
	// Create a new account for withdrawals/deposits.
	const amount = 100_000
	signer := memorySigner.NewTestSigner("oasis runtime msg tests: " + time.Now().String())
	r.testAddress = staking.NewAddress(signer.Public())
	if err := r.TransferFunds(ctx, fundingAccount, r.testAddress, amount); err != nil {
		return fmt.Errorf("failed to transfer funds: %w", err)
	}

	// Allow the runtime to withdraw some funds.
	rtAddress := staking.NewRuntimeAddress(r.runtimeID)

	tx := staking.NewAllowTx(0, nil, &staking.Allow{
		Beneficiary:  rtAddress,
		AmountChange: *quantity.NewFromUint64(amount),
	})
	if err := r.FundSignAndSubmitTx(ctx, signer, tx); err != nil {
		r.Logger.Error("failed to sign and submit allow transaction",
			"tx", tx,
			"signer", fundingAccount.Public(),
		)
		return fmt.Errorf("failed to sign and submit allow tx: %w", err)
	}

	// Query initial account balance.
	acct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  r.testAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to query account: %w", err)
	}
	r.testInitialBalance = acct.General.Balance

	return nil
}

// Implements Workload.
func (r *runtime) Run(
	gracefulExit context.Context,
	rng *rand.Rand,
	conn *grpc.ClientConn,
	cnsc consensus.ClientBackend,
	sm consensus.SubmissionManager,
	fundingAccount signature.Signer,
	validatorEntities []signature.Signer,
) error {
	// Initialize base workload.
	r.BaseWorkload.Init(cnsc, sm, fundingAccount)

	beacon := beacon.NewBeaconClient(conn)
	ctx := context.Background()

	// Simple-keyvalue runtime.
	err := r.runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID))
	if err != nil {
		r.Logger.Error("runtime unmarshal error",
			"err", err,
			"runtime_id", viper.GetString(CfgRuntimeID),
		)
		return fmt.Errorf("runtime unmarshal: %w", err)
	}
	r.reckonedKeyValueState = make(map[string]string)

	// Initialize staking accounts for testing runtime interactions.
	if err = r.initAccounts(ctx, fundingAccount); err != nil {
		return fmt.Errorf("failed to initialize accounts: %w", err)
	}

	// Set up the runtime client.
	rtc := runtimeClient.NewRuntimeClient(conn)

	// Wait for 3rd epoch, so that runtimes are up and running.
	r.Logger.Info("waiting for 3rd epoch")
	if err := beacon.WaitEpoch(ctx, 3); err != nil {
		return fmt.Errorf("failed waiting for 3rd epoch: %w", err)
	}

	var totalWeight int
	for _, w := range runtimeRequestWeights {
		totalWeight = totalWeight + w
	}

	for {
		// Determine which request to perform based on the configured weight table.
		p := rng.Intn(totalWeight)
		var (
			cw      int
			request runtimeRequest
		)
		for r, w := range runtimeRequestWeights {
			if cw = cw + w; p < cw {
				request = r
				break
			}
		}

		switch request {
		case runtimeRequestInsert:
			if err := r.doInsertRequest(ctx, rng, rtc, rng.Float64() < runtimeInsertExistingRatio); err != nil {
				return fmt.Errorf("doInsertRequest failure: %w", err)
			}
		case runtimeRequestGet:
			if err := r.doGetRequest(ctx, rng, rtc, rng.Float64() < runtimeGetExistingRatio); err != nil {
				return fmt.Errorf("doGetRequest failure: %w", err)
			}
		case runtimeRequestRemove:
			if err := r.doRemoveRequest(ctx, rng, rtc, rng.Float64() < runtimeRemoveExistingRatio); err != nil {
				return fmt.Errorf("doRemoveRequest failure: %w", err)
			}
		case runtimeRequestWithdraw:
			if err := r.doWithdrawRequest(ctx, rng, rtc); err != nil {
				return fmt.Errorf("doWithdrawRequest failure: %w", err)
			}
		case runtimeRequestTransfer:
			if err := r.doTransferRequest(ctx, rng, rtc); err != nil {
				return fmt.Errorf("doTransferRequest failure: %w", err)
			}
		case runtimeRequestAddEscrow:
			if err := r.doAddEscrowRequest(ctx, rng, rtc); err != nil {
				return fmt.Errorf("doAddEscrowRequest failure: %w", err)
			}
		case runtimeRequestReclaimEscrow:
			if err := r.doReclaimEscrowRequest(ctx, rng, rtc); err != nil {
				return fmt.Errorf("doReclaimEscrowRequest failure: %w", err)
			}
		case runtimeRequestInMsg:
			if err := r.doInMsgRequest(ctx, rng, rtc); err != nil {
				return fmt.Errorf("doInMsgRequest failure: %w", err)
			}
		default:
			return fmt.Errorf("unimplemented")
		}

		select {
		case <-time.After(1 * time.Second):
		case <-gracefulExit.Done():
			r.Logger.Debug("time's up")
			return nil
		}
	}
}

func init() {
	RuntimeFlags.String(CfgRuntimeID, "", "Simple-keyvalue runtime ID")
	_ = viper.BindPFlags(RuntimeFlags)
}
