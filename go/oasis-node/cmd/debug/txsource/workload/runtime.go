package workload

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	runtimeClient "github.com/oasisprotocol/oasis-core/go/runtime/client/api"
	runtimeTransaction "github.com/oasisprotocol/oasis-core/go/runtime/transaction"
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

	runtimeRequestTimeout = 120 * time.Second
)

// Possible request types.
type runtimeRequest uint8

const (
	runtimeRequestInsert   runtimeRequest = 0
	runtimeRequestGet      runtimeRequest = 1
	runtimeRequestRemove   runtimeRequest = 2
	runtimeRequestWithdraw runtimeRequest = 3
	runtimeRequestTransfer runtimeRequest = 4
)

// Weights to select between requests types.
var runtimeRequestWeights = map[runtimeRequest]int{
	runtimeRequestInsert:   3,
	runtimeRequestGet:      2,
	runtimeRequestRemove:   3,
	runtimeRequestWithdraw: 1,
	runtimeRequestTransfer: 1,
}

// RuntimeFlags are the runtime workload flags.
var RuntimeFlags = flag.NewFlagSet("", flag.ContinueOnError)

type runtime struct {
	BaseWorkload

	runtimeID             common.Namespace
	reckonedKeyValueState map[string]string

	testAddress    staking.Address
	testBalance    quantity.Quantity
	runtimeBalance quantity.Quantity
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

func (r *runtime) validateResponse(key string, rsp *runtimeTransaction.TxnOutput) error {
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

func (r *runtime) validateEvents(ctx context.Context, rtc runtimeClient.RuntimeClient, op, key string) error {
	evs, err := rtc.GetEvents(ctx, &runtimeClient.GetEventsRequest{
		RuntimeID: r.runtimeID,
		Round:     runtimeClient.RoundLatest,
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

func (r *runtime) submitRuntimeRquest(ctx context.Context, rtc runtimeClient.RuntimeClient, req *runtimeTransaction.TxnCall) (*runtimeTransaction.TxnOutput, error) {
	var rsp runtimeTransaction.TxnOutput
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
	out, err := rtc.SubmitTx(submitCtx, rtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("failed to submit runtime transaction: %w", err)
	}

	if err = cbor.Unmarshal(out, &rsp); err != nil {
		return nil, fmt.Errorf("malformed tx output from runtime: %w", err)
	}
	if rsp.Error != nil {
		return nil, fmt.Errorf("runtime tx failed: %s", *rsp.Error)
	}

	return &rsp, nil
}

func (r *runtime) doInsertRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient, existing bool) error {
	key := r.generateVal(rng, existing)
	value := r.generateVal(rng, false)

	// Submit request.
	req := &runtimeTransaction.TxnCall{
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
	rsp, err := r.submitRuntimeRquest(ctx, rtc, req)
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

	if err := r.validateEvents(ctx, rtc, "insert", key); err != nil {
		return err
	}

	r.Logger.Debug("insert request success",
		"request", req,
		"response", rsp,
		"existing_key", existing,
	)

	// Update local state.
	r.reckonedKeyValueState[key] = value

	return nil
}

func (r *runtime) doGetRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient, existing bool) error {
	key := r.generateVal(rng, existing)

	// Submit request.
	req := &runtimeTransaction.TxnCall{
		Method: "get",
		Args: struct {
			Key   string `json:"key"`
			Nonce uint64 `json:"nonce"`
		}{
			Key:   key,
			Nonce: rng.Uint64(),
		},
	}
	rsp, err := r.submitRuntimeRquest(ctx, rtc, req)
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

	if err := r.validateEvents(ctx, rtc, "get", key); err != nil {
		return err
	}

	r.Logger.Debug("get request success",
		"request", req,
		"response", rsp,
		"existing_key", existing,
	)

	return nil
}

func (r *runtime) doRemoveRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient, existing bool) error {
	key := r.generateVal(rng, existing)

	// Submit request.
	req := &runtimeTransaction.TxnCall{
		Method: "remove",
		Args: struct {
			Key   string `json:"key"`
			Nonce uint64 `json:"nonce"`
		}{
			Key:   key,
			Nonce: rng.Uint64(),
		},
	}
	rsp, err := r.submitRuntimeRquest(ctx, rtc, req)
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

	if err := r.validateEvents(ctx, rtc, "remove", key); err != nil {
		return err
	}

	r.Logger.Debug("remove request success",
		"request", req,
		"response", rsp,
		"existing_key", existing,
	)

	// Update local state.
	delete(r.reckonedKeyValueState, key)

	return nil
}

func (r *runtime) doWithdrawRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	// Submit message request.
	amount := *quantity.NewFromUint64(1)
	req := &runtimeTransaction.TxnCall{
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
	rsp, err := r.submitRuntimeRquest(ctx, rtc, req)
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
	)

	// Make sure the withdrawal was processed correctly in the consensus layer.
	acct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  r.testAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to query test account: %w", err)
	}

	// Check source account balance.
	if err = r.testBalance.Sub(&amount); err != nil {
		return fmt.Errorf("failed to compute new test balance: %w", err)
	}
	if r.testBalance.Cmp(&acct.General.Balance) != 0 {
		return fmt.Errorf("unexpected balance in test account (expected: %s got: %s)", r.testBalance, acct.General.Balance)
	}

	// Check runtime account balance.
	acct, err = r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  staking.NewRuntimeAddress(r.runtimeID),
	})
	if err != nil {
		return fmt.Errorf("failed to query runtime account: %w", err)
	}

	if err = r.runtimeBalance.Add(&amount); err != nil {
		return fmt.Errorf("failed to compute new runtime balance: %w", err)
	}
	if r.runtimeBalance.Cmp(&acct.General.Balance) != 0 {
		return fmt.Errorf("unexpected balance in runtime account (expected: %s got: %s)", r.runtimeBalance, acct.General.Balance)
	}

	return nil
}

func (r *runtime) doTransferRequest(ctx context.Context, rng *rand.Rand, rtc runtimeClient.RuntimeClient) error {
	if r.runtimeBalance.IsZero() {
		return nil
	}

	// Submit message request.
	amount := *quantity.NewFromUint64(1)
	req := &runtimeTransaction.TxnCall{
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
	rsp, err := r.submitRuntimeRquest(ctx, rtc, req)
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
	)

	// Make sure the transfer was processed correctly in the consensus layer.
	acct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  r.testAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to query test account: %w", err)
	}

	// Check source account balance.
	if err = r.testBalance.Add(&amount); err != nil {
		return fmt.Errorf("failed to compute new test balance: %w", err)
	}
	if r.testBalance.Cmp(&acct.General.Balance) != 0 {
		return fmt.Errorf("unexpected balance in test account (expected: %s got: %s)", r.testBalance, acct.General.Balance)
	}

	// Check runtime account balance.
	acct, err = r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  staking.NewRuntimeAddress(r.runtimeID),
	})
	if err != nil {
		return fmt.Errorf("failed to query runtime account: %w", err)
	}

	if err = r.runtimeBalance.Sub(&amount); err != nil {
		return fmt.Errorf("failed to compute new runtime balance: %w", err)
	}
	if r.runtimeBalance.Cmp(&acct.General.Balance) != 0 {
		return fmt.Errorf("unexpected balance in runtime account (expected: %s got: %s)", r.runtimeBalance, acct.General.Balance)
	}

	return nil
}

// Implements Workload.
func (r *runtime) NeedsFunds() bool {
	return true
}

func (r *runtime) initAccounts(ctx context.Context, fundingAccount signature.Signer) error {
	// Allow the runtime to withdraw some funds from the funding account.
	rtAddress := staking.NewRuntimeAddress(r.runtimeID)

	tx := staking.NewAllowTx(0, nil, &staking.Allow{
		Beneficiary:  rtAddress,
		AmountChange: *quantity.NewFromUint64(100000),
	})
	if err := r.FundSignAndSubmitTx(ctx, fundingAccount, tx); err != nil {
		r.Logger.Error("failed to sign and submit allow transaction",
			"tx", tx,
			"signer", fundingAccount.Public(),
		)
		return fmt.Errorf("failed to sign and submit allow tx: %w", err)
	}

	// Configure the address used for runtime tests.
	r.testAddress = staking.NewAddress(fundingAccount.Public())

	// Query initial account balance.
	acct, err := r.Consensus().Staking().Account(ctx, &staking.OwnerQuery{
		Height: consensus.HeightLatest,
		Owner:  r.testAddress,
	})
	if err != nil {
		return fmt.Errorf("failed to query account: %w", err)
	}
	r.testBalance = acct.General.Balance

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

	ctx := context.Background()

	// Simple-keyvalue runtime.
	err := r.runtimeID.UnmarshalHex(viper.GetString(CfgRuntimeID))
	if err != nil {
		r.Logger.Error("runtime unmsrshal error",
			"err", err,
			"runtime_id", viper.GetString(CfgRuntimeID),
		)
		return fmt.Errorf("Runtime unmarshal: %w", err)
	}
	r.reckonedKeyValueState = make(map[string]string)

	// Initialize staking accounts for testing runtime interactions.
	if err = r.initAccounts(ctx, fundingAccount); err != nil {
		return fmt.Errorf("failed to initialize accounts: %w", err)
	}

	// Set up the runtime client.
	rtc := runtimeClient.NewRuntimeClient(conn)

	// Wait for 2nd epoch, so that runtimes are up and running.
	r.Logger.Info("waiting for 2nd epoch")
	if err := cnsc.WaitEpoch(ctx, 2); err != nil {
		return fmt.Errorf("failed waiting for 2nd epoch: %w", err)
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
