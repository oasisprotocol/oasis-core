package runtime

import (
	"context"
	"crypto"
	"fmt"
	"math/rand"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// KVTestClient is a client that exercises the simple key-value test runtime.
type KVTestClient struct {
	sc *Scenario

	seed     string
	scenario TestClientScenario

	ctx      context.Context
	cancelFn context.CancelFunc
	errCh    chan error
}

func (cli *KVTestClient) Init(scenario *Scenario) error {
	cli.sc = scenario
	return nil
}

func (cli *KVTestClient) Start(ctx context.Context, childEnv *env.Env) error {
	cli.ctx = ctx

	subCtx, cancelFn := context.WithCancel(ctx)
	cli.errCh = make(chan error)
	cli.cancelFn = cancelFn

	go func() {
		cli.errCh <- cli.workload(subCtx)
	}()

	return nil
}

func (cli *KVTestClient) Wait() error {
	var err error

	// Wait for the network to fail, the context to be canceled, or the
	// workload to terminate on it's own.
	select {
	case err = <-cli.sc.Net.Errors():
		cli.cancelFn()
	case <-cli.ctx.Done():
		err = cli.ctx.Err()
		cli.cancelFn()
	case err = <-cli.errCh:
	}

	return err
}

func (cli *KVTestClient) Stop() error {
	// Kill the workload.
	cli.cancelFn()

	// Wait for the network to fail, or the workload to terminate on it's own.
	select {
	case err := <-cli.sc.Net.Errors():
		return err
	case err := <-cli.errCh:
		return err
	}
}

func (cli *KVTestClient) Clone() TestClient {
	return &KVTestClient{
		seed:     cli.seed,
		scenario: cli.scenario,
	}
}

func (cli *KVTestClient) WithSeed(seed string) *KVTestClient {
	cli.seed = seed
	return cli
}

func (cli *KVTestClient) WithScenario(scenario TestClientScenario) *KVTestClient {
	cli.scenario = scenario
	return cli
}

func (cli *KVTestClient) workload(ctx context.Context) error {
	// Initialize the nonce DRBG.
	rng, err := drbgFromSeed(
		[]byte("oasis-core/oasis-test-runner/e2e/runtime/test-client"),
		[]byte(cli.seed),
	)
	if err != nil {
		return err
	}

	cli.sc.Logger.Info("starting k/v runtime test client")

	if err := cli.scenario(func(req interface{}) error {
		return cli.submit(ctx, req, rng)
	}); err != nil {
		return err
	}

	cli.sc.Logger.Info("k/v runtime test client finished")

	return nil
}

func (cli *KVTestClient) submit(ctx context.Context, req interface{}, rng rand.Source64) error {
	switch req := req.(type) {
	case KeyValueQuery:
		rsp, err := cli.sc.submitKeyValueRuntimeGetQuery(
			ctx,
			runtimeID,
			req.Key,
			req.Round,
		)
		if err != nil {
			return fmt.Errorf("failed to query k/v pair: %w", err)
		}
		if rsp != req.Response {
			return fmt.Errorf("response does not have expected value (got: '%v', expected: '%v')", rsp, req.Response)
		}

	case InsertKeyValueTx:
		rsp, err := cli.sc.submitKeyValueRuntimeInsertTx(
			ctx,
			runtimeID,
			rng.Uint64(),
			req.Key,
			req.Value,
			req.Encrypted,
		)
		if err != nil {
			return fmt.Errorf("failed to insert k/v pair: %w", err)
		}
		if rsp != req.Response {
			return fmt.Errorf("response does not have expected value (got: '%v', expected: '%v')", rsp, req.Response)
		}

	case GetKeyValueTx:
		rsp, err := cli.sc.submitKeyValueRuntimeGetTx(
			ctx,
			runtimeID,
			rng.Uint64(),
			req.Key,
			req.Encrypted,
		)
		if err != nil {
			return err
		}
		if rsp != req.Response {
			return fmt.Errorf("response does not have expected value (got: '%v', expected: '%v')", rsp, req.Response)
		}

	case RemoveKeyValueTx:
		rsp, err := cli.sc.submitKeyValueRuntimeRemoveTx(
			ctx,
			runtimeID,
			rng.Uint64(),
			req.Key,
			req.Encrypted,
		)
		if err != nil {
			return err
		}
		if rsp != req.Response {
			return fmt.Errorf("response does not have expected value (got: '%v', expected: '%v')", rsp, req.Response)
		}

	case InsertMsg:
		err := cli.sc.submitKeyValueRuntimeInsertMsg(
			ctx,
			runtimeID,
			rng.Uint64(),
			req.Key,
			req.Value,
			req.Encrypted,
		)
		if err != nil {
			return err
		}

	case GetRuntimeIDTx:
		_, err := cli.sc.submitKeyValueRuntimeGetRuntimeIDTx(ctx, runtimeID, rng.Uint64())
		if err != nil {
			return err
		}

	case ConsensusTransferTx:
		err := cli.sc.submitConsensusTransferTx(ctx, runtimeID, rng.Uint64(), staking.Transfer{})
		if err != nil {
			return err
		}

	case ConsensusAccountsTx:
		err := cli.sc.submitConsensusAccountsTx(ctx, runtimeID, rng.Uint64())
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid k/v runtime test client scenario command")
	}

	return nil
}

func NewKVTestClient() *KVTestClient {
	return &KVTestClient{
		seed:     "seed",
		scenario: func(submit func(req interface{}) error) error { return nil },
	}
}

func (sc *Scenario) submitAndDecodeRuntimeTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	method string,
	args interface{},
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, id, nonce, method, args)
	if err != nil {
		return "", fmt.Errorf("failed to submit %s tx to runtime: %w", method, err)
	}

	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal %s tx response from runtime: %w", method, err)
	}

	return rsp, nil
}

func (sc *Scenario) submitKeyValueRuntimeInsertTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key, value string,
	encrypted bool,
) (string, error) {
	sc.Logger.Info("inserting k/v pair",
		"key", key,
		"value", value,
		"encrypted", encrypted,
	)

	args := struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{
		Key:   key,
		Value: value,
	}

	if encrypted {
		return sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "enc_insert", args)
	}
	return sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "insert", args)
}

func (sc *Scenario) submitKeyValueRuntimeGetTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key string,
	encrypted bool,
) (string, error) {
	sc.Logger.Info("retrieving k/v pair",
		"key", key,
		"encrypted", encrypted,
	)

	args := struct {
		Key string `json:"key"`
	}{
		Key: key,
	}

	if encrypted {
		return sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "enc_get", args)
	}
	return sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "get", args)
}

func (sc *Scenario) submitKeyValueRuntimeRemoveTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key string,
	encrypted bool,
) (string, error) {
	sc.Logger.Info("removing k/v pair",
		"key", key,
		"encrypted", encrypted,
	)

	args := struct {
		Key string `json:"key"`
	}{
		Key: key,
	}

	if encrypted {
		return sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "enc_remove", args)
	}
	return sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "remove", args)
}

func (sc *Scenario) submitKeyValueRuntimeGetRuntimeIDTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
) (string, error) {
	sc.Logger.Info("retrieving runtime ID")

	rsp, err := sc.submitAndDecodeRuntimeTx(ctx, id, nonce, "get_runtime_id", nil)
	if err != nil {
		return "", fmt.Errorf("failed to query remote runtime ID: %w", err)
	}

	return rsp, nil
}

func (sc *Scenario) submitKeyValueRuntimeInsertMsg(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key, value string,
	encrypted bool,
) error {
	sc.Logger.Info("submitting incoming runtime message",
		"key", key,
		"value", value,
		"encrypted", encrypted,
	)

	args := struct {
		Key        string `json:"key"`
		Value      string `json:"value"`
		Generation uint64 `json:"generation,omitempty"`
	}{
		Key:   key,
		Value: value,
	}

	if encrypted {
		return sc.submitRuntimeInMsg(ctx, id, nonce, "enc_insert", args)
	}
	return sc.submitRuntimeInMsg(ctx, id, nonce, "insert", args)
}

func (sc *Scenario) submitAndDecodeRuntimeQuery(
	ctx context.Context,
	id common.Namespace,
	round uint64,
	method string,
	args interface{},
) (string, error) {
	rawRsp, err := sc.submitRuntimeQuery(ctx, id, round, method, args)
	if err != nil {
		return "", fmt.Errorf("failed to submit %s query to runtime: %w", method, err)
	}

	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal %s tx response from runtime: %w", method, err)
	}

	return rsp, nil
}

func (sc *Scenario) submitKeyValueRuntimeGetQuery(
	ctx context.Context,
	id common.Namespace,
	key string,
	round uint64,
) (string, error) {
	sc.Logger.Info("querying k/v pair",
		"key", key,
		"round", round,
	)

	args := struct {
		Key string `json:"key"`
	}{
		Key: key,
	}

	return sc.submitAndDecodeRuntimeQuery(ctx, id, round, "get", args)
}

func (sc *Scenario) submitConsensusTransferTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	transfer staking.Transfer,
) error {
	sc.Logger.Info("submitting consensus transfer",
		"transfer", transfer,
	)

	_, err := sc.submitRuntimeTx(ctx, id, nonce, "consensus_transfer", struct {
		Transfer staking.Transfer `json:"transfer"`
	}{
		Transfer: transfer,
	})
	if err != nil {
		return fmt.Errorf("failed to submit consensus transfer: %w", err)
	}

	return nil
}

func (sc *Scenario) submitConsensusAccountsTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
) error {
	sc.Logger.Info("submitting consensus accounts query")

	_, err := sc.submitRuntimeTx(ctx, id, nonce, "consensus_accounts", nil)
	if err != nil {
		return fmt.Errorf("failed to submit consensus_accounts query: %w", err)
	}
	// TODO: The old test printed out the accounts and delegations, but
	// it's not like it validated them or anything.

	return nil
}

func drbgFromSeed(domainSep, seed []byte) (rand.Source64, error) {
	h := hash.NewFromBytes(seed)
	drbg, err := drbg.New(
		crypto.SHA512_256,
		h[:],
		nil,
		domainSep,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize drbg: %w", err)
	}

	return mathrand.New(drbg), nil
}
