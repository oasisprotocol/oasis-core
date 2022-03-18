package runtime

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
)

var BasicKVEncTestClient = NewKeyValueEncTestClient()

// KeyValueEncTestClient is a client that exercises the simple key-value
// test runtime with encryption.
type KeyValueEncTestClient struct {
	sc *runtimeImpl

	seed string
	key  string

	ctx      context.Context
	cancelFn context.CancelFunc
	errCh    chan error
}

func (cli *KeyValueEncTestClient) Init(scenario *runtimeImpl) error {
	cli.sc = scenario
	return nil
}

func (cli *KeyValueEncTestClient) Start(ctx context.Context, childEnv *env.Env) error {
	cli.ctx = ctx

	subCtx, cancelFn := context.WithCancel(ctx)
	cli.errCh = make(chan error)
	cli.cancelFn = cancelFn

	go func() {
		cli.errCh <- cli.workload(subCtx)
	}()

	return nil
}

func (cli *KeyValueEncTestClient) Wait() error {
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

func (cli *KeyValueEncTestClient) Clone() TestClient {
	return NewKeyValueEncTestClient().WithSeed(cli.seed).WithKey(cli.key)
}

func (cli *KeyValueEncTestClient) WithSeed(seed string) *KeyValueEncTestClient {
	cli.seed = seed
	return cli
}

func (cli *KeyValueEncTestClient) WithKey(key string) *KeyValueEncTestClient {
	cli.key = key
	return cli
}

func (cli *KeyValueEncTestClient) workload(ctx context.Context) error {
	// Initialize the nonce DRBG.
	rng, err := drbgFromSeed(
		[]byte("oasis-core/oasis-test-runner/e2e/runtime/kv-enc"),
		[]byte(cli.seed),
	)
	if err != nil {
		return err
	}

	cli.sc.Logger.Info("initializing simple key/value runtime!")

	const myValue = "hello_value"

	cli.sc.Logger.Info("storing k/v pair to database",
		"key", cli.key,
		"value", myValue,
	)
	resp, err := cli.sc.submitKeyValueRuntimeEncInsertTx(
		ctx,
		runtimeID,
		cli.key,
		myValue,
		rng.Uint64(),
	)
	if err != nil {
		return fmt.Errorf("failed to insert k/v pair: %w", err)
	}
	if resp != "" {
		return fmt.Errorf("k/v pair already exists: '%v'", resp)
	}

	cli.sc.Logger.Info("checking if key exists and has the correct value")
	resp, err = cli.sc.submitKeyValueRuntimeEncGetTx(
		ctx,
		runtimeID,
		cli.key,
		rng.Uint64(),
	)
	if err != nil {
		return err
	}
	if resp != myValue {
		return fmt.Errorf("key does not have expected value (Got: '%v', Expected: '%v')", resp, myValue)
	}

	cli.sc.Logger.Info("removing k/v pair")
	if _, err = cli.sc.submitRuntimeTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		"enc_remove",
		struct {
			Key string `json:"key"`
		}{
			Key: cli.key,
		},
	); err != nil {
		return fmt.Errorf("failed to remove k/v pair: %w", err)
	}

	cli.sc.Logger.Info("ensuring k/v pair has been removed")
	resp, err = cli.sc.submitKeyValueRuntimeEncGetTx(
		ctx,
		runtimeID,
		cli.key,
		rng.Uint64(),
	)
	if err != nil {
		return err
	}
	if resp != "" {
		return fmt.Errorf("key still exists in database after removal: '%v'", resp)
	}

	cli.sc.Logger.Info("simple k/v (enc) client finished")

	return nil
}

func NewKeyValueEncTestClient() *KeyValueEncTestClient {
	return &KeyValueEncTestClient{
		key:  "hello_key",
		seed: "seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed",
	}
}

func (sc *runtimeImpl) submitKeyValueRuntimeEncInsertTx(
	ctx context.Context,
	id common.Namespace,
	key, value string,
	nonce uint64,
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, nonce, "enc_insert", struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{
		Key:   key,
		Value: value,
	})
	if err != nil {
		return "", fmt.Errorf("failed to submit enc_insert tx to runtime: %w", err)
	}

	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
}

func (sc *runtimeImpl) submitKeyValueRuntimeEncGetTx(
	ctx context.Context,
	id common.Namespace,
	key string,
	nonce uint64,
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, nonce, "enc_get", struct {
		Key string `json:"key"`
	}{
		Key: key,
	})
	if err != nil {
		return "", fmt.Errorf("failed to submit get tx to runtime: %w", err)
	}

	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
}
