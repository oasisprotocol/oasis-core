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

var BasicKVTestClient = NewKeyValueTestClient()

// KeyValueTestClient is a client that exercises the simple key-value
// test runtime.
type KeyValueTestClient struct {
	sc *runtimeImpl

	seed   string
	repeat bool

	ctx      context.Context
	cancelFn context.CancelFunc
	errCh    chan error
}

func (cli *KeyValueTestClient) Init(scenario *runtimeImpl) error {
	cli.sc = scenario
	return nil
}

func (cli *KeyValueTestClient) Start(ctx context.Context, childEnv *env.Env) error {
	cli.ctx = ctx

	subCtx, cancelFn := context.WithCancel(ctx)
	cli.errCh = make(chan error)
	cli.cancelFn = cancelFn

	go func() {
		cli.errCh <- cli.workload(subCtx)
	}()

	return nil
}

func (cli *KeyValueTestClient) Wait() error {
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

func (cli *KeyValueTestClient) Kill() error {
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

func (cli *KeyValueTestClient) Clone() TestClient {
	ncli := NewKeyValueTestClient().WithSeed(cli.seed)
	if cli.repeat {
		ncli = ncli.WithRepeat()
	}
	return ncli
}

func (cli *KeyValueTestClient) WithSeed(seed string) *KeyValueTestClient {
	cli.seed = seed
	return cli
}

func (cli *KeyValueTestClient) WithRepeat() *KeyValueTestClient {
	cli.repeat = true
	return cli
}

func (cli *KeyValueTestClient) workload(ctx context.Context) error {
	// Initialize the nonce DRBG.
	rng, err := drbgFromSeed(
		[]byte("oasis-core/oasis-test-runner/e2e/runtime/kv"),
		[]byte(cli.seed),
	)
	if err != nil {
		return err
	}

	cli.sc.Logger.Info("initializing simple key/value runtime!")

	const (
		myKey = "hello_key"

		myLongKey   = "I laud Agni the priest, the divine minister of sacrifice, who invokes the gods, and is the most rich in gems."
		myLongValue = "May Agni, the invoker, the sage, the true, the most renowned, a god, come hither with the gods!"
	)

	// Check whether Runtime ID is also set remotely.
	//
	// XXX: This would check that the response is sensible but the Rust
	// side `to_string()` returns `8000…0000`, and the original Rust
	// test client was doing a string compare so no one ever noticed
	// that truncated values were being compared.
	if _, err = cli.sc.submitKeyValueRuntimeGetRuntimeIDTx(ctx, runtimeID); err != nil {
		return fmt.Errorf("failed to query remote runtime ID: %w", err)
	}

	for iter := 0; ; iter++ {
		var resp string

		cli.sc.Logger.Info("beginning client loop",
			"iteration", iter,
		)

		// Test simple [set,get] calls.
		myValue := fmt.Sprintf("hello_value_from_%s:%d", runtimeID, iter)
		cli.sc.Logger.Info("storing k/v pair to database",
			"key", myKey,
			"value", myValue,
		)
		if resp, err = cli.sc.submitKeyValueRuntimeInsertTx(
			ctx,
			runtimeID,
			myKey,
			myValue,
			rng.Uint64(),
		); err != nil {
			return fmt.Errorf("failed to insert k/v pair: %w", err)
		}
		if iter == 0 && resp != "" {
			return fmt.Errorf("k/v pair already exists: '%v'", resp)
		}

		cli.sc.Logger.Info("checking if key exists and has the correct value")
		resp, err = cli.sc.submitKeyValueRuntimeGetTx(
			ctx,
			runtimeID,
			myKey,
			rng.Uint64(),
		)
		if err != nil {
			return err
		}
		if resp != myValue {
			return fmt.Errorf("key does not have expected value (Got: '%v', Expected: '%v')", resp, myValue)
		}

		// Test [set, get] long key calls
		cli.sc.Logger.Info("storing long k/v pair to database",
			"key", myLongKey,
			"value", myLongValue,
		)
		if resp, err = cli.sc.submitKeyValueRuntimeInsertTx(
			ctx,
			runtimeID,
			myLongKey,
			myLongValue,
			rng.Uint64(),
		); err != nil {
			return fmt.Errorf("failed to insert k/v pair: %w", err)
		}
		if iter == 0 && resp != "" {
			return fmt.Errorf("k/v pair already exists: '%v'", resp)
		}

		if err = cli.sc.submitConsensusXferTx(
			ctx,
			runtimeID,
			staking.Transfer{},
			rng.Uint64(),
		); err != nil {
			return fmt.Errorf("failed to submit consensus transfer: %w", err)
		}

		cli.sc.Logger.Info("checking if long key exists and has the correct value")
		if resp, err = cli.sc.submitKeyValueRuntimeGetTx(
			ctx,
			runtimeID,
			myLongKey,
			rng.Uint64(),
		); err != nil {
			return err
		}
		if resp != myLongValue {
			return fmt.Errorf("key does not have expected value (Got: '%v', Expected: '%v')", resp, myLongValue)
		}

		if !cli.repeat {
			break
		}
	}

	// Test submission and processing of incoming messages.
	cli.sc.Logger.Info("testing incoming runtime messages")
	const (
		inMsgKey   = "in_msg"
		inMsgValue = "hello world from inmsg"
	)
	err = cli.sc.submitRuntimeInMsg(ctx, runtimeID, "insert", struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		Nonce uint64 `json:"nonce"`
	}{
		Key:   inMsgKey,
		Value: inMsgValue,
		Nonce: rng.Uint64(),
	})
	if err != nil {
		return fmt.Errorf("failed to submit 'insert' incoming runtime message: %w", err)
	}

	resp, err := cli.sc.submitKeyValueRuntimeGetTx(ctx, runtimeID, inMsgKey, rng.Uint64())
	if err != nil {
		return err
	}
	if resp != inMsgValue {
		return fmt.Errorf("key does not have expected value (got: '%s', expected: '%s')", resp, inMsgValue)
	}

	cli.sc.Logger.Info("testing consensus queries")
	if _, err = cli.sc.submitRuntimeTx(ctx, runtimeID, "consensus_accounts", nil); err != nil {
		return fmt.Errorf("failed to submit consensus_accounts query: %w", err)
	}
	// TODO: The old test printed out the accounts and delegations, but
	// it's not like it validated them or anything.

	cli.sc.Logger.Info("simple k/v client finished")

	return nil
}

func NewKeyValueTestClient() *KeyValueTestClient {
	return &KeyValueTestClient{
		seed: "seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed",
	}
}

func (sc *runtimeImpl) submitKeyValueRuntimeInsertTx(
	ctx context.Context,
	id common.Namespace,
	key, value string,
	nonce uint64,
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, id, "insert", struct {
		Key   string `json:"key"`
		Value string `json:"value"`
		Nonce uint64 `json:"nonce"`
	}{
		Key:   key,
		Value: value,
		Nonce: nonce,
	})
	if err != nil {
		return "", fmt.Errorf("failed to submit insert tx to runtime: %w", err)
	}

	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
}

func (sc *runtimeImpl) submitKeyValueRuntimeGetTx(
	ctx context.Context,
	id common.Namespace,
	key string,
	nonce uint64,
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, "get", struct {
		Key   string `json:"key"`
		Nonce uint64 `json:"nonce"`
	}{
		Key:   key,
		Nonce: nonce,
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

func (sc *runtimeImpl) submitKeyValueRuntimeGetRuntimeIDTx(
	ctx context.Context,
	id common.Namespace,
) (string, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, "get_runtime_id", nil)
	if err != nil {
		return "", fmt.Errorf("failed to submit get_runtime_id tx to runtime: %w", err)
	}

	// For some reason I'm too stupid to understand the response is returned
	// as a string of all things.
	var rsp string
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return "", fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
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
