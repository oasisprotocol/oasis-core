package runtime

import (
	"context"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

type LongTermMode int

const (
	ModePart1 LongTermMode = iota
	ModePart1NoMsg
	ModePart2
)

type LongTermTestClient struct {
	sc *runtimeImpl

	mode LongTermMode
	seed string

	ctx      context.Context
	cancelFn context.CancelFunc
	errCh    chan error
}

func (cli *LongTermTestClient) Init(scenario *runtimeImpl) error {
	cli.sc = scenario
	return nil
}

func (cli *LongTermTestClient) Start(ctx context.Context, childEnv *env.Env) error {
	cli.ctx = ctx

	subCtx, cancelFn := context.WithCancel(ctx)
	cli.errCh = make(chan error)
	cli.cancelFn = cancelFn

	go func() {
		cli.errCh <- cli.workload(subCtx)
	}()

	return nil
}

func (cli *LongTermTestClient) Wait() error {
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

func (cli *LongTermTestClient) Clone() TestClient {
	return NewLongTermTestClient().WithSeed(cli.seed).WithMode(cli.mode)
}

func (cli *LongTermTestClient) WithSeed(seed string) *LongTermTestClient {
	cli.seed = seed
	return cli
}

func (cli *LongTermTestClient) WithMode(mode LongTermMode) *LongTermTestClient {
	cli.mode = mode
	return cli
}

func (cli *LongTermTestClient) workload(ctx context.Context) error {
	// Initialize the nonce DRBG.
	rng, err := drbgFromSeed(
		[]byte("oasis-core/oasis-test-runner/e2e/runtime/longterm"),
		[]byte(cli.seed),
	)
	if err != nil {
		return err
	}

	cli.sc.Logger.Info("initializing simple key/value runtime!")

	const (
		myKey   = "my_key"
		myValue = "my_value"
	)

	switch cli.mode {
	case ModePart1, ModePart1NoMsg:
		cli.sc.Logger.Info("inserting k/v pair")
		if _, err = cli.sc.submitKeyValueRuntimeInsertTx(
			ctx,
			runtimeID,
			myKey,
			myValue,
			rng.Uint64(),
		); err != nil {
			return fmt.Errorf("failed to insert k/v pair: %w", err)
		}

		cli.sc.Logger.Info("checking if key exists and has the correct value")
		resp, err := cli.sc.submitKeyValueRuntimeGetTx(
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

		if cli.mode != ModePart1NoMsg {
			cli.sc.Logger.Info("testing runtime message emission")
			if err = cli.sc.submitConsensusXferTx(
				ctx,
				runtimeID,
				staking.Transfer{},
				rng.Uint64(),
			); err != nil {
				return fmt.Errorf("failed to submit consensus transfer: %w", err)
			}
		}
	case ModePart2:
		cli.sc.Logger.Info("checking (again) if key exists and has the correct value")
		resp, err := cli.sc.submitKeyValueRuntimeGetTx(
			ctx,
			runtimeID,
			myKey,
			rng.Uint64(),
		)
		if err != nil {
			return err
		}
		if resp != myValue {
			// key should still exist in db
			return fmt.Errorf("key does not have expected value (Got: '%v', Expected: '%v')", resp, myValue)
		}
	}

	return nil
}

func NewLongTermTestClient() *LongTermTestClient {
	return &LongTermTestClient{
		seed: "seeeeeeeeeeeeeeeeeeeeeeeeeeeeeed",
		mode: ModePart1,
	}
}
