package runtime

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"math/rand"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/drbg"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/mathrand"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// TestClient is a client that exercises a pre-determined workload against
// the simple key-value runtime.
type TestClient struct {
	sc *Scenario

	scenario TestClientScenario

	seed string
	rng  rand.Source64

	ctx      context.Context
	cancelFn context.CancelFunc
	errCh    chan error
}

// Init initializes the test client.
func (cli *TestClient) Init(scenario *Scenario) error {
	cli.sc = scenario
	return nil
}

// Start starts the test client in a background.
func (cli *TestClient) Start(ctx context.Context, _ *env.Env) error {
	cli.ctx = ctx

	subCtx, cancelFn := context.WithCancel(ctx)
	cli.errCh = make(chan error)
	cli.cancelFn = cancelFn

	go func() {
		cli.errCh <- cli.workload(subCtx)
	}()

	return nil
}

// Wait waits the client to finish its work.
func (cli *TestClient) Wait() error {
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

// Stop stops the client.
func (cli *TestClient) Stop() error {
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

// Clone returns a clone of a test client instance, in a state that is ready for Init.
func (cli *TestClient) Clone() *TestClient {
	return &TestClient{
		seed:     cli.seed,
		scenario: cli.scenario,
	}
}

// WithSeed sets the seed.
func (cli *TestClient) WithSeed(seed string) *TestClient {
	cli.seed = seed
	cli.rng = nil
	return cli
}

// WithScenario sets the scenario.
func (cli *TestClient) WithScenario(scenario TestClientScenario) *TestClient {
	cli.scenario = scenario
	return cli
}

func (cli *TestClient) workload(ctx context.Context) error {
	if cli.rng == nil {
		// Initialize the nonce DRBG.
		rng, err := drbgFromSeed(
			[]byte("oasis-core/oasis-test-runner/e2e/runtime/test-client"),
			[]byte(cli.seed),
		)
		if err != nil {
			return err
		}
		cli.rng = rng
	}

	cli.sc.Logger.Info("waiting for key managers to generate the first master secret")

	if _, err := cli.sc.WaitMasterSecret(ctx, 0); err != nil {
		return fmt.Errorf("first master secret not generated: %w", err)
	}
	// The CometBFT verifier is one block behind, so wait for an additional
	// two blocks to ensure that the first secret has been loaded.
	if _, err := cli.sc.WaitBlocks(ctx, 2); err != nil {
		return fmt.Errorf("failed to wait two blocks: %w", err)
	}

	cli.sc.Logger.Info("starting k/v runtime test client")

	if err := cli.scenario(func(req interface{}) error {
		return cli.submit(ctx, req, cli.rng)
	}); err != nil {
		return err
	}

	cli.sc.Logger.Info("k/v runtime test client finished")

	return nil
}

func (cli *TestClient) submit(ctx context.Context, req interface{}, rng rand.Source64) error {
	switch req := req.(type) {
	case KeyValueQuery:
		rsp, err := cli.sc.submitKeyValueRuntimeGetQuery(
			ctx,
			KeyValueRuntimeID,
			req.Key,
			req.Round,
		)
		if err != nil {
			return fmt.Errorf("failed to query k/v pair: %w", err)
		}
		if rsp != req.Response {
			return fmt.Errorf("response does not have expected value (got: '%v', expected: '%v')", rsp, req.Response)
		}

	case EncryptDecryptTx:
		ciphertext, err := cli.sc.submitKeyValueRuntimeEncryptTx(
			ctx,
			KeyValueRuntimeID,
			rng.Uint64(),
			req.Epoch,
			req.KeyPairID,
			req.Message,
		)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}
		plaintext, err := cli.sc.submitKeyValueRuntimeDecryptTx(
			ctx,
			KeyValueRuntimeID,
			rng.Uint64(),
			req.Epoch,
			req.KeyPairID,
			ciphertext,
		)
		if err != nil {
			return fmt.Errorf("failed to decrypt ciphertext: %w", err)
		}
		if !bytes.Equal(plaintext, req.Message) {
			return fmt.Errorf("decrypted message does not have expected value (got: '%v', expected: '%v')", plaintext, req.Message)
		}

	case InsertKeyValueTx:
		rsp, err := cli.sc.submitKeyValueRuntimeInsertTx(
			ctx,
			KeyValueRuntimeID,
			rng.Uint64(),
			req.Key,
			req.Value,
			req.Encrypted,
			req.Generation,
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
			KeyValueRuntimeID,
			rng.Uint64(),
			req.Key,
			req.Encrypted,
			req.Generation,
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
			KeyValueRuntimeID,
			rng.Uint64(),
			req.Key,
			req.Encrypted,
			req.Generation,
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
			KeyValueRuntimeID,
			rng.Uint64(),
			req.Key,
			req.Value,
			req.Encrypted,
			req.Generation,
		)
		if err != nil {
			return err
		}

	case GetRuntimeIDTx:
		_, err := cli.sc.submitKeyValueRuntimeGetRuntimeIDTx(ctx, KeyValueRuntimeID, rng.Uint64())
		if err != nil {
			return err
		}

	case ConsensusTransferTx:
		err := cli.sc.submitConsensusTransferTx(ctx, KeyValueRuntimeID, rng.Uint64(), staking.Transfer{})
		if err != nil {
			return err
		}

	case ConsensusAccountsTx:
		err := cli.sc.submitConsensusAccountsTx(ctx, KeyValueRuntimeID, rng.Uint64())
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid k/v runtime test client scenario command")
	}

	return nil
}

func NewTestClient() *TestClient {
	return &TestClient{
		seed:     "seed",
		scenario: func(submit func(req interface{}) error) error { return nil },
	}
}

func (sc *Scenario) submitRuntimeTxAndDecode(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	method string,
	args interface{},
	rsp interface{},
) error {
	rawRsp, err := sc.submitRuntimeTx(ctx, id, nonce, method, args)
	if err != nil {
		return fmt.Errorf("failed to submit %s tx to runtime: %w", method, err)
	}

	if err = cbor.Unmarshal(rawRsp, rsp); err != nil {
		return fmt.Errorf("failed to unmarshal %s tx response from runtime: %w", method, err)
	}

	return nil
}

func (sc *Scenario) submitRuntimeTxAndDecodeString(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	method string,
	args interface{},
) (string, error) {
	var rsp string
	if err := sc.submitRuntimeTxAndDecode(ctx, id, nonce, method, args, &rsp); err != nil {
		return "", err
	}
	return rsp, nil
}

func (sc *Scenario) submitRuntimeTxAndDecodeByteSlice(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	method string,
	args interface{},
) ([]byte, error) {
	var rsp []byte
	if err := sc.submitRuntimeTxAndDecode(ctx, id, nonce, method, args, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (sc *Scenario) submitKeyValueRuntimeEncryptTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	epoch beacon.EpochTime,
	keyPairID string,
	plaintext []byte,
) ([]byte, error) {
	sc.Logger.Info("encrypting",
		"epoch", epoch,
		"key_pair_id", keyPairID,
		"plaintext", plaintext,
	)

	args := struct {
		Epoch     beacon.EpochTime `json:"epoch"`
		KeyPairID string           `json:"key_pair_id"`
		Plaintext []byte           `json:"plaintext"`
	}{
		Epoch:     epoch,
		KeyPairID: keyPairID,
		Plaintext: plaintext,
	}

	return sc.submitRuntimeTxAndDecodeByteSlice(ctx, id, nonce, "encrypt", args)
}

func (sc *Scenario) submitKeyValueRuntimeDecryptTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	epoch beacon.EpochTime,
	keyPairID string,
	ciphertext []byte,
) ([]byte, error) {
	sc.Logger.Info("decrypting",
		"epoch", epoch,
		"key_pair_id", keyPairID,
		"ciphertext", ciphertext,
	)

	args := struct {
		Epoch      beacon.EpochTime `json:"epoch"`
		KeyPairID  string           `json:"key_pair_id"`
		Ciphertext []byte           `json:"ciphertext"`
	}{
		Epoch:      epoch,
		KeyPairID:  keyPairID,
		Ciphertext: ciphertext,
	}

	return sc.submitRuntimeTxAndDecodeByteSlice(ctx, id, nonce, "decrypt", args)
}

func (sc *Scenario) submitKeyValueRuntimeInsertTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key, value string,
	encrypted bool,
	generation uint64,
) (string, error) {
	sc.Logger.Info("inserting k/v pair",
		"key", key,
		"value", value,
		"encrypted", encrypted,
		"generation", generation,
	)

	args := struct {
		Key        string `json:"key"`
		Value      string `json:"value"`
		Generation uint64 `json:"generation,omitempty"`
	}{
		Key:        key,
		Value:      value,
		Generation: generation,
	}

	if encrypted {
		return sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "enc_insert", args)
	}
	return sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "insert", args)
}

func (sc *Scenario) submitKeyValueRuntimeGetTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key string,
	encrypted bool,
	generation uint64,
) (string, error) {
	sc.Logger.Info("retrieving k/v pair",
		"key", key,
		"encrypted", encrypted,
		"generation", generation,
	)

	args := struct {
		Key        string `json:"key"`
		Generation uint64 `json:"generation,omitempty"`
	}{
		Key:        key,
		Generation: generation,
	}

	if encrypted {
		return sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "enc_get", args)
	}
	return sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "get", args)
}

func (sc *Scenario) submitKeyValueRuntimeRemoveTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	key string,
	encrypted bool,
	generation uint64,
) (string, error) {
	sc.Logger.Info("removing k/v pair",
		"key", key,
		"encrypted", encrypted,
		"generation", generation,
	)

	args := struct {
		Key        string `json:"key"`
		Generation uint64 `json:"generation,omitempty"`
	}{
		Key:        key,
		Generation: generation,
	}

	if encrypted {
		return sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "enc_remove", args)
	}
	return sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "remove", args)
}

func (sc *Scenario) submitKeyValueRuntimeGetRuntimeIDTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
) (string, error) {
	sc.Logger.Info("retrieving runtime ID")

	rsp, err := sc.submitRuntimeTxAndDecodeString(ctx, id, nonce, "get_runtime_id", nil)
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
	generation uint64,
) error {
	sc.Logger.Info("submitting incoming runtime message",
		"key", key,
		"value", value,
		"encrypted", encrypted,
		"generation", generation,
	)

	args := struct {
		Key        string `json:"key"`
		Value      string `json:"value"`
		Generation uint64 `json:"generation,omitempty"`
	}{
		Key:        key,
		Value:      value,
		Generation: generation,
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
