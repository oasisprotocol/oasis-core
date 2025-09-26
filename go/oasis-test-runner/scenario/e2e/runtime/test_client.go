package runtime

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
)

// GetCall represents a call to get a key-value pair.
type GetCall struct {
	Key        string `json:"key"`
	Generation uint64 `json:"generation,omitempty"`
	ChurpID    uint8  `json:"churp_id,omitempty"`
}

// RemoveCall represents a call to remove a key-value pair.
type RemoveCall struct {
	Key        string `json:"key"`
	Generation uint64 `json:"generation,omitempty"`
	ChurpID    uint8  `json:"churp_id,omitempty"`
}

// InsertCall represents a call to insert a key-value pair.
type InsertCall struct {
	Key        string `json:"key"`
	Value      string `json:"value"`
	Generation uint64 `json:"generation,omitempty"`
	ChurpID    uint8  `json:"churp_id,omitempty"`
}

// EncryptCall represents a call to encrypt a plaintext.
type EncryptCall struct {
	Epoch     beacon.EpochTime `json:"epoch"`
	KeyPairID string           `json:"key_pair_id"`
	Plaintext []byte           `json:"plaintext"`
}

// DecryptCall represents a call to decrypt a ciphertext.
type DecryptCall struct {
	Epoch      beacon.EpochTime `json:"epoch"`
	KeyPairID  string           `json:"key_pair_id"`
	Ciphertext []byte           `json:"ciphertext"`
}

// TransferCall represents a call to transfer tokens.
type TransferCall struct {
	Transfer staking.Transfer `json:"transfer"`
}

// NonceRegistry tracks and manages nonces for each sender.
type NonceRegistry struct {
	mu     sync.Mutex
	nonces map[string]uint64
}

// NewNonceRegistry creates a new nonce registry.
func NewNonceRegistry() *NonceRegistry {
	return &NonceRegistry{
		nonces: make(map[string]uint64),
	}
}

// Next returns the next nonce for the given sender.
func (r *NonceRegistry) Next(sender string) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()

	nonce := r.nonces[sender]
	r.nonces[sender]++
	return nonce
}

// TestClient is a client that exercises a pre-determined workload against
// the simple key-value runtime.
type TestClient struct {
	sc *Scenario

	scenario TestClientScenario

	sender string
	seed   string

	ctx      context.Context
	cancelFn context.CancelFunc
	errCh    chan error
}

// NewTestClient creates a new test client.
func NewTestClient() *TestClient {
	return &TestClient{
		sender:   "sender",
		seed:     "seed",
		scenario: func(_ func(req any) error) error { return nil },
	}
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
		sender:   cli.sender,
		seed:     cli.seed,
		scenario: cli.scenario,
	}
}

// WithSeed sets the seed.
func (cli *TestClient) WithSeed(seed string) *TestClient {
	cli.seed = seed
	return cli
}

// WithSender sets the sender.
func (cli *TestClient) WithSender(sender string) *TestClient {
	cli.sender = sender
	return cli
}

// WithScenario sets the scenario.
func (cli *TestClient) WithScenario(scenario TestClientScenario) *TestClient {
	cli.scenario = scenario
	return cli
}

func (cli *TestClient) workload(ctx context.Context) error {
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

	if err := cli.scenario(func(req any) error {
		return cli.submit(ctx, req)
	}); err != nil {
		return err
	}

	cli.sc.Logger.Info("k/v runtime test client finished")

	return nil
}

func (cli *TestClient) submit(ctx context.Context, req any) error {
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
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
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
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
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
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
			req.Key,
			req.Value,
			req.Generation,
			req.ChurpID,
			req.Kind,
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
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
			req.Key,
			req.Generation,
			req.ChurpID,
			req.Kind,
		)
		if err != nil {
			return err
		}
		if rsp != req.Response {
			return fmt.Errorf("response does not have expected value (got: '%v', expected: '%v')", rsp, req.Response)
		}

	case KeyExistsTx:
		rsp, err := cli.sc.submitKeyValueRuntimeGetTx(
			ctx,
			KeyValueRuntimeID,
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
			req.Key,
			req.Generation,
			req.ChurpID,
			req.Kind,
		)
		if err != nil {
			return err
		}
		if len(rsp) == 0 {
			return fmt.Errorf("response does not have non-zero value")
		}

	case RemoveKeyValueTx:
		rsp, err := cli.sc.submitKeyValueRuntimeRemoveTx(
			ctx,
			KeyValueRuntimeID,
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
			req.Key,
			req.Generation,
			req.ChurpID,
			req.Kind,
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
			cli.sender,
			cli.sc.Nonces.Next(cli.sender),
			req.Key,
			req.Value,
			req.Generation,
			req.ChurpID,
			req.Kind,
		)
		if err != nil {
			return err
		}

	case GetRuntimeIDTx:
		_, err := cli.sc.submitKeyValueRuntimeGetRuntimeIDTx(ctx, KeyValueRuntimeID, cli.sender, cli.sc.Nonces.Next(cli.sender))
		if err != nil {
			return err
		}

	case ConsensusTransferTx:
		err := cli.sc.submitConsensusTransferTx(ctx, KeyValueRuntimeID, cli.sender, cli.sc.Nonces.Next(cli.sender), staking.Transfer{})
		if err != nil {
			return err
		}

	case ConsensusAccountsTx:
		err := cli.sc.submitConsensusAccountsTx(ctx, KeyValueRuntimeID, cli.sender, cli.sc.Nonces.Next(cli.sender))
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("invalid k/v runtime test client scenario command")
	}

	return nil
}

func (sc *Scenario) submitRuntimeTxAndDecode(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	method string,
	args any,
	rsp any,
) error {
	rawRsp, err := sc.submitRuntimeTx(ctx, id, sender, nonce, method, args)
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
	sender string,
	nonce uint64,
	method string,
	args any,
) (string, error) {
	var rsp string
	if err := sc.submitRuntimeTxAndDecode(ctx, id, sender, nonce, method, args, &rsp); err != nil {
		return "", err
	}
	return rsp, nil
}

func (sc *Scenario) submitRuntimeTxAndDecodeByteSlice(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	method string,
	args any,
) ([]byte, error) {
	var rsp []byte
	if err := sc.submitRuntimeTxAndDecode(ctx, id, sender, nonce, method, args, &rsp); err != nil {
		return nil, err
	}
	return rsp, nil
}

func (sc *Scenario) submitKeyValueRuntimeEncryptTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
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

	args := EncryptCall{
		Epoch:     epoch,
		KeyPairID: keyPairID,
		Plaintext: plaintext,
	}

	return sc.submitRuntimeTxAndDecodeByteSlice(ctx, id, sender, nonce, "encrypt", args)
}

func (sc *Scenario) submitKeyValueRuntimeDecryptTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
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

	args := DecryptCall{
		Epoch:      epoch,
		KeyPairID:  keyPairID,
		Ciphertext: ciphertext,
	}

	return sc.submitRuntimeTxAndDecodeByteSlice(ctx, id, sender, nonce, "decrypt", args)
}

func (sc *Scenario) submitKeyValueRuntimeInsertTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	key, value string,
	generation uint64,
	churpID uint8,
	kind uint,
) (string, error) {
	sc.Logger.Info("inserting k/v pair",
		"key", key,
		"value", value,
		"generation", generation,
		"churp_id", churpID,
		"kind", kind,
	)

	var method string
	switch kind {
	case plaintextTxKind:
		method = "insert"
	case encryptedWithSecretsTxKind:
		method = "enc_insert"
	case encryptedWithChurpTxKind:
		method = "churp_insert"
	}

	args := InsertCall{
		Key:        key,
		Value:      value,
		Generation: generation,
		ChurpID:    churpID,
	}

	return sc.submitRuntimeTxAndDecodeString(ctx, id, sender, nonce, method, args)
}

func (sc *Scenario) submitKeyValueRuntimeGetTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	key string,
	generation uint64,
	churpID uint8,
	kind uint,
) (string, error) {
	sc.Logger.Info("retrieving k/v pair",
		"key", key,
		"generation", generation,
		"churp_id", churpID,
		"kind", kind,
	)

	var method string
	switch kind {
	case plaintextTxKind:
		method = "get"
	case encryptedWithSecretsTxKind:
		method = "enc_get"
	case encryptedWithChurpTxKind:
		method = "churp_get"
	}

	args := GetCall{
		Key:        key,
		Generation: generation,
		ChurpID:    churpID,
	}

	return sc.submitRuntimeTxAndDecodeString(ctx, id, sender, nonce, method, args)
}

func (sc *Scenario) submitKeyValueRuntimeRemoveTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	key string,
	generation uint64,
	churpID uint8,
	kind uint,
) (string, error) {
	sc.Logger.Info("removing k/v pair",
		"key", key,
		"generation", generation,
		"churp_id", churpID,
		"kind", kind,
	)

	var method string
	switch kind {
	case plaintextTxKind:
		method = "remove"
	case encryptedWithSecretsTxKind:
		method = "enc_remove"
	case encryptedWithChurpTxKind:
		method = "churp_remove"
	}

	args := RemoveCall{
		Key:        key,
		Generation: generation,
		ChurpID:    churpID,
	}

	return sc.submitRuntimeTxAndDecodeString(ctx, id, sender, nonce, method, args)
}

func (sc *Scenario) submitKeyValueRuntimeGetRuntimeIDTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
) (string, error) {
	sc.Logger.Info("retrieving runtime ID")

	rsp, err := sc.submitRuntimeTxAndDecodeString(ctx, id, sender, nonce, "get_runtime_id", nil)
	if err != nil {
		return "", fmt.Errorf("failed to query remote runtime ID: %w", err)
	}

	return rsp, nil
}

func (sc *Scenario) submitKeyValueRuntimeInsertMsg(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	key, value string,
	generation uint64,
	churpID uint8,
	kind uint,
) error {
	sc.Logger.Info("submitting incoming runtime message",
		"key", key,
		"value", value,
		"generation", generation,
		"churp_id", churpID,
		"kind", kind,
	)

	var method string
	switch kind {
	case plaintextTxKind:
		method = "insert"
	case encryptedWithSecretsTxKind:
		method = "enc_insert"
	case encryptedWithChurpTxKind:
		method = "churp_insert"
	}

	args := InsertCall{
		Key:        key,
		Value:      value,
		Generation: generation,
		ChurpID:    churpID,
	}

	return sc.submitRuntimeInMsg(ctx, id, sender, nonce, method, args)
}

func (sc *Scenario) submitAndDecodeRuntimeQuery(
	ctx context.Context,
	id common.Namespace,
	round uint64,
	method string,
	args any,
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

	args := GetCall{
		Key: key,
	}

	return sc.submitAndDecodeRuntimeQuery(ctx, id, round, "get", args)
}

func (sc *Scenario) submitConsensusTransferTx(
	ctx context.Context,
	id common.Namespace,
	sender string,
	nonce uint64,
	transfer staking.Transfer,
) error {
	sc.Logger.Info("submitting consensus transfer",
		"transfer", transfer,
	)

	_, err := sc.submitRuntimeTx(ctx, id, sender, nonce, "consensus_transfer", TransferCall{
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
	sender string,
	nonce uint64,
) error {
	sc.Logger.Info("submitting consensus accounts query")

	_, err := sc.submitRuntimeTx(ctx, id, sender, nonce, "consensus_accounts", nil)
	if err != nil {
		return fmt.Errorf("failed to submit consensus_accounts query: %w", err)
	}
	// TODO: The old test printed out the accounts and delegations, but
	// it's not like it validated them or anything.

	return nil
}
