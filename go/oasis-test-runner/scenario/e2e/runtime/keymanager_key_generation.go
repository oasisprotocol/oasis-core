package runtime

import (
	"context"
	"fmt"
	"reflect"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
)

// KeymanagerKeyGeneration is the keymanager key generation scenario.
//
// It uses encryption and decryption transactions provided by the
// simple key/value runtime to test whether the key manager client
// can retrieve private and public ephemeral keys from the key manager
// and if the latter generates those according to the specifications.
var KeymanagerKeyGeneration scenario.Scenario = newKmKeyGenerationImpl()

type kmKeyGenerationImpl struct {
	runtimeImpl
}

func newKmKeyGenerationImpl() scenario.Scenario {
	return &kmKeyGenerationImpl{
		runtimeImpl: *newRuntimeImpl("keymanager-key-generation", BasicKVEncTestClient),
	}
}

func (sc *kmKeyGenerationImpl) Fixture() (*oasis.NetworkFixture, error) {
	return sc.runtimeImpl.Fixture()
}

func (sc *kmKeyGenerationImpl) Clone() scenario.Scenario {
	return &kmKeyGenerationImpl{
		runtimeImpl: *sc.runtimeImpl.Clone().(*runtimeImpl),
	}
}

func (sc *kmKeyGenerationImpl) Run(childEnv *env.Env) error {
	// Start the network, but no need to start the client. Just ensure it
	// is synced.
	ctx := context.Background()
	if err := sc.runtimeImpl.startNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Initialize the nonce DRBG.
	rng, err := drbgFromSeed(
		[]byte("oasis-core/oasis-test-runner/e2e/runtime/keymanager-key-generation"),
		[]byte("keymanager-key-generation"),
	)
	if err != nil {
		return err
	}

	// Data needed for encryption and decryption.
	keyPairID := "key pair id"
	plaintext := []byte("The quick brown fox jumps over the lazy dog")

	epoch, err := sc.Net.Controller().Beacon.GetEpoch(ctx, consensus.HeightLatest)
	if err != nil {
		return fmt.Errorf("failed to get epoch at the latest height: %w", err)
	}

	// Encrypt plaintext using ephemeral public key for the current epoch.
	// Successful encryption indicates that the key manager generated
	// an ephemeral public key.
	sc.Logger.Info("encrypting plaintext")
	ciphertext, err := sc.submitKeyValueRuntimeEncryptTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		epoch,
		keyPairID,
		plaintext,
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt plaintext: %w", err)
	}

	// Decrypt ciphertext using ephemeral private key for the current epoch.
	// Successful decryption indicates that the key manager generates
	// matching public and private ephemeral keys.
	sc.Logger.Info("decrypting ciphertext")
	decrypted, err := sc.submitKeyValueRuntimeDecryptTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		epoch,
		keyPairID,
		ciphertext,
	)
	if err != nil {
		return fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}
	if !reflect.DeepEqual(decrypted, plaintext) {
		return fmt.Errorf("decrypted ciphertext does match the plaintext (got: '%s', expected: '%s')", decrypted, plaintext)
	}

	// Decrypt ciphertext using ephemeral private key for the previous epoch.
	// As ephemeral keys are derived from the epoch, the decryption should
	// fail.
	sc.Logger.Info("decrypting ciphertext with wrong epoch")
	decrypted, err = sc.submitKeyValueRuntimeDecryptTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		epoch-1,
		keyPairID,
		ciphertext,
	)
	if err == nil && reflect.DeepEqual(decrypted, plaintext) {
		return fmt.Errorf("decryption with wrong epoch should fail or produce garbage")
	}

	// Decrypt ciphertext using ephemeral private key derived from wrong
	// key pair id. As ephemeral keys are derived from the id, the decryption
	// should fail.
	sc.Logger.Info("decrypting ciphertext with wrong key pair id")
	decrypted, err = sc.submitKeyValueRuntimeDecryptTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		epoch,
		"wrong key pair id",
		ciphertext,
	)
	if err == nil && reflect.DeepEqual(decrypted, plaintext) {
		return fmt.Errorf("decryption with wrong key pair id should fail or produce garbage")
	}

	// Change epoch and test what happens if epoch is invalid,
	// i.e. too old or somewhere in the future.
	epoch = epoch + 10

	// Encrypt plaintext using epoch that is in the future.
	// As public ephemeral keys are not allowed to be derived
	// for future epoch neither for epoch that are too far
	// in the past, the encryption should fail.
	sc.Logger.Info("encrypting plaintext with invalid epoch")
	_, err = sc.submitKeyValueRuntimeEncryptTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		epoch,
		keyPairID,
		plaintext,
	)
	if err == nil {
		return fmt.Errorf("encryption with invalid epoch should fail")
	}

	// Decrypt ciphertext using epoch that is in the future.
	// The same rule holds for private ephemeral keys,
	// so the encryption should fail.
	sc.Logger.Info("decrypting ciphertext with invalid epoch")
	_, err = sc.submitKeyValueRuntimeDecryptTx(
		ctx,
		runtimeID,
		rng.Uint64(),
		epoch,
		keyPairID,
		ciphertext,
	)
	if err == nil {
		return fmt.Errorf("decryption with invalid epoch should fail")
	}

	// Check the logs whether any issues were detected.
	err = sc.Net.CheckLogWatchers()
	if err != nil {
		return err
	}

	return nil
}

func (sc *kmKeyGenerationImpl) submitKeyValueRuntimeEncryptTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	epoch beacon.EpochTime,
	keyPairID string,
	plaintext []byte,
) ([]byte, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, nonce, "encrypt", struct {
		Epoch     uint64 `json:"epoch"`
		KeyPairID string `json:"key_pair_id"`
		Plaintext []byte `json:"plaintext"`
	}{
		Epoch:     uint64(epoch),
		KeyPairID: keyPairID,
		Plaintext: plaintext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit encrypt tx to runtime: %w", err)
	}

	var rsp []byte
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
}

func (sc *kmKeyGenerationImpl) submitKeyValueRuntimeDecryptTx(
	ctx context.Context,
	id common.Namespace,
	nonce uint64,
	epoch beacon.EpochTime,
	keyPairID string,
	ciphertext []byte,
) ([]byte, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, runtimeID, nonce, "decrypt", struct {
		Epoch      uint64 `json:"epoch"`
		KeyPairID  string `json:"key_pair_id"`
		Ciphertext []byte `json:"ciphertext"`
	}{
		Epoch:      uint64(epoch),
		KeyPairID:  keyPairID,
		Ciphertext: ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to submit decrypt tx to runtime: %w", err)
	}

	var rsp []byte
	if err = cbor.Unmarshal(rawRsp, &rsp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response from runtime: %w", err)
	}

	return rsp, nil
}
