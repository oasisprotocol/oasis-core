package runtime

import (
	"context"
	"fmt"
	"reflect"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// KeymanagerEphemeralSecrets is the keymanager ephemeral secret and ephemeral
// key generation scenario.
//
// It uses encryption and decryption transactions provided by the
// simple key/value runtime to test whether the key manager client
// can retrieve private and public ephemeral keys from the key manager
// and if the latter generates those according to the specifications.
//
// Scenario:
//   - Start one key manager and test ephemeral secrets.
//   - Restart the manager and test that the first secret was lost.
//   - Start all managers and test that ephemeral secrets can be replicated.
//   - Run managers for few epochs and test that everything works.
//   - Publish transactions that use ephemeral keys to encrypt/decrypt messages.
var KeymanagerEphemeralSecrets scenario.Scenario = newKmEphemeralSecretsImpl()

type kmEphemeralSecretsImpl struct {
	Scenario
}

func newKmEphemeralSecretsImpl() scenario.Scenario {
	return &kmEphemeralSecretsImpl{
		Scenario: *NewScenario(
			"keymanager-ephemeral-secrets",
			NewTestClient().WithScenario(InsertRemoveEncWithSecretsScenario),
		),
	}
}

func (sc *kmEphemeralSecretsImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.Scenario.Fixture()
	if err != nil {
		return nil, err
	}

	// Test requires multiple key managers.
	f.Keymanagers = []oasis.KeymanagerFixture{
		{Runtime: 0, Entity: 1},
		{Runtime: 0, Entity: 1, NodeFixture: oasis.NodeFixture{NoAutoStart: true}},
		{Runtime: 0, Entity: 1, NodeFixture: oasis.NodeFixture{NoAutoStart: true}},
	}

	return f, nil
}

func (sc *kmEphemeralSecretsImpl) Clone() scenario.Scenario {
	return &kmEphemeralSecretsImpl{
		Scenario: *sc.Scenario.Clone().(*Scenario),
	}
}

func (sc *kmEphemeralSecretsImpl) Run(ctx context.Context, _ *env.Env) error { // nolint: gocyclo
	// Start the network, but no need to start the client. Just ensure it
	// is synced.
	if err := sc.Scenario.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Fetch runtime to know on which TEE platform the key manager is running.
	rt, err := sc.Net.ClientController().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     KeyManagerRuntimeID,
	})
	if err != nil {
		return err
	}

	// Prepare an RPC client which will be used to query key manager nodes
	// for public ephemeral keys.
	chainContext, err := sc.Net.Controller().Consensus.GetChainContext(ctx)
	if err != nil {
		return err
	}
	rpcClient, err := newKeyManagerRPCClient(chainContext)
	if err != nil {
		return err
	}
	kms := sc.Net.Keymanagers()
	firstKmPeerID, err := rpcClient.addKeyManagerAddrToHost(kms[0])
	if err != nil {
		return err
	}
	secondKmPeerID, err := rpcClient.addKeyManagerAddrToHost(kms[1])
	if err != nil {
		return err
	}
	thirdKmPeerID, err := rpcClient.addKeyManagerAddrToHost(kms[2])
	if err != nil {
		return err
	}

	// Wait until the first key manager is ready.
	if err = sc.WaitKeymanagers(ctx, []int{0}); err != nil {
		return err
	}

	// Wait until the first ephemeral secret is published.
	sc.Logger.Info("waiting for the first ephemeral secret")

	sigSecret, err := sc.WaitEphemeralSecrets(ctx, 1)
	if err != nil {
		return err
	}
	if len(sigSecret.Secret.Secret.Ciphertexts) != 1 {
		return fmt.Errorf("the first ephemeral secret should be encrypted for one enclave only")
	}

	// Wait for the ephemeral secret epoch.
	sc.Logger.Info("waiting for the ephemeral secret epoch",
		"epoch", sigSecret.Secret.Epoch,
	)

	if err = sc.Net.Controller().Beacon.WaitEpoch(ctx, sigSecret.Secret.Epoch); err != nil {
		return err
	}

	// Test that ephemeral key for the previous epoch is not available.
	sc.Logger.Info("testing ephemeral keys - previous epoch",
		"epoch", sigSecret.Secret.Epoch-1,
	)

	key, err := rpcClient.fetchEphemeralPublicKey(ctx, sigSecret.Secret.Epoch-1, firstKmPeerID)
	if err != nil {
		return err
	}
	if key != nil {
		return fmt.Errorf("ephemeral key for epoch %d should not be available", sigSecret.Secret.Epoch-1)
	}

	// Test that ephemeral key for the current epoch is available.
	// When using CometBFT as a backend service we need to retry the query
	// because the verifier is probably one block behind.
	sc.Logger.Info("testing ephemeral keys - current epoch",
		"epoch", sigSecret.Secret.Epoch,
	)

	key, err = rpcClient.fetchEphemeralPublicKeyWithRetry(ctx, sigSecret.Secret.Epoch, firstKmPeerID)
	if err != nil {
		return err
	}
	if key == nil {
		return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
	}

	// Restart the first key manager.
	if err = sc.RestartAndWaitKeymanagers(ctx, []int{0}); err != nil {
		return err
	}

	// Test that ephemeral key for the last epoch is not available after restart.
	sc.Logger.Info("testing ephemeral keys - restart",
		"epoch", sigSecret.Secret.Epoch,
	)
	key, err = rpcClient.fetchEphemeralPublicKeyWithRetry(ctx, sigSecret.Secret.Epoch, firstKmPeerID)
	if err != nil {
		return err
	}
	if key != nil {
		return fmt.Errorf("ephemeral key for epoch %d should not be available", sigSecret.Secret.Epoch)
	}

	// Wait until the next ephemeral secret is published.
	sc.Logger.Info("waiting for the first ephemeral secret")

	sigSecret, err = sc.WaitEphemeralSecrets(ctx, 1)
	if err != nil {
		return err
	}
	if len(sigSecret.Secret.Secret.Ciphertexts) != 1 {
		return fmt.Errorf("the first ephemeral secret should be encrypted for one enclave only")
	}

	// Wait for the ephemeral secret epoch.
	sc.Logger.Info("waiting for the ephemeral secret epoch",
		"epoch", sigSecret.Secret.Epoch,
	)

	if err = sc.Net.Controller().Beacon.WaitEpoch(ctx, sigSecret.Secret.Epoch); err != nil {
		return err
	}

	// Fetch public key which will be used to test replication.
	key, err = rpcClient.fetchEphemeralPublicKeyWithRetry(ctx, sigSecret.Secret.Epoch, firstKmPeerID)
	if err != nil {
		return err
	}
	if key == nil {
		return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
	}

	// Confirm that only one key manager is registered.
	err = sc.checkNumberOfKeyManagers(ctx, 1)
	if err != nil {
		return err
	}

	// Start other key managers.
	if err = sc.StartAndWaitKeymanagers(ctx, []int{1, 2}); err != nil {
		return err
	}

	// Test if the last ephemeral secret was copied.
	sc.Logger.Info("testing ephemeral keys - replication",
		"epoch", sigSecret.Secret.Epoch,
	)
	keyCopy, err := rpcClient.fetchEphemeralPublicKey(ctx, sigSecret.Secret.Epoch, secondKmPeerID)
	if err != nil {
		return err
	}
	if keyCopy == nil {
		return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
	}
	if *key != *keyCopy {
		return fmt.Errorf("ephemeral keys should be the same")
	}

	sc.Logger.Info("testing ephemeral keys - replication",
		"epoch", sigSecret.Secret.Epoch,
	)
	keyCopy, err = rpcClient.fetchEphemeralPublicKey(ctx, sigSecret.Secret.Epoch, thirdKmPeerID)
	if err != nil {
		return err
	}
	if keyCopy == nil {
		return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
	}
	if *key != *keyCopy {
		return fmt.Errorf("ephemeral keys should be the same")
	}

	// Test that all key managers derive the same keys.
	sc.Logger.Info("testing if ephemeral keys are the same")

	epoCh, epoSub, err := sc.Net.Controller().Beacon.WatchEpochs(ctx)
	if err != nil {
		return err
	}
	defer epoSub.Close()

	set := make(map[x25519.PublicKey]struct{})
	for i := 1; i <= 3; i++ {
		epoch := <-epoCh

		sc.Logger.Info("fetching ephemeral keys from all key managers",
			"epoch", epoch,
		)

		for _, peerID := range []peer.ID{firstKmPeerID, secondKmPeerID, thirdKmPeerID} {
			key, err = rpcClient.fetchEphemeralPublicKeyWithRetry(ctx, epoch, peerID)
			if err != nil {
				return fmt.Errorf("fetching ephemeral key should succeed, %w", err)
			}
			if key == nil {
				return fmt.Errorf("ephemeral key for epoch %d should be available", epoch)
			}
			set[*key] = struct{}{}
		}

		if len(set) != i {
			return fmt.Errorf("ephemeral keys should match")
		}
	}

	// Test that published secrets are encrypted to all enclaves.
	ephCh, ephSub, err := sc.Net.Controller().Keymanager.Secrets().WatchEphemeralSecrets(ctx)
	if err != nil {
		return err
	}
	defer ephSub.Close()

	for i := 1; i <= 3; i++ {
		sigSecret := <-ephCh

		sc.Logger.Info("checking if published ephemeral secret contains enough ciphertexts",
			"epoch", sigSecret.Secret.Epoch,
		)

		var numCiphertexts int
		switch rt.TEEHardware {
		case node.TEEHardwareIntelSGX:
			numCiphertexts = 3
		default:
			numCiphertexts = 1
		}

		if n := len(sigSecret.Secret.Secret.Ciphertexts); n != numCiphertexts {
			return fmt.Errorf("ephemeral secret should be encrypted to %d enclaves, not %d", numCiphertexts, n)
		}
	}

	// Confirm that all key managers were registered.
	err = sc.checkNumberOfKeyManagers(ctx, 3)
	if err != nil {
		return err
	}

	// Initialize the nonce DRBG.
	rng, err := drbgFromSeed(
		[]byte("oasis-core/oasis-test-runner/e2e/runtime/keymanager-ephemeral-keys"),
		[]byte("keymanager-ephemeral-keys"),
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

func (sc *kmEphemeralSecretsImpl) submitKeyValueRuntimeEncryptTx(
	ctx context.Context,
	nonce uint64,
	epoch beacon.EpochTime,
	keyPairID string,
	plaintext []byte,
) ([]byte, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, KeyValueRuntimeID, nonce, "encrypt", struct {
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

func (sc *kmEphemeralSecretsImpl) submitKeyValueRuntimeDecryptTx(
	ctx context.Context,
	nonce uint64,
	epoch beacon.EpochTime,
	keyPairID string,
	ciphertext []byte,
) ([]byte, error) {
	rawRsp, err := sc.submitRuntimeTx(ctx, KeyValueRuntimeID, nonce, "decrypt", struct {
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

func (sc *kmEphemeralSecretsImpl) checkNumberOfKeyManagers(ctx context.Context, n int) error {
	status, err := sc.Net.Controller().Keymanager.Secrets().GetStatus(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     KeyManagerRuntimeID,
	})
	if err != nil {
		return err
	}
	if num := len(status.Nodes); num != n {
		return fmt.Errorf("only %d key manager should be registered, not %d", n, num)
	}

	return nil
}
