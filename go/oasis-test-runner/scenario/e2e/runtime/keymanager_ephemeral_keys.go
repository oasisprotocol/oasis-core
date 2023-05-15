package runtime

import (
	"context"
	"crypto/rand"
	"fmt"
	"reflect"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/multiformats/go-multiaddr"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/scenario"
	p2p "github.com/oasisprotocol/oasis-core/go/p2p/api"
	"github.com/oasisprotocol/oasis-core/go/p2p/protocol"
	"github.com/oasisprotocol/oasis-core/go/p2p/rpc"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	enclaverpc "github.com/oasisprotocol/oasis-core/go/runtime/enclaverpc/api"
	kmp2p "github.com/oasisprotocol/oasis-core/go/worker/keymanager/p2p"
)

// KeymanagerEphemeralKeys is the keymanager ephemeral secret and ephemeral
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
var KeymanagerEphemeralKeys scenario.Scenario = newKmEphemeralKeysImpl()

type kmEphemeralKeysImpl struct {
	RuntimeImpl
}

func newKmEphemeralKeysImpl() scenario.Scenario {
	return &kmEphemeralKeysImpl{
		RuntimeImpl: *NewRuntimeImpl(
			"keymanager-ephemeral-keys",
			NewKVTestClient().WithScenario(InsertRemoveKeyValueEncScenario),
		),
	}
}

func (sc *kmEphemeralKeysImpl) Fixture() (*oasis.NetworkFixture, error) {
	f, err := sc.RuntimeImpl.Fixture()
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

func (sc *kmEphemeralKeysImpl) Clone() scenario.Scenario {
	return &kmEphemeralKeysImpl{
		RuntimeImpl: *sc.RuntimeImpl.Clone().(*RuntimeImpl),
	}
}

func (sc *kmEphemeralKeysImpl) Run(childEnv *env.Env) error { // nolint: gocyclo
	// Start the network, but no need to start the client. Just ensure it
	// is synced.
	ctx := context.Background()
	if err := sc.RuntimeImpl.StartNetworkAndWaitForClientSync(ctx); err != nil {
		return err
	}

	// Fetch runtime to know on which TEE platform the key manager is running.
	rt, err := sc.Net.ClientController().Registry.GetRuntime(ctx, &registry.GetRuntimeQuery{
		Height: consensus.HeightLatest,
		ID:     keymanagerID,
	})
	if err != nil {
		return err
	}

	// Prepare key managers.
	kms := sc.Net.Keymanagers()
	firstKm := kms[0]
	secondKm := kms[1]
	thirdKm := kms[2]

	// Prepare an RPC client which will be used to query key manager nodes
	// for public ephemeral keys.
	chainContext, err := sc.Net.Controller().Consensus.GetChainContext(ctx)
	if err != nil {
		return err
	}
	rpcClient, rpcHost, err := sc.keyManagerRPCClient(chainContext)
	if err != nil {
		return err
	}
	firstKmPeerID, err := sc.addKeyManagerAddrToHost(firstKm, rpcHost)
	if err != nil {
		return err
	}
	secondKmPeerID, err := sc.addKeyManagerAddrToHost(secondKm, rpcHost)
	if err != nil {
		return err
	}
	thirdKmPeerID, err := sc.addKeyManagerAddrToHost(thirdKm, rpcHost)
	if err != nil {
		return err
	}

	// Wait until the first key manager is ready.
	sc.Logger.Info("ensuring the first key manager is ready")

	firstKmCtrl, err := oasis.NewController(firstKm.SocketPath())
	if err != nil {
		return err
	}
	if err = firstKmCtrl.WaitReady(ctx); err != nil {
		return err
	}

	// Wait until the first ephemeral secret is published.
	sc.Logger.Info("waiting for the first ephemeral secret")

	sigSecret, err := sc.waitForNextEphemeralSecret(ctx)
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

	key, err := sc.fetchEphemeralPublicKey(ctx, sigSecret.Secret.Epoch-1, firstKmPeerID, rpcClient)
	if err != nil {
		return err
	}
	if key != nil {
		return fmt.Errorf("ephemeral key for epoch %d should not be available", sigSecret.Secret.Epoch-1)
	}

	// Test that ephemeral key for the current epoch is available.
	// When using Tendermint as a backend service we need to retry the query
	// because the verifier is probably one block behind.
	sc.Logger.Info("testing ephemeral keys - current epoch",
		"epoch", sigSecret.Secret.Epoch,
	)

	key, err = sc.fetchEphemeralPublicKeyWithRetry(ctx, sigSecret.Secret.Epoch, firstKmPeerID, rpcClient)
	if err != nil {
		return err
	}
	if key == nil {
		return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
	}

	// Restart the first key manager.
	sc.Logger.Info("restarting the first key manager")
	if err = firstKm.Restart(ctx); err != nil {
		return fmt.Errorf("failed to restart the first key manager: %w", err)
	}

	sc.Logger.Info("ensuring the first key manager is ready")
	if err = firstKmCtrl.WaitReady(ctx); err != nil {
		return err
	}

	// Test that ephemeral key for the last epoch is not available after restart.
	sc.Logger.Info("testing ephemeral keys - restart",
		"epoch", sigSecret.Secret.Epoch,
	)
	key, err = sc.fetchEphemeralPublicKeyWithRetry(ctx, sigSecret.Secret.Epoch, firstKmPeerID, rpcClient)
	if err != nil {
		return err
	}
	switch rt.TEEHardware {
	case node.TEEHardwareIntelSGX:
		// REK changes on restarts and therefore the key managers shouldn't be able to decrypt
		// previous ciphertexts.
		if key != nil {
			return fmt.Errorf("ephemeral key for epoch %d should not be available", sigSecret.Secret.Epoch)
		}
	default:
		// Insecure REK doesn't change on restarts so the key manager should be able to decrypt
		// all previous ciphertexts.
		if key == nil {
			return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
		}
	}

	// Wait until the next ephemeral secret is published.
	sc.Logger.Info("waiting for the first ephemeral secret")

	sigSecret, err = sc.waitForNextEphemeralSecret(ctx)
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
	key, err = sc.fetchEphemeralPublicKeyWithRetry(ctx, sigSecret.Secret.Epoch, firstKmPeerID, rpcClient)
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
	sc.Logger.Info("starting all key managers")

	if err = secondKm.Start(); err != nil {
		return fmt.Errorf("failed to start the second key manager: %w", err)
	}
	if err = thirdKm.Start(); err != nil {
		return fmt.Errorf("failed to start the third key manager: %w", err)
	}

	sc.Logger.Info("ensuring all key manager are ready")

	secondKmCtrl, err := oasis.NewController(secondKm.SocketPath())
	if err != nil {
		return err
	}
	if err = secondKmCtrl.WaitReady(ctx); err != nil {
		return err
	}

	thirdKmCtrl, err := oasis.NewController(thirdKm.SocketPath())
	if err != nil {
		return err
	}
	if err = thirdKmCtrl.WaitReady(ctx); err != nil {
		return err
	}

	// Test if the last ephemeral secret was copied.
	sc.Logger.Info("testing ephemeral keys - replication",
		"epoch", sigSecret.Secret.Epoch,
	)
	keyCopy, err := sc.fetchEphemeralPublicKey(ctx, sigSecret.Secret.Epoch, secondKmPeerID, rpcClient)
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
	keyCopy, err = sc.fetchEphemeralPublicKey(ctx, sigSecret.Secret.Epoch, thirdKmPeerID, rpcClient)
	if err != nil {
		return err
	}
	if keyCopy == nil {
		return fmt.Errorf("ephemeral key for epoch %d should be available", sigSecret.Secret.Epoch)
	}
	if *key != *keyCopy {
		return fmt.Errorf("ephemeral keys should be the same")
	}

	// Test that all key managers produce the same keys and that ephemeral secrets
	// are published in the consensus layer.
	sc.Logger.Info("testing if ephemeral keys are the same and ephemeral secrets published")

	epoCh, epoSub, err := sc.Net.Controller().Beacon.WatchEpochs(ctx)
	if err != nil {
		return err
	}
	defer epoSub.Close()

	set := make(map[x25519.PublicKey]struct{})
	for i := 0; i < 5; i++ {
		epoch := <-epoCh

		sc.Logger.Info("checking if ephemeral secret was published",
			"epoch", epoch,
		)

		sigSecret, err = sc.Net.Controller().Keymanager.GetEphemeralSecret(ctx, &registry.NamespaceEpochQuery{
			Height: consensus.HeightLatest,
			ID:     keymanagerID,
			Epoch:  epoch,
		})
		if err != nil {
			return err
		}

		var numCiphertexts int
		switch rt.TEEHardware {
		case node.TEEHardwareIntelSGX:
			numCiphertexts = 3
		default:
			numCiphertexts = 1
		}

		// Skip first two secrets as we cannot be sure how many key manager nodes were registered
		// when the secret was generated.
		if i > 1 {
			if n := len(sigSecret.Secret.Secret.Ciphertexts); n != numCiphertexts {
				return fmt.Errorf("ephemeral secret should be encrypted to %d enclaves, not %d", numCiphertexts, n)
			}
		}

		sc.Logger.Info("fetching ephemeral keys from all key managers",
			"epoch", epoch,
		)

		for _, peerID := range []peer.ID{firstKmPeerID, secondKmPeerID, thirdKmPeerID} {
			key, err = sc.fetchEphemeralPublicKeyWithRetry(ctx, epoch, peerID, rpcClient)
			if err != nil {
				return fmt.Errorf("fetching ephemeral key should succeed")
			}
			if key == nil {
				return fmt.Errorf("ephemeral key for epoch %d should be available", epoch)
			}
			set[*key] = struct{}{}
		}

		if len(set) != i+1 {
			return fmt.Errorf("ephemeral keys should match")
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

func (sc *kmEphemeralKeysImpl) submitKeyValueRuntimeEncryptTx(
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

func (sc *kmEphemeralKeysImpl) submitKeyValueRuntimeDecryptTx(
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

func (sc *kmEphemeralKeysImpl) waitForNextEphemeralSecret(ctx context.Context) (*keymanager.SignedEncryptedEphemeralSecret, error) {
	ch, sub, err := sc.Net.Controller().Keymanager.WatchEphemeralSecrets(ctx)
	if err != nil {
		return nil, err
	}
	defer sub.Close()

	select {
	case secret, ok := <-ch:
		if !ok {
			return nil, fmt.Errorf("channel for ephemeral secrets closed")
		}
		return secret, nil
	case <-time.After(time.Minute):
		return nil, fmt.Errorf("timed out waiting for the next ephemeral secret")
	}
}

func (sc *kmEphemeralKeysImpl) checkNumberOfKeyManagers(ctx context.Context, n int) error {
	status, err := sc.Net.Controller().Keymanager.GetStatus(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     keymanagerID,
	})
	if err != nil {
		return err
	}
	if num := len(status.Nodes); num != n {
		return fmt.Errorf("only %d key manager should be registered, not %d", n, num)
	}

	return nil
}

func (sc *kmEphemeralKeysImpl) keyManagerRPCClient(chainContext string) (rpc.Client, host.Host, error) {
	signer, err := memory.NewFactory().Generate(signature.SignerP2P, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	listenAddr, err := multiaddr.NewMultiaddr("/ip4/0.0.0.0/tcp/0")
	if err != nil {
		return nil, nil, err
	}

	host, err := libp2p.New(
		libp2p.ListenAddrs(listenAddr),
		libp2p.Identity(p2p.SignerToPrivKey(signer)),
	)
	if err != nil {
		return nil, nil, err
	}

	pid := protocol.NewRuntimeProtocolID(chainContext, keymanagerID, kmp2p.KeyManagerProtocolID, kmp2p.KeyManagerProtocolVersion)
	rc := rpc.NewClient(host, pid)

	return rc, host, nil
}

func (sc *kmEphemeralKeysImpl) addKeyManagerAddrToHost(km *oasis.Keymanager, host host.Host) (peer.ID, error) {
	identity, err := km.LoadIdentity()
	if err != nil {
		return "", err
	}

	peerID, err := p2p.PublicKeyToPeerID(identity.P2PSigner.Public())
	if err != nil {
		return "", err
	}

	listenAddr, err := multiaddr.NewMultiaddr(fmt.Sprintf("/ip4/0.0.0.0/tcp/%d", km.P2PPort()))
	if err != nil {
		return "", err
	}

	host.Peerstore().AddAddr(peerID, listenAddr, time.Hour)

	return peerID, nil
}

func (sc *kmEphemeralKeysImpl) fetchEphemeralPublicKey(ctx context.Context, epoch beacon.EpochTime, peerID peer.ID, rc rpc.Client) (*x25519.PublicKey, error) {
	args := keymanager.EphemeralKeyRequest{
		Height:    nil,
		ID:        keymanagerID,
		KeyPairID: keymanager.KeyPairID{1, 2, 3},
		Epoch:     epoch,
	}

	req := enclaverpc.Request{
		Method: keymanager.RPCMethodGetPublicEphemeralKey,
		Args:   args,
	}

	p2pReq := kmp2p.CallEnclaveRequest{
		Kind: enclaverpc.KindInsecureQuery,
		Data: cbor.Marshal(req),
	}

	var p2pRsp kmp2p.CallEnclaveResponse
	_, err := rc.Call(ctx, peerID, kmp2p.MethodCallEnclave, p2pReq, &p2pRsp)
	if err != nil {
		return nil, err
	}

	var rsp enclaverpc.Response
	if err = cbor.Unmarshal(p2pRsp.Data, &rsp); err != nil {
		return nil, err
	}

	if rsp.Body.Error != nil {
		msg := *rsp.Body.Error
		if msg == fmt.Sprintf("ephemeral secret for epoch %d not found", epoch) {
			return nil, nil
		}
		return nil, fmt.Errorf(msg)
	}

	var key keymanager.SignedPublicKey
	if err = cbor.Unmarshal(rsp.Body.Success, &key); err != nil {
		return nil, err
	}

	return &key.Key, nil
}

func (sc *kmEphemeralKeysImpl) fetchEphemeralPublicKeyWithRetry(ctx context.Context, epoch beacon.EpochTime, peerID peer.ID, rc rpc.Client) (*x25519.PublicKey, error) {
	var (
		err error
		key *x25519.PublicKey
	)

	retry := backoff.WithContext(backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second), 5), ctx)
	err = backoff.Retry(func() error {
		key, err = sc.fetchEphemeralPublicKey(ctx, epoch, peerID, rc)
		if err != nil {
			sc.Logger.Warn("failed to fetch ephemeral public key",
				"err", err,
			)
		}
		return err
	}, retry)
	if err != nil {
		return nil, err
	}

	return key, err
}
