package runtime

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/env"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis"
	"github.com/oasisprotocol/oasis-core/go/oasis-test-runner/oasis/cli"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
)

// KeyManagerStatus returns the latest key manager status.
func (sc *Scenario) KeyManagerStatus(ctx context.Context) (*keymanager.Status, error) {
	return sc.Net.ClientController().Keymanager.GetStatus(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     KeyManagerRuntimeID,
	})
}

// MasterSecret returns the key manager master secret.
func (sc *Scenario) MasterSecret(ctx context.Context) (*keymanager.SignedEncryptedMasterSecret, error) {
	secret, err := sc.Net.ClientController().Keymanager.GetMasterSecret(ctx, &registry.NamespaceQuery{
		Height: consensus.HeightLatest,
		ID:     KeyManagerRuntimeID,
	})
	if err == keymanager.ErrNoSuchMasterSecret {
		return nil, nil
	}
	return secret, err
}

// WaitMasterSecret waits until the specified generation of the master secret is generated.
func (sc *Scenario) WaitMasterSecret(ctx context.Context, generation uint64) (*keymanager.Status, error) {
	sc.Logger.Info("waiting for master secret", "generation", generation)

	mstCh, mstSub, err := sc.Net.Controller().Keymanager.WatchMasterSecrets(ctx)
	if err != nil {
		return nil, err
	}
	defer mstSub.Close()

	stCh, stSub, err := sc.Net.Controller().Keymanager.WatchStatuses(ctx)
	if err != nil {
		return nil, err
	}
	defer stSub.Close()

	var last *keymanager.Status
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case secret := <-mstCh:
			if !secret.Secret.ID.Equal(&KeyManagerRuntimeID) {
				continue
			}

			sc.Logger.Info("master secret proposed",
				"generation", secret.Secret.Generation,
				"epoch", secret.Secret.Epoch,
				"num_ciphertexts", len(secret.Secret.Secret.Ciphertexts),
			)
		case status := <-stCh:
			if !status.ID.Equal(&KeyManagerRuntimeID) {
				continue
			}
			if status.NextGeneration() == 0 {
				continue
			}
			if last != nil && status.Generation == last.Generation {
				last = status
				continue
			}

			sc.Logger.Info("master secret rotation",
				"generation", status.Generation,
				"rotation_epoch", status.RotationEpoch,
			)

			if status.Generation >= generation {
				return status, nil
			}
			last = status
		}
	}
}

// WaitEphemeralSecrets waits for the specified number of ephemeral secrets to be generated.
func (sc *Scenario) WaitEphemeralSecrets(ctx context.Context, n int) (*keymanager.SignedEncryptedEphemeralSecret, error) {
	sc.Logger.Info("waiting ephemeral secrets", "n", n)

	ephCh, ephSub, err := sc.Net.Controller().Keymanager.WatchEphemeralSecrets(ctx)
	if err != nil {
		return nil, err
	}
	defer ephSub.Close()

	var secret *keymanager.SignedEncryptedEphemeralSecret
	for i := 0; i < n; i++ {
		select {
		case secret = <-ephCh:
			sc.Logger.Info("ephemeral secret published",
				"epoch", secret.Secret.Epoch,
			)
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for ephemeral secrets")
		}
	}
	return secret, nil
}

// UpdateRotationInterval updates the master secret rotation interval in the key manager policy.
func (sc *Scenario) UpdateRotationInterval(ctx context.Context, nonce uint64, childEnv *env.Env, rotationInterval beacon.EpochTime) error {
	sc.Logger.Info("updating master secret rotation interval in the key manager policy",
		"interval", rotationInterval,
	)

	status, err := sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}

	// Update the policy, or create a new one if it doesn't already exist.
	var policy keymanager.PolicySGX
	if status != nil && status.Policy != nil {
		policy = status.Policy.Policy
		policy.Serial++
	} else {
		policy.Serial = 1
		policy.ID = KeyManagerRuntimeID
		policy.Enclaves = make(map[sgx.EnclaveIdentity]*keymanager.EnclavePolicySGX)
	}
	policy.MasterSecretRotationInterval = rotationInterval

	// Sign and publish the new policy.
	kmPolicyPath := filepath.Join(childEnv.Dir(), "km_policy.cbor")
	kmPolicySig1Path := filepath.Join(childEnv.Dir(), "km_policy_sig1.pem")
	kmPolicySig2Path := filepath.Join(childEnv.Dir(), "km_policy_sig2.pem")
	kmPolicySig3Path := filepath.Join(childEnv.Dir(), "km_policy_sig3.pem")
	kmUpdateTxPath := filepath.Join(childEnv.Dir(), "km_gen_update.json")

	sc.Logger.Info("saving key manager policy")
	raw := cbor.Marshal(policy)
	if err = os.WriteFile(kmPolicyPath, raw, 0o644); err != nil { // nolint: gosec
		return err
	}

	sc.Logger.Info("signing key manager policy")
	cli := cli.New(childEnv, sc.Net, sc.Logger)
	if err := cli.Keymanager.SignPolicy("1", kmPolicyPath, kmPolicySig1Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("2", kmPolicyPath, kmPolicySig2Path); err != nil {
		return err
	}
	if err := cli.Keymanager.SignPolicy("3", kmPolicyPath, kmPolicySig3Path); err != nil {
		return err
	}

	sc.Logger.Info("updating key manager policy")
	if err := cli.Keymanager.GenUpdate(nonce, kmPolicyPath, []string{kmPolicySig1Path, kmPolicySig2Path, kmPolicySig3Path}, kmUpdateTxPath); err != nil {
		return err
	}
	if err := cli.Consensus.SubmitTx(kmUpdateTxPath); err != nil {
		return fmt.Errorf("failed to update key manager policy: %w", err)
	}

	return nil
}

// CompareLongtermPublicKeys compares long-term public keys generated by the specified
// key manager nodes.
func (sc *Scenario) CompareLongtermPublicKeys(ctx context.Context, idxs []int) error {
	chainContext, err := sc.Net.Controller().Consensus.GetChainContext(ctx)
	if err != nil {
		return err
	}

	status, err := sc.KeyManagerStatus(ctx)
	if err != nil {
		return err
	}

	var generation uint64
	if status.Generation > 0 {
		// Avoid verification problems when the consensus verifier is one block behind.
		generation = status.Generation - 1
	}

	sc.Logger.Info("comparing long-term public keys generated by the key managers",
		"ids", idxs,
		"generation", generation,
	)

	keys := make(map[uint64]*x25519.PublicKey)
	kms := sc.Net.Keymanagers()
	for _, idx := range idxs {
		km := kms[idx]

		// Prepare an RPC client which will be used to query key manager nodes
		// for public ephemeral keys.
		rpcClient, err := newKeyManagerRPCClient(chainContext)
		if err != nil {
			return err
		}
		peerID, err := rpcClient.addKeyManagerAddrToHost(km)
		if err != nil {
			return err
		}

		for gen := uint64(0); gen <= generation; gen++ {
			sc.Logger.Info("fetching public key", "generation", gen, "node", km.Name)

			var key *x25519.PublicKey
			key, err = rpcClient.fetchPublicKey(ctx, gen, peerID)
			switch {
			case err != nil:
				return err
			case key == nil:
				return fmt.Errorf("master secret generation %d not found", gen)
			}

			if expected, ok := keys[gen]; ok && !bytes.Equal(expected[:], key[:]) {
				return fmt.Errorf("derived keys don't match: expected %+X, given %+X", expected, key)
			}
			keys[gen] = key

			sc.Logger.Info("public key fetched", "key", fmt.Sprintf("%+X", key))
		}
		if err != nil {
			return err
		}
	}
	if expected, size := int(generation)+1, len(keys); expected != size {
		return fmt.Errorf("the number of derived keys doesn't match: expected %d, found %d", expected, size)
	}

	return nil
}

// KeymanagerInitResponse returns InitResponse of the specified key manager node.
func (sc *Scenario) KeymanagerInitResponse(ctx context.Context, idx int) (*keymanager.InitResponse, error) {
	kms := sc.Net.Keymanagers()
	if kmLen := len(kms); kmLen <= idx {
		return nil, fmt.Errorf("expected more than %d keymanager, have: %v", idx, kmLen)
	}
	km := kms[idx]

	ctrl, err := oasis.NewController(km.SocketPath())
	if err != nil {
		return nil, err
	}

	// Extract ExtraInfo.
	node, err := ctrl.Registry.GetNode(
		ctx,
		&registry.IDQuery{
			ID: km.NodeID,
		},
	)
	if err != nil {
		return nil, err
	}
	rt := node.GetRuntime(KeyManagerRuntimeID, version.Version{})
	if rt == nil {
		return nil, fmt.Errorf("key manager is missing keymanager runtime from descriptor")
	}
	var signedInitResponse keymanager.SignedInitResponse
	if err = cbor.Unmarshal(rt.ExtraInfo, &signedInitResponse); err != nil {
		return nil, fmt.Errorf("failed to unmarshal extrainfo")
	}

	return &signedInitResponse.InitResponse, nil
}
