package keymanager

import (
	"crypto/sha512"
	"fmt"
	"testing"
	"time"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	keymanagerState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/keymanager/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/api"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
)

func TestPublishEphemeralSecret(t *testing.T) {
	// Prepare key manager app.
	now := time.Unix(1580461674, 0)
	cfg := abciAPI.MockApplicationStateConfig{}
	appState := abciAPI.NewMockApplicationState(&cfg)
	app := keymanagerApplication{appState}

	// Prepare abci contexts.
	ctx := appState.NewContext(abciAPI.ContextEndBlock, now)
	defer ctx.Close()
	txCtx := appState.NewContext(abciAPI.ContextDeliverTx, now)
	defer txCtx.Close()

	// Prepare states.
	kmState := keymanagerState.NewMutableState(ctx.State())
	regState := registryState.NewMutableState(ctx.State())

	// Set up key manager consensus parameters.
	err := kmState.SetConsensusParameters(ctx, &api.ConsensusParameters{})
	require.NoError(t, err, "api.SetConsensusParameters")

	// Register one compute and two key manager runtimes.
	var runtimeID common.Namespace
	err = runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(t, err, "failed to unmarshal runtime id")
	rt := registryAPI.Runtime{
		ID:   runtimeID,
		Kind: registryAPI.KindCompute,
	}
	err = regState.SetRuntime(ctx, &rt, false)
	require.NoError(t, err, "registry.SetRuntime")

	var firstKmID common.Namespace
	err = firstKmID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(t, err, "failed to unmarshal keymanager id")
	firstKmRt := registryAPI.Runtime{
		ID:          firstKmID,
		Kind:        registryAPI.KindKeyManager,
		TEEHardware: node.TEEHardwareIntelSGX,
	}
	err = regState.SetRuntime(ctx, &firstKmRt, false)
	require.NoError(t, err, "registry.SetRuntime")

	var secondKmID common.Namespace
	err = secondKmID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000002")
	require.NoError(t, err, "failed to unmarshal keymanager id")
	secondKmRt := registryAPI.Runtime{
		ID:          secondKmID,
		Kind:        registryAPI.KindKeyManager,
		TEEHardware: node.TEEHardwareIntelSGX,
	}
	err = regState.SetRuntime(ctx, &secondKmRt, false)
	require.NoError(t, err, "registry.SetRuntime")

	// Prepare nodes.
	numNodes := 3
	nodes := make([]signature.PublicKey, 0, numNodes)
	signers := make([]signature.Signer, 0, numNodes)
	raks := make([]signature.Signer, 0, numNodes)
	reks := make([]x25519.PrivateKey, 0, numNodes)
	for i := 0; i < numNodes; i++ {
		signer := memorySigner.NewTestSigner(fmt.Sprintf("node signer %d", i))
		rak := memorySigner.NewTestSigner(fmt.Sprintf("rak %d", i))
		rek := x25519.PrivateKey(sha512.Sum512_256([]byte(fmt.Sprintf("rek %d", i))))
		nodes = append(nodes, signer.Public())
		signers = append(signers, signer)
		raks = append(raks, rak)
		reks = append(reks, rek)
	}

	// Register an entity.
	entitySigner := memorySigner.NewTestSigner("entity signer")
	ent := entity.Entity{
		Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
		ID:        entitySigner.Public(),
		Nodes:     nodes,
	}
	sigEnt, err := entity.SignEntity(entitySigner, registryAPI.RegisterEntitySignatureContext, &ent)
	require.NoError(t, err, "entity.SignEntity")
	err = regState.SetEntity(ctx, &ent, sigEnt)
	require.NoError(t, err, "registry.SetEntity")

	// Register nodes.
	for i, signer := range signers {
		nod := &node.Node{
			Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:        signer.Public(),
			Consensus: node.ConsensusInfo{
				ID: signer.Public(),
			},
			EntityID: entitySigner.Public(),
			Runtimes: []*node.Runtime{
				{
					ID: firstKmRt.ID,
					Capabilities: node.Capabilities{
						TEE: &node.CapabilityTEE{
							Hardware:    node.TEEHardwareIntelSGX,
							RAK:         raks[i].Public(),
							REK:         reks[i].Public(),
							Attestation: nil,
						},
					},
				},
				{
					ID: secondKmID,
					Capabilities: node.Capabilities{
						TEE: &node.CapabilityTEE{
							Hardware:    node.TEEHardwareIntelSGX,
							RAK:         raks[i].Public(),
							REK:         nil,
							Attestation: nil,
						},
					},
				},
			},
		}
		sigNode, nErr := node.MultiSignNode([]signature.Signer{signer}, registryAPI.RegisterNodeSignatureContext, nod)
		require.NoError(t, nErr, "node.MultiSignNode")
		err = regState.SetNode(ctx, nil, nod, sigNode)
		require.NoError(t, err, "registry.SetNode")

	}

	// Set key manager statuses.
	firstKmStatus := api.Status{
		ID:    firstKmID,
		Nodes: nodes,
	}
	err = kmState.SetStatus(ctx, &firstKmStatus)
	require.NoError(t, err, "keymanager.SetStatus")

	secondKmStatus := api.Status{
		ID:    secondKmID,
		Nodes: nodes,
	}
	err = kmState.SetStatus(ctx, &secondKmStatus)
	require.NoError(t, err, "keymanager.SetStatus")

	// Prepare signed secret.
	newSignedSecret := func() *api.SignedEncryptedEphemeralSecret {
		secret := api.EncryptedEphemeralSecret{
			ID:    firstKmID,
			Epoch: beacon.EpochTime(1),
			Secret: api.EncryptedSecret{
				PubKey: *reks[0].Public(),
				Ciphertexts: map[x25519.PublicKey][]byte{
					*reks[0].Public(): {1, 2, 3},
					*reks[1].Public(): {4, 5, 6},
				},
			},
		}
		sig, err2 := signature.Sign(raks[0], api.EncryptedEphemeralSecretSignatureContext, cbor.Marshal(secret))
		require.NoError(t, err2, "signature.Sign")

		return &api.SignedEncryptedEphemeralSecret{
			Secret:    secret,
			Signature: sig.Signature,
		}
	}

	// Set transaction signer.
	txCtx.SetTxSigner(signers[0].Public())

	// Finally, start testing.
	t.Run("invalid runtime", func(t *testing.T) {
		sigSecret := newSignedSecret()
		sigSecret.Secret.ID = common.Namespace{}

		err = app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "registry: no such runtime")
	})

	t.Run("runtime is not a key manager", func(t *testing.T) {
		sigSecret := newSignedSecret()
		sigSecret.Secret.ID = runtimeID

		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: runtime is not a key manager: 8000000000000000000000000000000000000000000000000000000000000000")
	})

	t.Run("node not in the key manager committee", func(t *testing.T) {
		err := kmState.SetStatus(ctx, &api.Status{ID: firstKmID})
		require.NoError(t, err, "SetStatus")

		sigSecret := newSignedSecret()
		err = app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: ephemeral secret can be published only by the key manager committee")

		err = kmState.SetStatus(ctx, &firstKmStatus)
		require.NoError(t, err, "SetStatus")
	})

	t.Run("not enough ciphertexts", func(t *testing.T) {
		sigSecret := newSignedSecret()
		delete(sigSecret.Secret.Secret.Ciphertexts, *reks[0].Public())

		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: sanity check failed: secret is not encrypted with enough keys")
	})

	t.Run("empty committee", func(t *testing.T) {
		sigSecret := newSignedSecret()
		sigSecret.Secret.ID = secondKmID

		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: sanity check failed: secret has to be encrypted with at least one key")
	})

	t.Run("invalid signature", func(t *testing.T) {
		sigSecret := newSignedSecret()
		sigSecret.Signature = signature.RawSignature{1, 2, 3, 4, 5}

		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: sanity check failed: ephemeral secret contains an invalid signature")
	})

	t.Run("invalid epoch", func(t *testing.T) {
		sigSecret := newSignedSecret()
		sigSecret.Secret.Epoch = 2

		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: sanity check failed: ephemeral secret contains an invalid epoch: (expected: 1, got: 2)")
	})

	t.Run("happy path", func(t *testing.T) {
		sigSecret := newSignedSecret()
		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.NoError(t, err, "publishEphemeralSecret")
	})

	t.Run("ephemeral secret already published", func(t *testing.T) {
		sigSecret := newSignedSecret()
		err := app.publishEphemeralSecret(txCtx, kmState, sigSecret)
		require.EqualError(t, err, "keymanager: ephemeral secret for epoch 1 already published")
	})
}
