package secrets

import (
	"crypto/sha512"
	"fmt"
	"math"
	"testing"

	"github.com/oasisprotocol/curve25519-voi/primitives/x25519"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	consensusState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/consensus/state"
	secretsState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/secrets/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	consensusGenesis "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	"github.com/oasisprotocol/oasis-core/go/keymanager/secrets"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
)

type TxTestSuite struct {
	suite.Suite

	ext secretsExt

	ctx   *abciAPI.Context
	txCtx *abciAPI.Context

	kmState  *secretsState.MutableState
	regState *registryState.MutableState

	runtimeID common.Namespace
	kmIDs     []common.Namespace

	runtimeSigner signature.Signer

	nodes   []signature.PublicKey
	signers []signature.Signer
	raks    []signature.Signer
	reks    []x25519.PrivateKey
}

func (s *TxTestSuite) SetupSuite() {
	// Prepare key manager app.
	cfg := abciAPI.MockApplicationStateConfig{}
	appState := abciAPI.NewMockApplicationState(&cfg)
	s.ext = secretsExt{
		state: appState,
	}

	// Prepare abci contexts.
	s.ctx = appState.NewContext(abciAPI.ContextEndBlock)
	s.txCtx = appState.NewContext(abciAPI.ContextDeliverTx)

	// Prepare states.
	s.kmState = secretsState.NewMutableState(s.ctx.State())
	s.regState = registryState.NewMutableState(s.ctx.State())

	// Set up key manager consensus parameters.
	err := s.kmState.SetConsensusParameters(s.ctx, &secrets.ConsensusParameters{})
	require.NoError(s.T(), err, "api.SetConsensusParameters")

	// Register one compute and two key manager runtimes.
	s.runtimeSigner = memorySigner.NewTestSigner("runtime signer")

	err = s.runtimeID.UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000000")
	require.NoError(s.T(), err, "failed to unmarshal runtime id")
	rt := registryAPI.Runtime{
		ID:       s.runtimeID,
		Kind:     registryAPI.KindCompute,
		EntityID: s.runtimeSigner.Public(),
	}
	err = s.regState.SetRuntime(s.ctx, &rt, false)
	require.NoError(s.T(), err, "registry.SetRuntime")

	s.kmIDs = make([]common.Namespace, 2)

	err = s.kmIDs[0].UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000001")
	require.NoError(s.T(), err, "failed to unmarshal keymanager id")
	firstKmRt := registryAPI.Runtime{
		ID:          s.kmIDs[0],
		Kind:        registryAPI.KindKeyManager,
		TEEHardware: node.TEEHardwareIntelSGX,
		EntityID:    s.runtimeSigner.Public(),
	}
	err = s.regState.SetRuntime(s.ctx, &firstKmRt, false)
	require.NoError(s.T(), err, "registry.SetRuntime")

	err = s.kmIDs[1].UnmarshalHex("8000000000000000000000000000000000000000000000000000000000000002")
	require.NoError(s.T(), err, "failed to unmarshal keymanager id")
	secondKmRt := registryAPI.Runtime{
		ID:          s.kmIDs[1],
		Kind:        registryAPI.KindKeyManager,
		TEEHardware: node.TEEHardwareIntelSGX,
		EntityID:    s.runtimeSigner.Public(),
	}
	err = s.regState.SetRuntime(s.ctx, &secondKmRt, false)
	require.NoError(s.T(), err, "registry.SetRuntime")

	// Prepare nodes.
	numNodes := 3
	s.nodes = make([]signature.PublicKey, 0, numNodes)
	s.signers = make([]signature.Signer, 0, numNodes)
	s.raks = make([]signature.Signer, 0, numNodes)
	s.reks = make([]x25519.PrivateKey, 0, numNodes)
	for i := 0; i < numNodes; i++ {
		signer := memorySigner.NewTestSigner(fmt.Sprintf("node signer %d", i))
		rak := memorySigner.NewTestSigner(fmt.Sprintf("rak %d", i))
		rek := x25519.PrivateKey(sha512.Sum512_256([]byte(fmt.Sprintf("rek %d", i))))
		s.nodes = append(s.nodes, signer.Public())
		s.signers = append(s.signers, signer)
		s.raks = append(s.raks, rak)
		s.reks = append(s.reks, rek)
	}

	// Register an entity.
	entitySigner := memorySigner.NewTestSigner("entity signer")
	ent := entity.Entity{
		Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
		ID:        entitySigner.Public(),
		Nodes:     s.nodes,
	}
	sigEnt, err := entity.SignEntity(entitySigner, registryAPI.RegisterEntitySignatureContext, &ent)
	require.NoError(s.T(), err, "entity.SignEntity")
	err = s.regState.SetEntity(s.ctx, &ent, sigEnt)
	require.NoError(s.T(), err, "registry.SetEntity")

	// Register nodes.
	for i, signer := range s.signers {
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
							RAK:         s.raks[i].Public(),
							REK:         s.reks[i].Public(),
							Attestation: nil,
						},
					},
				},
				{
					ID: s.kmIDs[1],
					Capabilities: node.Capabilities{
						TEE: &node.CapabilityTEE{
							Hardware:    node.TEEHardwareIntelSGX,
							RAK:         s.raks[i].Public(),
							REK:         nil,
							Attestation: nil,
						},
					},
				},
			},
		}
		sigNode, nErr := node.MultiSignNode([]signature.Signer{signer}, registryAPI.RegisterNodeSignatureContext, nod)
		require.NoError(s.T(), nErr, "node.MultiSignNode")
		err = s.regState.SetNode(s.ctx, nil, nod, sigNode)
		require.NoError(s.T(), err, "registry.SetNode")
	}
}

func (s *TxTestSuite) TearDownSuite() {
	s.ctx.Close()
	s.txCtx.Close()
}

func (s *TxTestSuite) TestPublishEphemeralSecret() {
	// Set key manager statuses.
	statuses := []*secrets.Status{
		{
			ID:    s.kmIDs[0],
			Nodes: s.nodes,
		},
		{
			ID:    s.kmIDs[1],
			Nodes: s.nodes,
		},
	}

	err := s.kmState.SetStatus(s.ctx, statuses[0])
	require.NoError(s.T(), err, "keymanager.SetStatus")

	err = s.kmState.SetStatus(s.ctx, statuses[1])
	require.NoError(s.T(), err, "keymanager.SetStatus")

	// Prepare signed secret.
	newSignedSecret := func() *secrets.SignedEncryptedEphemeralSecret {
		secret := secrets.EncryptedEphemeralSecret{
			ID:    s.kmIDs[0],
			Epoch: beacon.EpochTime(1),
			Secret: secrets.EncryptedSecret{
				PubKey: *s.reks[0].Public(),
				Ciphertexts: map[x25519.PublicKey][]byte{
					*s.reks[0].Public(): {1, 2, 3},
					*s.reks[1].Public(): {4, 5, 6},
				},
			},
		}
		sig, err2 := signature.Sign(s.raks[0], secrets.EncryptedEphemeralSecretSignatureContext, cbor.Marshal(secret))
		require.NoError(s.T(), err2, "signature.Sign")

		return &secrets.SignedEncryptedEphemeralSecret{
			Secret:    secret,
			Signature: sig.Signature,
		}
	}

	// Select a transaction signer.
	s.txCtx.SetTxSigner(s.signers[0].Public())

	// Finally, start testing.
	s.Run("invalid runtime", func() {
		sigSecret := newSignedSecret()
		sigSecret.Secret.ID = common.Namespace{}

		err = s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "registry: no such runtime")
	})

	s.Run("runtime is not a key manager", func() {
		sigSecret := newSignedSecret()
		sigSecret.Secret.ID = s.runtimeID

		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: runtime is not a key manager: 8000000000000000000000000000000000000000000000000000000000000000")
	})

	s.Run("node not in the key manager committee", func() {
		err := s.kmState.SetStatus(s.ctx, &secrets.Status{ID: s.kmIDs[0]})
		require.NoError(s.T(), err, "SetStatus")

		sigSecret := newSignedSecret()
		err = s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: ephemeral secret can be published only by the key manager committee")

		err = s.kmState.SetStatus(s.ctx, statuses[0])
		require.NoError(s.T(), err, "SetStatus")
	})

	s.Run("not enough ciphertexts", func() {
		sigSecret := newSignedSecret()
		delete(sigSecret.Secret.Secret.Ciphertexts, *s.reks[0].Public())

		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: sanity check failed: secret is not encrypted with enough keys")
	})

	s.Run("empty committee", func() {
		sigSecret := newSignedSecret()
		sigSecret.Secret.ID = s.kmIDs[1]

		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: sanity check failed: secret has to be encrypted with at least one key")
	})

	s.Run("invalid signature", func() {
		sigSecret := newSignedSecret()
		sigSecret.Signature = signature.RawSignature{1, 2, 3, 4, 5}

		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: sanity check failed: ephemeral secret contains an invalid signature")
	})

	s.Run("invalid epoch", func() {
		sigSecret := newSignedSecret()
		sigSecret.Secret.Epoch = 2

		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: sanity check failed: ephemeral secret contains an invalid epoch: (expected: 1, got: 2)")
	})

	s.Run("happy path", func() {
		sigSecret := newSignedSecret()
		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.NoError(s.T(), err, "publishEphemeralSecret")
	})

	s.Run("ephemeral secret already published", func() {
		sigSecret := newSignedSecret()
		err := s.ext.publishEphemeralSecret(s.txCtx, s.kmState, sigSecret)
		require.EqualError(s.T(), err, "keymanager: ephemeral secret can be proposed once per epoch")
	})
}

func (s *TxTestSuite) TestUpdatePolicy() {
	// Initialize consensus parameters across states.
	err := s.kmState.SetConsensusParameters(s.ctx, &secrets.ConsensusParameters{})
	require.NoError(s.T(), err)

	err = s.regState.SetConsensusParameters(s.ctx, &registryAPI.ConsensusParameters{})
	require.NoError(s.T(), err)

	consState := consensusState.NewMutableState(s.ctx.State())
	err = consState.SetConsensusParameters(s.ctx, &consensusGenesis.Parameters{
		FeatureVersion: &version.Version{
			Major: math.MaxUint16,
		},
	})
	require.NoError(s.T(), err)

	// Select one key manager.
	kmID := s.kmIDs[0]

	// Helper for signing a policy with all available signers.
	preparePolicy := func(serial uint32, id common.Namespace) *secrets.SignedPolicySGX {
		policy := secrets.PolicySGX{
			Serial: serial,
			ID:     id,
		}
		sigPolicy := &secrets.SignedPolicySGX{
			Policy: policy,
		}
		for _, signer := range s.signers {
			sig, err := signature.Sign(signer, secrets.PolicySGXSignatureContext, cbor.Marshal(policy))
			require.NoError(s.T(), err)
			sigPolicy.Signatures = append(sigPolicy.Signatures, *sig)
		}
		return sigPolicy
	}

	s.Run("reject non-keymanager runtime", func() {
		policy := preparePolicy(0, s.runtimeID)
		err := s.ext.updatePolicy(s.txCtx, s.kmState, policy)
		require.Error(s.T(), err)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.Run("reject invalid signer", func() {
		policy := preparePolicy(0, kmID)
		err := s.ext.updatePolicy(s.txCtx, s.kmState, policy)
		require.Error(s.T(), err)
		require.ErrorContains(s.T(), err, "invalid update signer")
	})

	// Set the right transaction signer.
	s.txCtx.SetTxSigner(s.runtimeSigner.Public())

	s.Run("schedule policy", func() {
		policy := preparePolicy(2, kmID)
		err = s.ext.updatePolicy(s.txCtx, s.kmState, policy)
		require.NoError(s.T(), err)

		status, err := s.kmState.Status(s.ctx, kmID)
		require.NoError(s.T(), err)
		require.Nil(s.T(), status.Policy)
		require.Equal(s.T(), status.NextPolicy, policy)
	})

	// Prepare a policy.
	policy := preparePolicy(1, kmID)

	s.Run("overwrite policy with lower serial", func() {
		err = s.ext.updatePolicy(s.txCtx, s.kmState, policy)
		require.NoError(s.T(), err)

		status, err := s.kmState.Status(s.ctx, kmID)
		require.NoError(s.T(), err)
		require.Nil(s.T(), status.Policy)
		require.Equal(s.T(), status.NextPolicy, policy)
	})

	// Pretend that policy was accepted.
	status, err := s.kmState.Status(s.ctx, kmID)
	require.NoError(s.T(), err)

	status.Policy = policy
	status.NextPolicy = nil

	err = s.kmState.SetStatus(s.ctx, status)
	require.NoError(s.T(), err)

	// Prepare next policy.
	nextPolicy := preparePolicy(2, kmID)

	s.Run("schedule policy with higher serial", func() {
		err = s.ext.updatePolicy(s.txCtx, s.kmState, nextPolicy)
		require.NoError(s.T(), err)

		status, err = s.kmState.Status(s.ctx, nextPolicy.Policy.ID)
		require.NoError(s.T(), err)
		require.Equal(s.T(), status.Policy, policy)
		require.Equal(s.T(), status.NextPolicy, nextPolicy)
	})

	s.Run("reject non-increasing serial", func() {
		err = s.ext.updatePolicy(s.txCtx, s.kmState, policy)
		require.Error(s.T(), err)
		require.ErrorContains(s.T(), err, "SGX policy serial number did not increase")
	})

	// Enable legacy policy updates.
	err = consState.SetConsensusParameters(s.ctx, &consensusGenesis.Parameters{
		FeatureVersion: &version.Version{},
	})
	require.NoError(s.T(), err)

	// Reset status.
	status, err = s.kmState.Status(s.ctx, kmID)
	require.NoError(s.T(), err)

	status.Policy = nil
	status.NextPolicy = nil

	err = s.kmState.SetStatus(s.ctx, status)
	require.NoError(s.T(), err)

	s.Run("legacy set policy", func() {
		err = s.ext.updatePolicy(s.txCtx, s.kmState, policy)
		require.NoError(s.T(), err)

		status, err = s.kmState.Status(s.ctx, kmID)
		require.NoError(s.T(), err)
		require.Equal(s.T(), status.Policy, policy)
		require.Nil(s.T(), status.NextPolicy)
	})

	s.Run("legacy update policy", func() {
		err = s.ext.updatePolicy(s.txCtx, s.kmState, nextPolicy)
		require.NoError(s.T(), err)

		status, err = s.kmState.Status(s.ctx, kmID)
		require.NoError(s.T(), err)
		require.Equal(s.T(), status.Policy, nextPolicy)
		require.Nil(s.T(), status.NextPolicy)
	})

	s.Run("legacy reject non-increasing serial", func() {
		err = s.ext.updatePolicy(s.txCtx, s.kmState, nextPolicy)
		require.Error(s.T(), err)
		require.ErrorContains(s.T(), err, "SGX policy serial number did not increase")
	})
}

func TestTxTestSuite(t *testing.T) {
	suite.Run(t, new(TxTestSuite))
}
