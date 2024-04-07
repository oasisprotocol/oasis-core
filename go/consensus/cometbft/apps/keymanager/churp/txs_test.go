package churp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	abciAPI "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/api"
	churpState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/keymanager/churp/state"
	registryState "github.com/oasisprotocol/oasis-core/go/consensus/cometbft/apps/registry/state"
	"github.com/oasisprotocol/oasis-core/go/keymanager/churp"
	registryAPI "github.com/oasisprotocol/oasis-core/go/registry/api"
)

const (
	numNodes              = 2
	numComputeRuntimes    = 1
	numKeyManagerRuntimes = 2
)

type testEntity struct {
	signer signature.Signer
}

type testNode struct {
	signer signature.Signer
	rak    signature.Signer
}

func TestTxTestSuite(t *testing.T) {
	suite.Run(t, new(TxTestSuite))
}

type TxTestSuite struct {
	suite.Suite

	ext churpExt

	ctx   *abciAPI.Context
	txCtx *abciAPI.Context
	cfg   *abciAPI.MockApplicationStateConfig

	state *churpState.MutableState

	nodes              []*testNode
	computeRuntimes    []*registryAPI.Runtime
	keymanagerRuntimes []*registryAPI.Runtime
	entity             *testEntity
}

func (s *TxTestSuite) SetupTest() {
	// Prepare extension.
	s.cfg = &abciAPI.MockApplicationStateConfig{}
	appState := abciAPI.NewMockApplicationState(s.cfg)
	s.ext = churpExt{
		state: appState,
	}

	// Prepare abci contexts.
	s.ctx = appState.NewContext(abciAPI.ContextEndBlock)
	s.txCtx = appState.NewContext(abciAPI.ContextDeliverTx)

	// Prepare states.
	s.state = churpState.NewMutableState(s.ctx.State())
	regState := registryState.NewMutableState(s.ctx.State())

	// Set up default consensus parameters.
	err := s.state.SetConsensusParameters(s.ctx, &churp.DefaultConsensusParameters)
	require.NoError(s.T(), err)

	// Prepare nodes.
	s.nodes = make([]*testNode, 0, numNodes)
	var nodes []signature.PublicKey
	for i := 0; i < numNodes; i++ {
		s.nodes = append(s.nodes, &testNode{
			signer: memorySigner.NewTestSigner(fmt.Sprintf("node %d", i)),
			rak:    memorySigner.NewTestSigner(fmt.Sprintf("rak %d", i)),
		})

		nodes = append(nodes, s.nodes[i].signer.Public())
	}

	// Register an entity.
	s.entity = &testEntity{
		signer: memorySigner.NewTestSigner("entity"),
	}
	ent := entity.Entity{
		Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
		ID:        s.entity.signer.Public(),
		Nodes:     nodes,
	}

	sigEnt, err := entity.SignEntity(s.entity.signer, registryAPI.RegisterEntitySignatureContext, &ent)
	require.NoError(s.T(), err)
	err = regState.SetEntity(s.ctx, &ent, sigEnt)
	require.NoError(s.T(), err)

	// Prepare and register runtimes.
	for i := 0; i < numComputeRuntimes; i++ {
		s.computeRuntimes = append(s.computeRuntimes, &registryAPI.Runtime{
			ID:       common.NewTestNamespaceFromSeed([]byte{0, byte(i)}, common.NamespaceTest),
			Kind:     registryAPI.KindCompute,
			EntityID: s.entity.signer.Public(),
		})

		err = regState.SetRuntime(s.ctx, s.computeRuntimes[i], false)
		require.NoError(s.T(), err)
	}

	for i := 0; i < numKeyManagerRuntimes; i++ {
		s.keymanagerRuntimes = append(s.keymanagerRuntimes, &registryAPI.Runtime{
			ID:          common.NewTestNamespaceFromSeed([]byte{1, byte(i)}, common.NamespaceTest),
			Kind:        registryAPI.KindKeyManager,
			TEEHardware: node.TEEHardwareIntelSGX,
			EntityID:    s.entity.signer.Public(),
		})

		err = regState.SetRuntime(s.ctx, s.keymanagerRuntimes[i], false)
		require.NoError(s.T(), err)
	}

	// Register nodes.
	for i := range s.nodes {
		n := &node.Node{
			Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
			ID:        s.nodes[i].signer.Public(),
			Consensus: node.ConsensusInfo{
				ID: s.nodes[i].signer.Public(),
			},
			EntityID:   s.entity.signer.Public(),
			Roles:      node.RoleKeyManager,
			Expiration: 100,
		}

		for _, rt := range s.keymanagerRuntimes {
			n.Runtimes = append(n.Runtimes, &node.Runtime{
				ID: rt.ID,
				Capabilities: node.Capabilities{
					TEE: &node.CapabilityTEE{
						Hardware: rt.TEEHardware,
						RAK:      s.nodes[i].rak.Public(),
					},
				},
			})
		}

		sigNode, nErr := node.MultiSignNode([]signature.Signer{s.nodes[i].signer}, registryAPI.RegisterNodeSignatureContext, n)
		require.NoError(s.T(), nErr)
		err = regState.SetNode(s.ctx, nil, n, sigNode)
		require.NoError(s.T(), err)

	}

	// Use entity as transaction signer.
	s.txCtx.SetTxSigner(s.entity.signer.Public())
}

func (s *TxTestSuite) TearDownTest() {
	s.ctx.Close()
	s.txCtx.Close()
}

func (s *TxTestSuite) TestCreate() {
	s.Run("not key manager runtime", func() {
		req := churp.CreateRequest{
			Identity: churp.Identity{
				RuntimeID: s.computeRuntimes[0].ID,
			},
		}
		err := s.ext.create(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.Run("not key manager owner", func() {
		s.txCtx.SetTxSigner(s.nodes[0].signer.Public())
		defer s.txCtx.SetTxSigner(s.entity.signer.Public())

		req := churp.CreateRequest{
			Identity: churp.Identity{
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
		}
		err := s.ext.create(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid signer")
	})

	s.Run("invalid config", func() {
		req := churp.CreateRequest{
			Identity: churp.Identity{
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
			GroupID: 100,
		}
		err := s.ext.create(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid config: unsupported group, ID 100")
	})

	s.Run("happy path - handoffs disabled", func() {
		identity := churp.Identity{
			ID:        0,
			RuntimeID: s.keymanagerRuntimes[0].ID,
		}
		policy := churp.SignedPolicySGX{
			Policy: churp.PolicySGX{
				Identity: identity,
			},
		}
		req := churp.CreateRequest{
			Identity:        identity,
			GroupID:         churp.EccNistP384,
			Threshold:       1,
			HandoffInterval: 0,
			Policy:          policy,
		}
		err := s.ext.create(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Create event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 1)

		// Verify status.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), uint8(0), status.ID)
		require.Equal(s.T(), s.keymanagerRuntimes[0].ID, status.RuntimeID)
		require.Equal(s.T(), churp.EccNistP384, status.GroupID)
		require.Equal(s.T(), uint8(1), status.Threshold)
		require.Equal(s.T(), beacon.EpochTime(0), status.HandoffInterval)
		require.Equal(s.T(), policy, status.Policy)
		require.Equal(s.T(), beacon.EpochTime(0), status.Handoff)
		require.Nil(s.T(), status.Checksum)
		require.Nil(s.T(), status.Committee)
		require.Equal(s.T(), churp.HandoffsDisabled, status.NextHandoff)
		require.Nil(s.T(), status.NextChecksum)
		require.Nil(s.T(), status.Applications)
	})

	s.Run("happy path - handoffs enabled", func() {
		identity := churp.Identity{
			ID:        1,
			RuntimeID: s.keymanagerRuntimes[0].ID,
		}
		policy := churp.SignedPolicySGX{
			Policy: churp.PolicySGX{
				Identity: identity,
			},
		}
		req := churp.CreateRequest{
			Identity:        identity,
			GroupID:         churp.EccNistP384,
			Threshold:       1,
			HandoffInterval: 10,
			Policy:          policy,
		}
		err := s.ext.create(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Verify status.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 1)
		require.NoError(s.T(), err)
		require.Equal(s.T(), beacon.EpochTime(1), status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(10), status.HandoffInterval)
	})

	s.Run("duplicate ID", func() {
		req := churp.CreateRequest{
			Identity: churp.Identity{
				ID:        0,
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
		}
		err := s.ext.create(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid config: ID must be unique")
	})
}

func (s *TxTestSuite) TestUpdate() {
	s.create()

	s.Run("not key manager runtime", func() {
		req := s.updateRequest()
		req.Identity.RuntimeID = s.computeRuntimes[0].ID

		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.txCtx.SetTxSigner(s.nodes[0].signer.Public())

	s.Run("not key manager owner", func() {
		req := s.updateRequest()

		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid signer")
	})

	s.txCtx.SetTxSigner(s.entity.signer.Public())

	s.Run("non-existing instance", func() {
		req := s.updateRequest()
		req.Identity.ID = 1 // Wrong ID.

		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")

		req = s.updateRequest()
		req.Identity.RuntimeID = s.keymanagerRuntimes[1].ID // Wrong runtime ID.

		err = s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")
	})

	s.Run("invalid config", func() {
		req := s.updateRequest()

		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid config: update config should not be empty")
	})

	s.Run("happy path - enable handoffs", func() {
		handoffInterval := beacon.EpochTime(100)
		req := s.updateRequest()
		req.HandoffInterval = &handoffInterval

		err := s.ext.update(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Update event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 2)

		// Verify status.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), beacon.EpochTime(1), status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(100), status.HandoffInterval)
	})

	s.Run("happy path - extend handoff interval", func() {
		handoffInterval := beacon.EpochTime(200)
		req := s.updateRequest()
		req.HandoffInterval = &handoffInterval

		err := s.ext.update(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Update event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 3)

		// Verify status.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), beacon.EpochTime(1), status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(200), status.HandoffInterval)
	})

	s.Run("happy path - disable handoffs", func() {
		handoffInterval := beacon.EpochTime(0)
		req := s.updateRequest()
		req.HandoffInterval = &handoffInterval

		err := s.ext.update(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Update event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 4)

		// Verify status.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), churp.HandoffsDisabled, status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(0), status.HandoffInterval)
	})
}

func (s *TxTestSuite) TestApply() {
	s.create()

	s.Run("not key manager runtime", func() {
		req := s.signedApplicationRequest()
		req.Application.Identity.RuntimeID = s.computeRuntimes[0].ID

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.Run("non-existing instance", func() {
		req := s.signedApplicationRequest()
		req.Application.Identity.ID = 1 // Wrong ID.

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")

		req = s.signedApplicationRequest()
		req.Application.Identity.RuntimeID = s.keymanagerRuntimes[1].ID // Wrong runtime ID.

		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")
	})

	s.Run("handoffs disabled", func() {
		req := s.signedApplicationRequest()

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "handoffs disabled")
	})

	s.enableHandoffs()

	s.cfg.CurrentEpoch = 1

	s.Run("submissions closed", func() {
		req := s.signedApplicationRequest()

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "submissions closed")
	})

	s.cfg.CurrentEpoch = 0

	s.Run("invalid handoff epoch", func() {
		req := s.signedApplicationRequest()
		req.Application.Epoch = 100

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid handoff")
	})

	s.Run("invalid RAK signature", func() {
		req := s.signedApplicationRequest()

		s.txCtx.SetTxSigner(s.nodes[0].signer.Public())

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "RAK signature verification failed")
	})

	s.Run("happy path", func() {
		req := s.signedApplicationRequest()
		s.signApplicationRequest(0, &req)

		s.txCtx.SetTxSigner(s.nodes[0].signer.Public())

		err := s.ext.apply(s.txCtx, &req)
		require.NoError(s.T(), err)
	})

	s.Run("duplicate submission", func() {
		req := s.signedApplicationRequest()
		s.signApplicationRequest(0, &req)

		err := s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "application already submitted")
	})
}

func (s *TxTestSuite) TestConfirm() {
	s.create()

	s.Run("not key manager runtime", func() {
		req := s.signedConfirmationRequest()
		req.Confirmation.Identity.RuntimeID = s.computeRuntimes[0].ID

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.Run("non-existing instance", func() {
		req := s.signedConfirmationRequest() // Wrong ID.
		req.Confirmation.Identity.ID = 1

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")

		req = s.signedConfirmationRequest()
		req.Confirmation.Identity.RuntimeID = s.keymanagerRuntimes[1].ID // Wrong runtime ID.

		err = s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")
	})

	s.Run("handoffs disabled", func() {
		req := s.signedConfirmationRequest()

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "handoffs disabled")
	})

	s.enableHandoffs()

	s.cfg.CurrentEpoch = 2

	s.Run("confirmations closed", func() {
		req := s.signedConfirmationRequest()

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "confirmations closed")
	})

	s.cfg.CurrentEpoch = 1

	s.Run("invalid handoff epoch", func() {
		req := s.signedConfirmationRequest()
		req.Confirmation.Epoch = 100

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid handoff")
	})

	s.Run("no application", func() {
		req := s.signedConfirmationRequest()

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "application not found")
	})

	s.cfg.CurrentEpoch = 0

	// Prepare and submit few applications.
	for i := range s.nodes {
		req := s.signedApplicationRequest()
		s.signApplicationRequest(i, &req)

		s.txCtx.SetTxSigner(s.nodes[i].signer.Public())

		err := s.ext.apply(s.txCtx, &req)
		require.NoError(s.T(), err)
	}

	s.cfg.CurrentEpoch = 1

	s.Run("invalid RAK signature", func() {
		req := s.signedConfirmationRequest()

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "RAK signature verification failed")
	})

	s.Run("happy path", func() {
		req := s.signedConfirmationRequest()
		s.signConfirmationRequest(0, &req)

		s.txCtx.SetTxSigner(s.nodes[0].signer.Public())

		err := s.ext.confirm(s.txCtx, &req)
		require.NoError(s.T(), err)
	})

	s.Run("duplicate submission", func() {
		req := s.signedConfirmationRequest()
		s.signConfirmationRequest(0, &req)

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "confirmation already submitted")
	})

	s.Run("checksum mismatch", func() {
		req := s.signedConfirmationRequest()
		req.Confirmation.Checksum = hash.Hash{3, 2, 1}

		s.txCtx.SetTxSigner(s.nodes[1].signer.Public())

		err := s.ext.confirm(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "checksum mismatch")
	})

	s.Run("handoff completed", func() {
		req := s.signedConfirmationRequest()
		s.signConfirmationRequest(1, &req)

		err := s.ext.confirm(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Verify status.
		committee := []signature.PublicKey{s.nodes[0].signer.Public(), s.nodes[1].signer.Public()}

		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), beacon.EpochTime(1), status.Handoff)
		require.Equal(s.T(), beacon.EpochTime(2), status.NextHandoff)
		require.Equal(s.T(), &hash.Hash{1, 2, 3}, status.Checksum)
		require.ElementsMatch(s.T(), committee, status.Committee)
		require.Nil(s.T(), status.NextChecksum)
		require.Nil(s.T(), status.Applications)
	})
}

func (s *TxTestSuite) create() {
	// Prepare one instance in advance.
	identity := churp.Identity{
		ID:        0,
		RuntimeID: s.keymanagerRuntimes[0].ID,
	}
	createReq := churp.CreateRequest{
		Identity:        identity,
		GroupID:         churp.EccNistP384,
		Threshold:       1,
		HandoffInterval: 0,
		Policy: churp.SignedPolicySGX{
			Policy: churp.PolicySGX{
				Identity: identity,
				Serial:   0,
			},
		},
	}
	err := s.ext.create(s.txCtx, &createReq)
	require.NoError(s.T(), err)

	// Create event should be emitted.
	events := s.txCtx.GetEvents()
	require.Len(s.T(), events, 1)
}

func (s *TxTestSuite) enableHandoffs() {
	handoffInterval := beacon.EpochTime(1)
	req := churp.UpdateRequest{
		Identity: churp.Identity{
			ID:        0,
			RuntimeID: s.keymanagerRuntimes[0].ID,
		},
		HandoffInterval: &handoffInterval,
	}

	err := s.ext.update(s.txCtx, &req)
	require.NoError(s.T(), err)
}

func (s *TxTestSuite) signApplicationRequest(nodeIdx int, req *churp.SignedApplicationRequest) {
	rak := s.nodes[nodeIdx].rak
	rawSigBytes, err := rak.ContextSign(churp.ApplicationRequestSignatureContext, cbor.Marshal(req.Application))
	require.NoError(s.T(), err)
	copy(req.Signature[:], rawSigBytes)
}

func (s *TxTestSuite) signConfirmationRequest(nodeIdx int, req *churp.SignedConfirmationRequest) {
	rak := s.nodes[nodeIdx].rak
	rawSigBytes, err := rak.ContextSign(churp.ConfirmationRequestSignatureContext, cbor.Marshal(req.Confirmation))
	require.NoError(s.T(), err)
	copy(req.Signature[:], rawSigBytes)
}

func (s *TxTestSuite) signedApplicationRequest() churp.SignedApplicationRequest {
	return churp.SignedApplicationRequest{
		Application: churp.ApplicationRequest{
			Identity: churp.Identity{
				ID:        0,
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
			Epoch:    1,
			Checksum: hash.Hash{1, 2, 3},
		},
		Signature: signature.RawSignature{},
	}
}

func (s *TxTestSuite) signedConfirmationRequest() churp.SignedConfirmationRequest {
	return churp.SignedConfirmationRequest{
		Confirmation: churp.ConfirmationRequest{
			Identity: churp.Identity{
				ID:        0,
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
			Epoch:    1,
			Checksum: hash.Hash{1, 2, 3},
		},
		Signature: signature.RawSignature{},
	}
}

func (s *TxTestSuite) updateRequest() churp.UpdateRequest {
	return churp.UpdateRequest{
		Identity: churp.Identity{
			ID:        0,
			RuntimeID: s.keymanagerRuntimes[0].ID,
		},
	}
}
