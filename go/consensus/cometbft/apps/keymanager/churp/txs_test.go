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
	numNodes              = 1
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

func TestCreateSuite(t *testing.T) {
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
			EntityID: s.entity.signer.Public(),
			Roles:    node.RoleKeyManager,
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
			Threshold: 0,
		}
		err := s.ext.create(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid config: threshold must be at least 1, got 0")
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

		// Verify state.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), uint8(0), status.ID)
		require.Equal(s.T(), s.keymanagerRuntimes[0].ID, status.RuntimeID)
		require.Equal(s.T(), churp.EccNistP384, status.GroupID)
		require.Equal(s.T(), uint8(1), status.Threshold)
		require.Equal(s.T(), beacon.EpochTime(0), status.ActiveHandoff)
		require.Equal(s.T(), churp.HandoffsDisabled, status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(0), status.HandoffInterval)
		require.Equal(s.T(), policy, status.Policy)
		require.Nil(s.T(), status.Committee)
		require.Nil(s.T(), status.Applications)
		require.Nil(s.T(), status.Checksum)
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

		// Verify state.
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

	s.Run("not key manager runtime", func() {
		req := churp.UpdateRequest{
			Identity: churp.Identity{
				RuntimeID: s.computeRuntimes[0].ID,
			},
		}
		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.Run("not key manager owner", func() {
		s.txCtx.SetTxSigner(s.nodes[0].signer.Public())
		defer s.txCtx.SetTxSigner(s.entity.signer.Public())

		req := churp.UpdateRequest{
			Identity: churp.Identity{
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
		}
		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid signer")
	})

	s.Run("non-existing instance", func() {
		// Wrong ID.
		req := churp.UpdateRequest{
			Identity: churp.Identity{
				ID:        1,
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
		}
		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")

		// Wrong runtime ID.
		req = churp.UpdateRequest{
			Identity: churp.Identity{
				ID:        0,
				RuntimeID: s.keymanagerRuntimes[1].ID,
			},
		}
		err = s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")
	})

	req := churp.UpdateRequest{
		Identity: churp.Identity{
			ID:        0,
			RuntimeID: s.keymanagerRuntimes[0].ID,
		},
	}

	s.Run("invalid config", func() {
		err := s.ext.update(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid config: update config should not be empty")
	})

	s.Run("happy path - enable handoffs", func() {
		handoffInterval := beacon.EpochTime(100)
		req.HandoffInterval = &handoffInterval

		err := s.ext.update(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Update event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 2)

		// Verify state.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), beacon.EpochTime(1), status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(100), status.HandoffInterval)
	})

	s.Run("happy path - extend handoff interval", func() {
		handoffInterval := beacon.EpochTime(200)
		req.HandoffInterval = &handoffInterval

		err := s.ext.update(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Update event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 3)

		// Verify state.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), beacon.EpochTime(1), status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(200), status.HandoffInterval)
	})

	s.Run("happy path - disable handoffs", func() {
		handoffInterval := beacon.EpochTime(0)
		req.HandoffInterval = &handoffInterval

		err := s.ext.update(s.txCtx, &req)
		require.NoError(s.T(), err)

		// Update event should be emitted.
		events := s.txCtx.GetEvents()
		require.Len(s.T(), events, 4)

		// Verify state.
		status, err := s.state.Status(s.txCtx, s.keymanagerRuntimes[0].ID, 0)
		require.NoError(s.T(), err)
		require.Equal(s.T(), churp.HandoffsDisabled, status.NextHandoff)
		require.Equal(s.T(), beacon.EpochTime(0), status.HandoffInterval)
	})
}

func (s *TxTestSuite) TestApply() {
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

	s.Run("not key manager runtime", func() {
		req := churp.SignedApplicationRequest{
			Application: churp.ApplicationRequest{
				Identity: churp.Identity{
					RuntimeID: s.computeRuntimes[0].ID,
				},
			},
		}
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "runtime is not a key manager")
	})

	s.Run("non-existing instance", func() {
		// Wrong ID.
		req := churp.SignedApplicationRequest{
			Application: churp.ApplicationRequest{
				Identity: churp.Identity{
					ID:        1,
					RuntimeID: s.keymanagerRuntimes[0].ID,
				},
			},
		}
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")

		// Wrong runtime ID.
		req = churp.SignedApplicationRequest{
			Application: churp.ApplicationRequest{
				Identity: churp.Identity{
					ID:        0,
					RuntimeID: s.keymanagerRuntimes[1].ID,
				},
			},
		}
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "non-existing ID")
	})

	s.Run("handoffs disabled", func() {
		req := churp.SignedApplicationRequest{
			Application: churp.ApplicationRequest{
				Identity: churp.Identity{
					ID:        0,
					RuntimeID: s.keymanagerRuntimes[0].ID,
				},
			},
		}
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "handoffs disabled")
	})

	// Enable handoffs.
	handoffInterval := beacon.EpochTime(1)
	updateReq := churp.UpdateRequest{
		Identity: churp.Identity{
			ID:        0,
			RuntimeID: s.keymanagerRuntimes[0].ID,
		},
		HandoffInterval: &handoffInterval,
	}
	err = s.ext.update(s.txCtx, &updateReq)
	require.NoError(s.T(), err)

	s.Run("submissions closed", func() {
		s.cfg.CurrentEpoch = 1

		req := churp.SignedApplicationRequest{
			Application: churp.ApplicationRequest{
				Identity: churp.Identity{
					ID:        0,
					RuntimeID: s.keymanagerRuntimes[0].ID,
				},
			},
		}
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "submissions closed")

		s.cfg.CurrentEpoch = 0
	})

	s.Run("invalid handoff", func() {
		req := churp.SignedApplicationRequest{
			Application: churp.ApplicationRequest{
				Identity: churp.Identity{
					ID:        0,
					RuntimeID: s.keymanagerRuntimes[0].ID,
				},
				Handoff: 100,
			},
		}
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "invalid handoff")
	})

	// A request with invalid signature.
	req := churp.SignedApplicationRequest{
		Application: churp.ApplicationRequest{
			Identity: churp.Identity{
				ID:        0,
				RuntimeID: s.keymanagerRuntimes[0].ID,
			},
			Handoff:  1,
			Checksum: hash.Hash{1, 2, 3},
		},
		Signature: signature.RawSignature{},
	}

	// A valid tx signer.
	s.txCtx.SetTxSigner(s.nodes[0].signer.Public())

	s.Run("invalid RAK signature", func() {
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "RAK signature verification failed")
	})

	// Sign the request.
	rak := s.nodes[0].rak
	rawSigBytes, err := rak.ContextSign(churp.ApplicationRequestSignatureContext, cbor.Marshal(req.Application))
	require.NoError(s.T(), err)
	copy(req.Signature[:], rawSigBytes)

	s.Run("happy path", func() {
		err = s.ext.apply(s.txCtx, &req)
		require.NoError(s.T(), err)
	})

	s.Run("duplicate submission", func() {
		err = s.ext.apply(s.txCtx, &req)
		require.ErrorContains(s.T(), err, "application already submitted")
	})
}
