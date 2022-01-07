package genesis

import (
	"encoding/json"
	"math"
	"net"
	"time"

	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmtypes "github.com/tendermint/tendermint/types"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/identity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	tendermint "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	"github.com/oasisprotocol/oasis-core/go/consensus/tendermint/crypto"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
)

var _ tendermint.GenesisProvider = (*testNodeGenesisProvider)(nil)

type testNodeGenesisProvider struct {
	document   *genesis.Document
	tmDocument *tmtypes.GenesisDoc
}

func (p *testNodeGenesisProvider) GetGenesisDocument() (*genesis.Document, error) {
	return p.document, nil
}

func (p *testNodeGenesisProvider) GetTendermintGenesisDocument() (*tmtypes.GenesisDoc, error) {
	return p.tmDocument, nil
}

// NewTestNodeGenesisProvider creates a synthetic genesis document for
// running a single node "network", only for testing.
func NewTestNodeGenesisProvider(identity *identity.Identity, ent *entity.Entity, entSigner signature.Signer) (genesis.Provider, error) {
	doc := &genesis.Document{
		Height:    1,
		ChainID:   genesisTestHelpers.TestChainID,
		Time:      time.Now(),
		HaltEpoch: beacon.EpochTime(math.MaxUint64),
		Beacon: beacon.Genesis{
			Parameters: beacon.ConsensusParameters{
				Backend:          beacon.BackendInsecure,
				DebugMockBackend: true,
				InsecureParameters: &beacon.InsecureParameters{
					// Since mock backend is used, this interval is only relevant
					// for determining consensus max evidence age. Make this big
					// emough so that the `SlashConsensusEquivocation` test works.
					Interval: 10_000,
				},
			},
		},
		Registry: registry.Genesis{
			Parameters: registry.ConsensusParameters{
				DebugAllowUnroutableAddresses: true,
				DebugAllowTestRuntimes:        true,
				DebugBypassStake:              true,
				EnableRuntimeGovernanceModels: map[registry.RuntimeGovernanceModel]bool{
					registry.GovernanceEntity:  true,
					registry.GovernanceRuntime: true,
				},
			},
		},
		Scheduler: scheduler.Genesis{
			Parameters: scheduler.ConsensusParameters{
				MinValidators:          1,
				MaxValidators:          100,
				MaxValidatorsPerEntity: 100,
				DebugBypassStake:       true,
			},
		},
		Governance: governance.Genesis{
			Parameters: governance.ConsensusParameters{
				StakeThreshold:            90,
				UpgradeCancelMinEpochDiff: 20,
				UpgradeMinEpochDiff:       20,
				VotingPeriod:              10,
				MinProposalDeposit:        *quantity.NewFromUint64(100),
			},
		},
		RootHash: roothash.Genesis{
			Parameters: roothash.ConsensusParameters{
				DebugDoNotSuspendRuntimes: true,
				MaxRuntimeMessages:        32,
				MaxInRuntimeMessages:      32,
			},
		},
		Consensus: consensus.Genesis{
			Backend: tendermint.BackendName,
			Parameters: consensus.Parameters{
				TimeoutCommit:     1 * time.Millisecond,
				SkipTimeoutCommit: true,
				MaxBlockSize:      21 * 1024 * 1024,
				MaxEvidenceSize:   1024 * 1024,
			},
		},
		Staking: stakingTests.GenesisState(),
	}

	// Update consensus equivocation freeze period to 0, so that we can test slashing on the single validator.
	doc.Staking.Parameters.Slashing[api.SlashConsensusEquivocation] = api.Slash{
		Amount:         *quantity.NewFromUint64(math.MaxInt64),
		FreezeInterval: 0,
	}

	// Include test node entity in genesis.
	signedEnt, err := entity.SignEntity(entSigner, registry.RegisterGenesisEntitySignatureContext, ent)
	if err != nil {
		return nil, err
	}
	doc.Registry.Entities = append(doc.Registry.Entities, signedEnt)

	// Include test node descriptor in registry genesis.
	var nextPubKey signature.PublicKey
	if s := identity.GetNextTLSSigner(); s != nil {
		nextPubKey = s.Public()
	}
	var consensusAddr node.Address
	if err = consensusAddr.FromIP(net.ParseIP("127.0.0.1"), 9999); err != nil { // Irrelevant address, as this is a single node network.
		return nil, err
	}
	n := &node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         identity.NodeSigner.Public(),
		EntityID:   ent.ID,
		Expiration: 2,
		TLS: node.TLSInfo{
			PubKey:     identity.GetTLSSigner().Public(),
			NextPubKey: nextPubKey,
		},
		P2P: node.P2PInfo{
			ID: identity.P2PSigner.Public(),
		},
		Consensus: node.ConsensusInfo{
			ID: identity.ConsensusSigner.Public(),
			Addresses: []node.ConsensusAddress{
				{
					ID:      identity.ConsensusSigner.Public(),
					Address: consensusAddr,
				},
			},
		},
		VRF: &node.VRFInfo{
			ID: identity.VRFSigner.Public(),
		},
		Roles: node.RoleValidator,
	}
	signers := []signature.Signer{
		identity.NodeSigner,
		identity.P2PSigner,
		identity.ConsensusSigner,
		identity.VRFSigner,
		identity.GetTLSSigner(),
	}
	signed, err := node.MultiSignNode(signers, registry.RegisterGenesisNodeSignatureContext, n)
	if err != nil {
		return nil, err
	}
	doc.Registry.Nodes = append(doc.Registry.Nodes, signed)

	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	tmDoc := &tmtypes.GenesisDoc{
		InitialHeight:   doc.Height,
		ChainID:         doc.ChainID,
		GenesisTime:     doc.Time,
		ConsensusParams: tmtypes.DefaultConsensusParams(),
		AppState:        b,
	}
	tmDoc.ConsensusParams.Version = tmproto.VersionParams{
		AppVersion: version.TendermintAppVersion,
	}

	nodeID := identity.ConsensusSigner.Public()
	pk := crypto.PublicKeyToTendermint(&nodeID)
	validator := tmtypes.GenesisValidator{
		Address: pk.Address(),
		PubKey:  pk,
		Power:   1,
		Name:    "oasis-test-validator-" + nodeID.String(),
	}

	tmDoc.Validators = append(tmDoc.Validators, validator)

	return &testNodeGenesisProvider{
		document:   doc,
		tmDocument: tmDoc,
	}, nil
}
