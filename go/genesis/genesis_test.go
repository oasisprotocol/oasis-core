package genesis

import (
	"encoding/hex"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	beacon "github.com/oasisprotocol/oasis-core/go/beacon/api"
	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/entity"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	"github.com/oasisprotocol/oasis-core/go/common/quantity"
	"github.com/oasisprotocol/oasis-core/go/common/sgx"
	"github.com/oasisprotocol/oasis-core/go/common/version"
	consensus "github.com/oasisprotocol/oasis-core/go/consensus/genesis"
	tendermint "github.com/oasisprotocol/oasis-core/go/consensus/tendermint/api"
	genesis "github.com/oasisprotocol/oasis-core/go/genesis/api"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	governance "github.com/oasisprotocol/oasis-core/go/governance/api"
	keymanager "github.com/oasisprotocol/oasis-core/go/keymanager/api"
	cmdFlags "github.com/oasisprotocol/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	roothash "github.com/oasisprotocol/oasis-core/go/roothash/api"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	staking "github.com/oasisprotocol/oasis-core/go/staking/api"
	"github.com/oasisprotocol/oasis-core/go/staking/api/token"
	stakingTests "github.com/oasisprotocol/oasis-core/go/staking/tests"
	upgrade "github.com/oasisprotocol/oasis-core/go/upgrade/api"
)

// Note: If you are here wanting to alter the genesis document used for
// the node that is spun up as part of the tests, you really want
// consensus/tendermint/tests/genesis/genesis.go.
func testDoc() genesis.Document {
	return genesis.Document{
		Height:    1,
		ChainID:   genesisTestHelpers.TestChainID,
		Time:      time.Unix(1574858284, 0),
		HaltEpoch: beacon.EpochTime(math.MaxUint64),
		Beacon: beacon.Genesis{
			Parameters: beacon.ConsensusParameters{
				Backend:            beacon.BackendInsecure,
				DebugMockBackend:   true,
				InsecureParameters: &beacon.InsecureParameters{},
			},
		},
		Registry: registry.Genesis{
			Parameters: registry.ConsensusParameters{
				DebugAllowUnroutableAddresses: true,
				DebugBypassStake:              true,
				EnableRuntimeGovernanceModels: map[registry.RuntimeGovernanceModel]bool{
					registry.GovernanceEntity:    true,
					registry.GovernanceRuntime:   true,
					registry.GovernanceConsensus: true,
				},
			},
		},
		Governance: governance.Genesis{
			Parameters: governance.ConsensusParameters{
				StakeThreshold:            90,
				VotingPeriod:              100,
				UpgradeCancelMinEpochDiff: 200,
				UpgradeMinEpochDiff:       200,
			},
		},
		Scheduler: scheduler.Genesis{
			Parameters: scheduler.ConsensusParameters{
				MinValidators:          1,
				MaxValidators:          100,
				MaxValidatorsPerEntity: 100,
				DebugBypassStake:       true,
				// Zero RewardFactorEpochElectionAny is normal.
			},
		},
		Consensus: consensus.Genesis{
			Backend: tendermint.BackendName,
			Parameters: consensus.Parameters{
				TimeoutCommit:     1 * time.Millisecond,
				SkipTimeoutCommit: true,
			},
		},
		Staking: stakingTests.GenesisState(),
	}
}

func signEntityOrDie(signer signature.Signer, e *entity.Entity) *entity.SignedEntity {
	signedEntity, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, e)
	if err != nil {
		panic(err)
	}
	return signedEntity
}

func signNodeOrDie(signers []signature.Signer, n *node.Node) *node.MultiSignedNode {
	signedNode, err := node.MultiSignNode(
		signers,
		registry.RegisterGenesisNodeSignatureContext,
		n,
	)
	if err != nil {
		panic(err)
	}
	return signedNode
}

func hex2ns(str string, force bool) common.Namespace {
	var ns common.Namespace
	if force {
		b, err := hex.DecodeString(str)
		if err != nil {
			panic(err)
		}
		copy(ns[:], b)
		return ns
	}
	if err := ns.UnmarshalHex(str); err != nil {
		panic(err)
	}
	return ns
}

func TestGenesisChainContext(t *testing.T) {
	// Ensure that the chain context is stable.
	stableDoc := testDoc()
	// NOTE: Staking part is not stable as it generates a new public key
	//       on each run.
	stableDoc.Staking = staking.Genesis{}

	// Having to update this every single time the genesis structure
	// changes isn't annoying at all.
	require.Equal(t, "a51281549373c59d90954f429a7df7d90f47a50735102f7e08a6304446ce1be9", stableDoc.ChainContext())
}

func TestGenesisSanityCheck(t *testing.T) {
	viper.Set(cmdFlags.CfgDebugDontBlameOasis, true)
	require := require.New(t)

	// First, set up a few things we'll need in the tests below.
	signer := memorySigner.NewTestSigner("genesis sanity checks signer")
	nodeSigner := memorySigner.NewTestSigner("node genesis sanity checks signer")
	nodeConsensusSigner := memorySigner.NewTestSigner("node consensus genesis sanity checks signer")
	nodeP2PSigner := memorySigner.NewTestSigner("node P2P genesis sanity checks signer")
	nodeTLSSigner := memorySigner.NewTestSigner("node TLS genesis sanity checks signer")
	validPK := signer.Public()
	var validNS common.Namespace
	_ = validNS.UnmarshalBinary(validPK[:])

	invalidPK := memorySigner.NewTestSigner("invalid genesis sanity checks signer").Public()
	require.NoError(invalidPK.Blacklist(), "blacklist invalid signer")
	unknownPK := memorySigner.NewTestSigner("unknown genesis sanity checks signer").Public()

	signature.BuildPublicKeyBlacklist(true)

	var emptyHash hash.Hash
	emptyHash.Empty()
	var nonEmptyHash hash.Hash
	_ = nonEmptyHash.UnmarshalHex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	// Note that this test entity has no nodes by design, those will be added
	// later by various tests.
	testEntity := &entity.Entity{
		Versioned: cbor.NewVersioned(entity.LatestDescriptorVersion),
		ID:        validPK,
	}
	signedTestEntity := signEntityOrDie(signer, testEntity)

	kmRuntimeID := hex2ns("4000000000000000ffffffffffffffffffffffffffffffffffffffffffffffff", false)
	testKMRuntime := &registry.Runtime{
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          kmRuntimeID,
		EntityID:    testEntity.ID,
		Kind:        registry.KindKeyManager,
		TEEHardware: node.TEEHardwareIntelSGX,
		Version: registry.VersionInfo{
			TEE: cbor.Marshal(node.SGXConstraints{
				Enclaves: []sgx.EnclaveIdentity{{}},
			}),
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			EntityWhitelist: &registry.EntityWhitelistRuntimeAdmissionPolicy{
				Entities: map[signature.PublicKey]registry.EntityWhitelistConfig{
					validPK: {},
				},
			},
		},
		GovernanceModel: registry.GovernanceEntity,
	}

	testRuntimeID := hex2ns("0000000000000000000000000000000000000000000000000000000000000001", false)
	testRuntime := &registry.Runtime{
		Versioned:  cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:         testRuntimeID,
		EntityID:   testEntity.ID,
		Kind:       registry.KindCompute,
		KeyManager: &testKMRuntime.ID,
		Executor: registry.ExecutorParameters{
			GroupSize:    1,
			RoundTimeout: 20,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			Algorithm:         "simple",
			BatchFlushTimeout: 1 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1024,
			ProposerTimeout:   20,
		},
		AdmissionPolicy: registry.RuntimeAdmissionPolicy{
			AnyNode: &registry.AnyNodeRuntimeAdmissionPolicy{},
		},
		Constraints: map[scheduler.CommitteeKind]map[scheduler.Role]registry.SchedulingConstraints{
			scheduler.KindComputeExecutor: {
				scheduler.RoleWorker: {
					MinPoolSize: &registry.MinPoolSizeConstraint{
						Limit: 1,
					},
				},
			},
		},
		TEEHardware: node.TEEHardwareIntelSGX,
		Version: registry.VersionInfo{
			TEE: cbor.Marshal(node.SGXConstraints{
				Enclaves: []sgx.EnclaveIdentity{{}},
			}),
		},
		GovernanceModel: registry.GovernanceEntity,
	}

	var testConsensusAddress node.ConsensusAddress
	_ = testConsensusAddress.UnmarshalText([]byte("AAAAAAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBBBBBBBA=@127.0.0.1:1234"))
	var testAddress node.Address
	_ = testAddress.UnmarshalText([]byte("127.0.0.1:1234"))
	testNode := &node.Node{
		Versioned:  cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:         nodeSigner.Public(),
		EntityID:   testEntity.ID,
		Expiration: 10,
		Roles:      node.RoleValidator,
		TLS: node.TLSInfo{
			PubKey: nodeTLSSigner.Public(),
			Addresses: []node.TLSAddress{
				{PubKey: nodeTLSSigner.Public(), Address: testAddress},
			},
		},
		P2P: node.P2PInfo{
			ID:        nodeP2PSigner.Public(),
			Addresses: []node.Address{testAddress},
		},
		Consensus: node.ConsensusInfo{
			ID:        nodeConsensusSigner.Public(),
			Addresses: []node.ConsensusAddress{testConsensusAddress},
		},
	}
	nodeSigners := []signature.Signer{
		nodeSigner,
		nodeP2PSigner,
		nodeTLSSigner,
		nodeConsensusSigner,
	}
	signedTestNode := signNodeOrDie(nodeSigners, testNode)

	// Test genesis document should pass sanity check.
	d := testDoc()
	require.NoError(d.SanityCheck(), "test genesis document should be valid")

	// Test top-level genesis checks.
	d = testDoc()
	d.Height = -123
	require.Error(d.SanityCheck(), "height < 0 should be invalid")

	d = testDoc()
	d.Height = 0
	require.Error(d.SanityCheck(), "height < 1 should be invalid")

	d = testDoc()
	d.ChainID = "   \t"
	require.Error(d.SanityCheck(), "empty chain ID should be invalid")

	d = testDoc()
	d.Beacon.Base = 10
	d.HaltEpoch = 5
	require.Error(d.SanityCheck(), "halt epoch in the past should be invalid")

	// Test consensus genesis checks.
	d = testDoc()
	d.Consensus.Parameters.TimeoutCommit = 0
	d.Consensus.Parameters.SkipTimeoutCommit = false
	require.Error(d.SanityCheck(), "too small timeout commit should be invalid")

	d = testDoc()
	d.Consensus.Parameters.TimeoutCommit = 0
	d.Consensus.Parameters.SkipTimeoutCommit = true
	require.NoError(d.SanityCheck(), "too small timeout commit should be allowed if it's skipped")

	// Test beacon genesis checks.
	d = testDoc()
	d.Beacon.Base = beacon.EpochInvalid
	require.Error(d.SanityCheck(), "invalid base epoch should be rejected")

	d = testDoc()
	d.Beacon.Parameters.DebugMockBackend = false
	d.Beacon.Parameters.InsecureParameters = &beacon.InsecureParameters{
		Interval: 0,
	}
	require.Error(d.SanityCheck(), "invalid epoch interval should be rejected")

	// Test keymanager genesis checks.
	d = testDoc()
	d.KeyManager = keymanager.Genesis{
		Statuses: []*keymanager.Status{
			{
				ID: testRuntimeID,
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid keymanager runtime should be rejected")

	d = testDoc()
	d.KeyManager = keymanager.Genesis{
		Statuses: []*keymanager.Status{
			{
				ID:    validNS,
				Nodes: []signature.PublicKey{invalidPK},
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid keymanager node should be rejected")

	// Test roothash genesis checks.
	// First we define a helper function for calling the SanityCheck() on RuntimeStates.
	rtsSanityCheck := func(g roothash.Genesis, isGenesis bool) error {
		for _, rts := range g.RuntimeStates {
			if err := rts.SanityCheck(isGenesis); err != nil {
				return err
			}
		}
		return nil
	}

	d = testDoc()
	d.RootHash.RuntimeStates = make(map[common.Namespace]*roothash.GenesisRuntimeState)
	d.RootHash.RuntimeStates[validNS] = &roothash.GenesisRuntimeState{
		RuntimeGenesis: registry.RuntimeGenesis{
			StateRoot: emptyHash,
			Round:     0,
		},
	}
	require.NoError(rtsSanityCheck(d.RootHash, false), "empty StateRoot should pass")
	require.NoError(rtsSanityCheck(d.RootHash, true), "empty StateRoot should pass")

	d = testDoc()
	d.RootHash.RuntimeStates = make(map[common.Namespace]*roothash.GenesisRuntimeState)
	d.RootHash.RuntimeStates[validNS] = &roothash.GenesisRuntimeState{
		RuntimeGenesis: registry.RuntimeGenesis{
			StateRoot: nonEmptyHash,
			Round:     0,
		},
	}
	require.NoError(rtsSanityCheck(d.RootHash, false), "non-empty StateRoot should pass")
	require.NoError(rtsSanityCheck(d.RootHash, true), "non-empty StateRoot should pass")

	// Test registry genesis checks.
	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	require.NoError(d.SanityCheck(), "test entity should pass")

	d = testDoc()
	te := *testEntity
	te.ID = invalidPK
	signedBrokenEntity := signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedBrokenEntity}
	require.Error(d.SanityCheck(), "invalid test entity ID should be rejected")

	d = testDoc()
	te = *testEntity
	te.Nodes = []signature.PublicKey{invalidPK}
	signedBrokenEntity = signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedBrokenEntity}
	require.Error(d.SanityCheck(), "test entity's invalid node public key should be rejected")

	d = testDoc()
	te = *testEntity
	signedBrokenEntity, err := entity.SignEntity(signer, signature.NewContext("genesis sanity check invalid ctx"), &te)
	if err != nil {
		panic(err)
	}
	d.Registry.Entities = []*entity.SignedEntity{signedBrokenEntity}
	require.Error(d.SanityCheck(), "test entity with invalid signing context should be rejected")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	require.NoError(d.SanityCheck(), "test keymanager runtime should pass")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.NoError(d.SanityCheck(), "test runtimes should pass")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testRuntime, testKMRuntime}
	require.NoError(d.SanityCheck(), "test runtimes in reverse order should pass")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testRuntime}
	require.Error(d.SanityCheck(), "test runtime with missing keymanager runtime should be rejected")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime, testRuntime}
	require.Error(d.SanityCheck(), "duplicate runtime IDs should be rejected")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	testRuntime.GovernanceModel = registry.GovernanceRuntime
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.NoError(d.SanityCheck(), "runtime with runtime gov model should pass")

	d = testDoc()
	delete(d.Registry.Parameters.EnableRuntimeGovernanceModels, registry.GovernanceRuntime)
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.Error(d.SanityCheck(), "runtime with runtime gov model should be rejected")

	testRuntime.GovernanceModel = registry.GovernanceEntity

	d = testDoc()
	delete(d.Registry.Parameters.EnableRuntimeGovernanceModels, registry.GovernanceEntity)
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.Error(d.SanityCheck(), "runtime with entity gov model should be rejected")

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	testRuntime.GovernanceModel = registry.GovernanceConsensus
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.NoError(d.SanityCheck(), "runtime with consensus gov model should pass")

	d = testDoc()
	d.Registry.Parameters.EnableRuntimeGovernanceModels[registry.GovernanceConsensus] = false
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.Error(d.SanityCheck(), "runtime with consensus gov model should be rejected (1)")

	d = testDoc()
	delete(d.Registry.Parameters.EnableRuntimeGovernanceModels, registry.GovernanceConsensus)
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.Error(d.SanityCheck(), "runtime with consensus gov model should be rejected (2)")

	testRuntime.GovernanceModel = registry.GovernanceEntity

	d = testDoc()
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	testKMRuntime.GovernanceModel = registry.GovernanceRuntime
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	require.Error(d.SanityCheck(), "non-compute runtime with runtime gov model should be rejected")
	testKMRuntime.GovernanceModel = registry.GovernanceEntity

	// TODO: fiddle with executor/merge/txnsched parameters.

	d = testDoc()
	te = *testEntity
	te.Nodes = []signature.PublicKey{testNode.ID}
	signedEntityWithTestNode := signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{}
	d.Registry.Nodes = []*node.MultiSignedNode{signedTestNode}
	require.NoError(d.SanityCheck(), "entity with node should pass")

	d = testDoc()
	te = *testEntity
	te.Nodes = []signature.PublicKey{unknownPK}
	signedEntityWithBrokenNode := signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithBrokenNode}
	d.Registry.Runtimes = []*registry.Runtime{}
	d.Registry.Nodes = []*node.MultiSignedNode{signedTestNode}
	require.Error(d.SanityCheck(), "node not listed among controlling entity's nodes should be rejected")

	d = testDoc()
	tn := *testNode
	tn.EntityID = unknownPK
	signedBrokenTestNode := signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with unknown entity ID should be rejected")

	d = testDoc()
	tn = *testNode
	signedBrokenTestNode, err = node.MultiSignNode(
		[]signature.Signer{
			signer,
		},
		signature.NewContext("genesis sanity check test invalid node ctx"),
		&tn,
	)
	if err != nil {
		panic(err)
	}
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with wrong signing context should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = 1<<16 | 1<<17
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with any reserved role bits set should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = 0
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node without any role bits set should be rejected")

	d = testDoc()
	tn = *testNode
	tn.TLS.PubKey = signature.PublicKey{}
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with invalid TLS public key should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Consensus.ID = invalidPK
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with invalid consensus ID should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleComputeWorker
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "compute node without runtimes should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "keymanager node without runtimes should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	tn.Runtimes = []*node.Runtime{
		{
			ID: testKMRuntime.ID,
		},
	}
	signedKMTestNode := signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedKMTestNode}
	require.NoError(d.SanityCheck(), "keymanager node with valid runtime should pass")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	tn.Runtimes = []*node.Runtime{
		{
			ID: testRuntime.ID,
		},
	}
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "keymanager node with invalid runtime should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	tn.Runtimes = []*node.Runtime{
		{
			ID: testRuntime.ID,
		},
	}
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "keymanager node with non-KM runtime should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleComputeWorker
	tn.Runtimes = []*node.Runtime{
		{
			ID: testKMRuntime.ID,
		},
	}
	signedBrokenTestNode = signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "compute node with non-compute runtime should be rejected")

	d = testDoc()
	tn = *testNode
	tn.Roles = node.RoleComputeWorker
	tn.Runtimes = []*node.Runtime{
		{
			ID: testRuntime.ID,
		},
	}
	signedComputeTestNode := signNodeOrDie(nodeSigners, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.Runtime{testKMRuntime, testRuntime}
	d.Registry.Nodes = []*node.MultiSignedNode{signedComputeTestNode}
	require.NoError(d.SanityCheck(), "compute node with compute runtime should pass")

	// Test staking genesis checks.

	testAcc1Address := stakingTests.Accounts.GetAddress(1)
	testAcc2Address := stakingTests.Accounts.GetAddress(2)

	d = testDoc()
	d.Staking.TokenSymbol = ""
	require.EqualError(
		d.SanityCheck(),
		"staking: sanity check failed: token symbol is empty",
		"empty token symbol should be rejected",
	)

	d = testDoc()
	d.Staking.TokenSymbol = "foo"
	require.EqualError(
		d.SanityCheck(),
		fmt.Sprintf("staking: sanity check failed: token symbol should match '%s'", token.TokenSymbolRegexp),
		"lower case token symbol should be rejected",
	)

	d = testDoc()
	d.Staking.TokenSymbol = "LONGSYMBOL"
	require.EqualError(
		d.SanityCheck(),
		"staking: sanity check failed: token symbol exceeds maximum length",
		"too long token symbol should be rejected",
	)

	d = testDoc()
	d.Staking.TokenValueExponent = 21
	require.EqualError(
		d.SanityCheck(),
		"staking: sanity check failed: token value exponent is invalid",
		"too large token value exponent should be rejected",
	)

	// NOTE: There doesn't seem to be a way to generate invalid Quantities, so
	// we're just going to test the code that checks if things add up.
	d = testDoc()
	d.Staking.TotalSupply = *quantity.NewFromUint64(100)
	require.Error(d.SanityCheck(), "invalid total supply should be rejected")

	d = testDoc()
	d.Staking.CommonPool = *quantity.NewFromUint64(100)
	require.Error(d.SanityCheck(), "invalid common pool should be rejected")

	d = testDoc()
	d.Staking.LastBlockFees = *quantity.NewFromUint64(100)
	require.Error(d.SanityCheck(), "invalid last block fees should be rejected")

	d = testDoc()
	d.Staking.Ledger[testAcc1Address].General.Balance = *quantity.NewFromUint64(100)
	require.Error(d.SanityCheck(), "invalid general balance should be rejected")

	d = testDoc()
	d.Staking.Ledger[testAcc1Address].Escrow.Active.Balance = *quantity.NewFromUint64(42)
	require.Error(d.SanityCheck(), "invalid escrow active balance should be rejected")

	d = testDoc()
	d.Staking.Ledger[testAcc1Address].Escrow.Debonding.Balance = *quantity.NewFromUint64(100)
	require.Error(d.SanityCheck(), "invalid escrow debonding balance should be rejected")

	d = testDoc()
	d.Staking.Ledger[testAcc1Address].Escrow.Active.TotalShares = *quantity.NewFromUint64(1)
	require.Error(d.SanityCheck(), "invalid escrow active total shares should be rejected")

	d = testDoc()
	d.Staking.Ledger[testAcc1Address].Escrow.Debonding.TotalShares = *quantity.NewFromUint64(1)
	require.Error(d.SanityCheck(), "invalid escrow debonding total shares should be rejected")

	d = testDoc()
	d.Staking.Delegations = map[staking.Address]map[staking.Address]*staking.Delegation{
		testAcc1Address: {
			testAcc2Address: {
				Shares: *quantity.NewFromUint64(1),
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid delegation should be rejected")

	d = testDoc()
	d.Staking.DebondingDelegations = map[staking.Address]map[staking.Address][]*staking.DebondingDelegation{
		testAcc1Address: {
			testAcc2Address: {
				{
					Shares:        *quantity.NewFromUint64(1),
					DebondEndTime: 10,
				},
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid debonding delegation should be rejected")

	// Test governance sanity checks.
	d = testDoc()
	d.Governance.Parameters.StakeThreshold = 1
	require.Error(d.SanityCheck(), "stake threshold too low should be rejected")

	d = testDoc()
	d.Governance.Parameters.StakeThreshold = 110
	require.Error(d.SanityCheck(), "threshold too high should be rejected")

	d = testDoc()
	d.Governance.Parameters.UpgradeCancelMinEpochDiff = 50
	require.Error(d.SanityCheck(), "upgrade_cancel_min_epoch_diff < voting_period should be rejected")

	d = testDoc()
	d.Governance.Parameters.UpgradeMinEpochDiff = 50
	require.Error(d.SanityCheck(), "upgrade_min_epoch_diff < voting_period should be rejected")

	validTestProposals := func() []*governance.Proposal {
		return []*governance.Proposal{
			{
				CreatedAt: 1,
				ClosesAt:  100,
				Submitter: testAcc2Address,
				Content: governance.ProposalContent{
					Upgrade: &governance.UpgradeProposal{
						Descriptor: upgrade.Descriptor{
							Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
							Handler:   "genesis_tests",
							Target:    version.Versions,
							Epoch:     500,
						},
					},
				},
				State: governance.StateActive,
				ID:    1,
			},
		}
	}
	d = testDoc()
	d.Beacon.Base = 10
	d.Beacon.Parameters.DebugMockBackend = false
	d.Beacon.Parameters.InsecureParameters = &beacon.InsecureParameters{
		Interval: 100,
	}
	d.Governance.Proposals = validTestProposals()
	require.NoError(d.SanityCheck(), "valid proposal should pass")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].Deposit = *quantity.NewFromUint64(100)
	require.Error(d.SanityCheck(), "proposal deposit doesn't match governance deposits")
	d.Staking.GovernanceDeposits = *quantity.NewFromUint64(100)
	totalSupply := d.Staking.TotalSupply.Clone()
	require.NoError(totalSupply.Add(&d.Staking.GovernanceDeposits), "totalSupply.Add(GovernanceDeposits)")
	d.Staking.TotalSupply = *totalSupply
	require.NoError(d.SanityCheck(), "proposal deposit matches governance deposits")

	d = testDoc()
	d.Beacon.Base = 10
	d.Beacon.Parameters.DebugMockBackend = false
	d.Beacon.Parameters.InsecureParameters = &beacon.InsecureParameters{
		Interval: 100,
	}
	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].CreatedAt = 15
	require.Error(d.SanityCheck(), "proposal created in future")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].Submitter = staking.CommonPoolAddress
	require.Error(d.SanityCheck(), "proposal submitter reserved address")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].Content.Upgrade = nil
	require.Error(d.SanityCheck(), "proposal invalid content")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].Content.Upgrade.Target = version.ProtocolVersions{}
	require.Error(d.SanityCheck(), "proposal upgrade invalid target")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].ClosesAt = 5
	require.Error(d.SanityCheck(), "active proposal with past closing epoch")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].Content.Upgrade.Epoch = 2
	require.Error(d.SanityCheck(), "active proposal upgrade with past upgrade epoch")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].Results = map[governance.Vote]quantity.Quantity{governance.VoteYes: *quantity.NewFromUint64(1)}
	require.Error(d.SanityCheck(), "active proposal with non-empty results")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].InvalidVotes = 5
	require.Error(d.SanityCheck(), "active proposal with non-empty invalid results")

	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals[0].State = governance.StateRejected
	require.Error(d.SanityCheck(), "closed proposal with closing epoch in future")

	d.Governance.Proposals = validTestProposals()
	d.Governance.VoteEntries = map[uint64][]*governance.VoteEntry{
		d.Governance.Proposals[0].ID: {
			{
				Voter: testAcc1Address,
				Vote:  governance.VoteYes,
			},
		},
	}
	require.NoError(d.SanityCheck(), "valid vote should pass sanity check")

	d.Governance.Proposals = validTestProposals()
	d.Governance.VoteEntries = map[uint64][]*governance.VoteEntry{
		d.Governance.Proposals[0].ID: {
			{
				Voter: staking.CommonPoolAddress,
				Vote:  governance.VoteYes,
			},
		},
	}
	require.Error(d.SanityCheck(), "vote from a reserved address")
	d.Governance.VoteEntries = nil

	descriptor := func(epoch beacon.EpochTime) upgrade.Descriptor {
		return upgrade.Descriptor{
			Versioned: cbor.NewVersioned(upgrade.LatestDescriptorVersion),
			Handler:   "handler_tests",
			Target:    version.Versions,
			Epoch:     epoch,
		}
	}
	d.Governance.Proposals = validTestProposals()
	d.Governance.Proposals = []*governance.Proposal{
		{
			CreatedAt: 1,
			ClosesAt:  2,
			Submitter: testAcc2Address,
			Content: governance.ProposalContent{
				Upgrade: &governance.UpgradeProposal{
					Descriptor: descriptor(400),
				},
			},
			State: governance.StatePassed,
			ID:    1,
		},
	}
	require.NoError(d.SanityCheck(), "valid closed proposal")

	d.Governance.Proposals = append(d.Governance.Proposals, &governance.Proposal{
		CreatedAt: 1,
		ClosesAt:  2,
		Submitter: testAcc2Address,
		Content: governance.ProposalContent{
			Upgrade: &governance.UpgradeProposal{
				Descriptor: descriptor(710),
			},
		},
		State: governance.StatePassed,
		ID:    2,
	})
	require.NoError(d.SanityCheck(), "valid closed proposal")

	d.Governance.Proposals = append(d.Governance.Proposals, &governance.Proposal{
		CreatedAt: 1,
		ClosesAt:  2,
		Submitter: testAcc2Address,
		Content: governance.ProposalContent{
			Upgrade: &governance.UpgradeProposal{
				Descriptor: descriptor(410),
			},
		},
		State: governance.StatePassed,
		ID:    3,
	})
	require.Error(d.SanityCheck(), "pending upgrades not UpgradeMinEpochDiff apart")
}
