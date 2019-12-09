package api

import (
	"math"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/crypto/tls"
	"github.com/oasislabs/oasis-core/go/common/entity"
	"github.com/oasislabs/oasis-core/go/common/node"
	consensus "github.com/oasislabs/oasis-core/go/consensus/genesis"
	tendermint "github.com/oasislabs/oasis-core/go/consensus/tendermint/api"
	epochtime "github.com/oasislabs/oasis-core/go/epochtime/api"
	genesisTests "github.com/oasislabs/oasis-core/go/genesis/tests"
	keymanager "github.com/oasislabs/oasis-core/go/keymanager/api"
	cmdFlags "github.com/oasislabs/oasis-core/go/oasis-node/cmd/common/flags"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	staking "github.com/oasislabs/oasis-core/go/staking/api"
	stakingTests "github.com/oasislabs/oasis-core/go/staking/tests/debug"
)

var testDoc = &Document{
	ChainID:   genesisTests.TestChainID,
	Time:      time.Unix(1574858284, 0),
	HaltEpoch: epochtime.EpochTime(math.MaxUint64),
	EpochTime: epochtime.Genesis{
		Parameters: epochtime.ConsensusParameters{
			DebugMockBackend: true,
		},
	},
	Registry: registry.Genesis{
		Parameters: registry.ConsensusParameters{
			DebugAllowUnroutableAddresses: true,
			DebugAllowRuntimeRegistration: true,
			DebugBypassStake:              true,
		},
	},
	Scheduler: scheduler.Genesis{
		Parameters: scheduler.ConsensusParameters{
			MinValidators:          1,
			MaxValidators:          100,
			MaxValidatorsPerEntity: 100,
			DebugBypassStake:       true,
			DebugStaticValidators:  true,
		},
	},
	Consensus: consensus.Genesis{
		Backend: tendermint.BackendName,
		Parameters: consensus.Parameters{
			TimeoutCommit:     1 * time.Millisecond,
			SkipTimeoutCommit: true,
		},
	},
	Staking: stakingTests.DebugGenesisState,
}

func signEntityOrDie(signer signature.Signer, e *entity.Entity) *entity.SignedEntity {
	signedEntity, err := entity.SignEntity(signer, registry.RegisterGenesisEntitySignatureContext, e)
	if err != nil {
		panic(err)
	}
	return signedEntity
}

func signRuntimeOrDie(signer signature.Signer, rt *registry.Runtime) *registry.SignedRuntime {
	signedRuntime, err := registry.SignRuntime(signer, registry.RegisterGenesisRuntimeSignatureContext, rt)
	if err != nil {
		panic(err)
	}
	return signedRuntime
}

func signNodeOrDie(signer signature.Signer, n *node.Node) *node.SignedNode {
	signedNode, err := node.SignNode(signer, registry.RegisterGenesisNodeSignatureContext, n)
	if err != nil {
		panic(err)
	}
	return signedNode
}

func hex2pk(hex string) signature.PublicKey {
	var pk signature.PublicKey
	if err := pk.UnmarshalHex(hex); err != nil {
		panic(err)
	}
	return pk
}

func TestGenesisChainContext(t *testing.T) {
	// Ensure that the chain context is stable.
	stableDoc := *testDoc
	// NOTE: Staking part is not stable as it generates a new public key
	//       on each run.
	stableDoc.Staking = staking.Genesis{}

	require.Equal(t, "daba5eed9f82d37c76384f9f185dc0bfff60eb57a33b7d8955e265244e0a0a51", stableDoc.ChainContext())
}

func TestGenesisSanityCheck(t *testing.T) {
	viper.Set(cmdFlags.CfgDebugDontBlameOasis, true)
	require := require.New(t)

	// First, set up a few things we'll need in the tests below.
	signer := memorySigner.NewTestSigner("genesis sanity checks signer")
	validPK := signer.Public()

	invalidPK := hex2pk("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a")

	signature.BuildPublicKeyBlacklist(true)

	var emptyHash hash.Hash
	emptyHash.Empty()

	// Note that this test entity has no nodes by design, those will be added
	// later by various tests.
	testEntity := &entity.Entity{
		ID:                     validPK,
		AllowEntitySignedNodes: true,
	}
	signedTestEntity := signEntityOrDie(signer, testEntity)

	kmRuntimeID := hex2pk("0000000000000000000000000000000000000000000000000000000000000000")
	testKMRuntime := &registry.Runtime{
		ID:   kmRuntimeID,
		Kind: registry.KindKeyManager,
	}
	signedTestKMRuntime := signRuntimeOrDie(signer, testKMRuntime)

	testRuntimeID := hex2pk("0000000000000000000000000000000000000000000000000000000000000001")
	testRuntime := &registry.Runtime{
		ID:            testRuntimeID,
		Kind:          registry.KindCompute,
		KeyManagerOpt: &testKMRuntime.ID,
		Compute: registry.ComputeParameters{
			GroupSize:    1,
			RoundTimeout: 1 * time.Second,
		},
		Merge: registry.MergeParameters{
			GroupSize:    1,
			RoundTimeout: 1 * time.Second,
		},
		TxnScheduler: registry.TxnSchedulerParameters{
			Algorithm:         "batching",
			BatchFlushTimeout: 1 * time.Second,
			MaxBatchSize:      1,
			MaxBatchSizeBytes: 1,
		},
	}
	signedTestRuntime := signRuntimeOrDie(signer, testRuntime)

	testNodeID := hex2pk("0000000000000000000000000000000000000000000000000000000000000010")
	dummyCert, err := tls.Generate("genesis sanity check dummy cert")
	if err != nil {
		panic(err)
	}
	testNode := &node.Node{
		ID:         testNodeID,
		EntityID:   testEntity.ID,
		Expiration: 10,
		Committee: node.CommitteeInfo{
			Certificate: dummyCert.Certificate[0],
		},
		Consensus: node.ConsensusInfo{
			ID: testNodeID,
		},
	}
	signedTestNode := signNodeOrDie(signer, testNode)

	// Test genesis document should pass sanity check.
	require.NoError(testDoc.SanityCheck(), "test genesis document should be valid")

	// Test top-level genesis checks.
	d := *testDoc
	d.Height = -123
	require.Error(d.SanityCheck(), "height < 0 should be invalid")

	d = *testDoc
	d.Time = time.Now().Add(time.Minute * 2)
	require.Error(d.SanityCheck(), "future time of genesis doc should be invalid")

	d = *testDoc
	d.ChainID = "   \t"
	require.Error(d.SanityCheck(), "empty chain ID should be invalid")

	d = *testDoc
	d.EpochTime.Base = 10
	d.HaltEpoch = 5
	require.Error(d.SanityCheck(), "halt epoch in the past should be invalid")

	// Test consensus genesis checks.
	d = *testDoc
	d.Consensus.Backend = "asdf"
	require.Error(d.SanityCheck(), "invalid consensus backend should be rejected")

	d = *testDoc
	d.Consensus.Parameters.TimeoutCommit = 0
	d.Consensus.Parameters.SkipTimeoutCommit = false
	require.Error(d.SanityCheck(), "too small timeout commit should be invalid")

	d = *testDoc
	d.Consensus.Parameters.TimeoutCommit = 0
	d.Consensus.Parameters.SkipTimeoutCommit = true
	require.NoError(d.SanityCheck(), "too small timeout commit should be allowed if it's skipped")

	// Test epochtime genesis checks.
	d = *testDoc
	d.EpochTime.Base = epochtime.EpochInvalid
	require.Error(d.SanityCheck(), "invalid base epoch should be rejected")

	d = *testDoc
	d.EpochTime.Parameters.Interval = 0
	d.EpochTime.Parameters.DebugMockBackend = false
	require.Error(d.SanityCheck(), "invalid epoch interval should be rejected")

	// Test keymanager genesis checks.
	d = *testDoc
	d.KeyManager = keymanager.Genesis{
		Statuses: []*keymanager.Status{
			{
				ID: invalidPK,
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid keymanager ID should be rejected")

	// Test roothash genesis checks.
	d = *testDoc
	d.RootHash.Blocks = make(map[signature.PublicKey]*block.Block)
	d.RootHash.Blocks[validPK] = &block.Block{
		Header: block.Header{
			HeaderType: 123,
		},
	}
	require.Error(d.SanityCheck(), "invalid block header should be rejected")

	d = *testDoc
	d.RootHash.Blocks = make(map[signature.PublicKey]*block.Block)
	d.RootHash.Blocks[validPK] = &block.Block{
		Header: block.Header{
			HeaderType:   block.Normal,
			PreviousHash: hash.Hash{},
		},
	}
	require.Error(d.SanityCheck(), "invalid previous hash should be rejected")

	d = *testDoc
	d.RootHash.Blocks = make(map[signature.PublicKey]*block.Block)
	d.RootHash.Blocks[validPK] = &block.Block{
		Header: block.Header{
			HeaderType:   block.Normal,
			PreviousHash: emptyHash,
			Timestamp:    uint64(time.Now().Unix() + 62*60),
		},
	}
	require.Error(d.SanityCheck(), "invalid timestamp should be rejected")

	d = *testDoc
	sigCtx := signature.NewContext("genesis sanity check storage sig test")
	sig, grr := signature.Sign(signer, sigCtx, []byte{1, 2, 3})
	require.NoError(grr, "should be able to sign")
	d.RootHash.Blocks = make(map[signature.PublicKey]*block.Block)
	d.RootHash.Blocks[validPK] = &block.Block{
		Header: block.Header{
			HeaderType:        block.Normal,
			PreviousHash:      emptyHash,
			Timestamp:         uint64(time.Now().Unix()),
			StorageSignatures: []signature.Signature{*sig},
		},
	}
	require.Error(d.SanityCheck(), "non-empty storage signature array should be rejected")

	d = *testDoc
	d.RootHash.Blocks = make(map[signature.PublicKey]*block.Block)
	d.RootHash.Blocks[validPK] = &block.Block{
		Header: block.Header{
			HeaderType:        block.Normal,
			PreviousHash:      emptyHash,
			Timestamp:         uint64(time.Now().Unix()),
			StorageSignatures: []signature.Signature{},
			RoothashMessages:  []*block.RoothashMessage{nil, nil, nil},
		},
	}
	require.Error(d.SanityCheck(), "non-empty roothash message array should be rejected")

	d = *testDoc
	d.RootHash.Blocks = make(map[signature.PublicKey]*block.Block)
	d.RootHash.Blocks[validPK] = &block.Block{
		Header: block.Header{
			HeaderType:   block.Normal,
			PreviousHash: emptyHash,
			Timestamp:    uint64(time.Now().Unix()),
		},
	}
	require.NoError(d.SanityCheck(), "well-formed block should pass")

	// Test registry genesis checks.
	d = *testDoc
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	require.NoError(d.SanityCheck(), "test entity should pass")

	d = *testDoc
	te := *testEntity
	te.ID = invalidPK
	signedBrokenEntity := signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedBrokenEntity}
	require.Error(d.SanityCheck(), "invalid test entity ID should be rejected")

	d = *testDoc
	te = *testEntity
	te.Nodes = []signature.PublicKey{invalidPK}
	signedBrokenEntity = signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedBrokenEntity}
	require.Error(d.SanityCheck(), "test entity's invalid node public key should be rejected")

	d = *testDoc
	te = *testEntity
	signedBrokenEntity, err = entity.SignEntity(signer, signature.NewContext("genesis sanity check invalid ctx"), &te)
	if err != nil {
		panic(err)
	}
	d.Registry.Entities = []*entity.SignedEntity{signedBrokenEntity}
	require.Error(d.SanityCheck(), "test entity with invalid signing context should be rejected")

	d = *testDoc
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	require.NoError(d.SanityCheck(), "test keymanager runtime should pass")

	d = *testDoc
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime, signedTestRuntime}
	require.NoError(d.SanityCheck(), "test runtimes should pass")

	d = *testDoc
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestRuntime, signedTestKMRuntime}
	require.NoError(d.SanityCheck(), "test runtimes in reverse order should pass")

	d = *testDoc
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestRuntime}
	require.Error(d.SanityCheck(), "test runtime with missing keymanager runtime should be rejected")

	d = *testDoc
	d.Registry.Entities = []*entity.SignedEntity{signedTestEntity}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime, signedTestRuntime, signedTestRuntime}
	require.Error(d.SanityCheck(), "duplicate runtime IDs should be rejected")

	// TODO: fiddle with compute/merge/txnsched parameters.

	d = *testDoc
	te = *testEntity
	te.Nodes = []signature.PublicKey{testNode.ID}
	signedEntityWithTestNode := signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{}
	d.Registry.Nodes = []*node.SignedNode{signedTestNode}
	require.NoError(d.SanityCheck(), "entity with node should pass")

	d = *testDoc
	te = *testEntity
	te.Nodes = []signature.PublicKey{testRuntime.ID}
	te.AllowEntitySignedNodes = false
	signedEntityWithBrokenNode := signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithBrokenNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{}
	d.Registry.Nodes = []*node.SignedNode{signedTestNode}
	require.Error(d.SanityCheck(), "node not listed among controlling entity's nodes should be rejected if the entity doesn't allow entity-signed nodes")

	d = *testDoc
	te = *testEntity
	te.Nodes = []signature.PublicKey{testRuntime.ID}
	te.AllowEntitySignedNodes = true
	signedEntityWithBrokenNode = signEntityOrDie(signer, &te)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithBrokenNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{}
	d.Registry.Nodes = []*node.SignedNode{signedTestNode}
	require.NoError(d.SanityCheck(), "node not listed among controlling entity's nodes should still be accepted if the entity allows entity-signed nodes")

	d = *testDoc
	tn := *testNode
	tn.EntityID = testRuntime.ID
	signedBrokenTestNode := signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with unknown entity ID should be rejected")

	d = *testDoc
	tn = *testNode
	signedBrokenTestNode, err = node.SignNode(signer, signature.NewContext("genesis sanity check test invalid node ctx"), &tn)
	if err != nil {
		panic(err)
	}
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with wrong signing context should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = 1<<16 | 1<<17
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with any reserved role bits set should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Committee.Certificate = []byte{1, 2, 3}
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with invalid committee certificate should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Consensus.ID = invalidPK
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "node with invalid consensus ID should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleComputeWorker
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "compute node without runtimes should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "keymanager node without runtimes should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	tn.Runtimes = []*node.Runtime{
		&node.Runtime{
			ID: testKMRuntime.ID,
		},
	}
	signedKMTestNode := signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedKMTestNode}
	require.NoError(d.SanityCheck(), "keymanager node with valid runtime should pass")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	tn.Runtimes = []*node.Runtime{
		&node.Runtime{
			ID: testRuntime.ID,
		},
	}
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "keymanager node with invalid runtime should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleKeyManager
	tn.Runtimes = []*node.Runtime{
		&node.Runtime{
			ID: testRuntime.ID,
		},
	}
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime, signedTestRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "keymanager node with non-KM runtime should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleComputeWorker
	tn.Runtimes = []*node.Runtime{
		&node.Runtime{
			ID: testKMRuntime.ID,
		},
	}
	signedBrokenTestNode = signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime, signedTestRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedBrokenTestNode}
	require.Error(d.SanityCheck(), "compute node with non-compute runtime should be rejected")

	d = *testDoc
	tn = *testNode
	tn.Roles = node.RoleComputeWorker
	tn.Runtimes = []*node.Runtime{
		&node.Runtime{
			ID: testRuntime.ID,
		},
	}
	signedComputeTestNode := signNodeOrDie(signer, &tn)
	d.Registry.Entities = []*entity.SignedEntity{signedEntityWithTestNode}
	d.Registry.Runtimes = []*registry.SignedRuntime{signedTestKMRuntime, signedTestRuntime}
	d.Registry.Nodes = []*node.SignedNode{signedComputeTestNode}
	require.NoError(d.SanityCheck(), "compute node with compute runtime should pass")

	// Test staking genesis checks.
	// NOTE: There doesn't seem to be a way to generate invalid Quantities, so
	// we're just going to test the code that checks if things add up.
	d = *testDoc
	d.Staking.TotalSupply = stakingTests.QtyFromInt(100)
	require.Error(d.SanityCheck(), "invalid total supply should be rejected")

	d = *testDoc
	d.Staking.CommonPool = stakingTests.QtyFromInt(100)
	require.Error(d.SanityCheck(), "invalid common pool should be rejected")

	d = *testDoc
	d.Staking.Ledger[stakingTests.DebugStateSrcID].General.Balance = stakingTests.QtyFromInt(100)
	require.Error(d.SanityCheck(), "invalid general balance should be rejected")

	d = *testDoc
	d.Staking.Ledger[stakingTests.DebugStateSrcID].Escrow.Active.Balance = stakingTests.QtyFromInt(100)
	require.Error(d.SanityCheck(), "invalid escrow active balance should be rejected")

	d = *testDoc
	d.Staking.Ledger[stakingTests.DebugStateSrcID].Escrow.Debonding.Balance = stakingTests.QtyFromInt(100)
	require.Error(d.SanityCheck(), "invalid escrow debonding balance should be rejected")

	d = *testDoc
	d.Staking.Ledger[stakingTests.DebugStateSrcID].Escrow.Active.TotalShares = stakingTests.QtyFromInt(1)
	require.Error(d.SanityCheck(), "invalid escrow active total shares should be rejected")

	d = *testDoc
	d.Staking.Ledger[stakingTests.DebugStateSrcID].Escrow.Debonding.TotalShares = stakingTests.QtyFromInt(1)
	require.Error(d.SanityCheck(), "invalid escrow debonding total shares should be rejected")

	d = *testDoc
	d.Staking.Delegations = map[signature.PublicKey]map[signature.PublicKey]*staking.Delegation{
		stakingTests.DebugStateSrcID: map[signature.PublicKey]*staking.Delegation{
			stakingTests.DebugStateDestID: &staking.Delegation{
				Shares: stakingTests.QtyFromInt(1),
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid delegation should be rejected")

	d = *testDoc
	d.Staking.DebondingDelegations = map[signature.PublicKey]map[signature.PublicKey][]*staking.DebondingDelegation{
		stakingTests.DebugStateSrcID: map[signature.PublicKey][]*staking.DebondingDelegation{
			stakingTests.DebugStateDestID: []*staking.DebondingDelegation{
				&staking.DebondingDelegation{
					Shares:        stakingTests.QtyFromInt(1),
					DebondEndTime: 10,
				},
			},
		},
	}
	require.Error(d.SanityCheck(), "invalid debonding delegation should be rejected")
}
