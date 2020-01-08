package commitment

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/oasis-core/go/common/node"
	genesisTestHelpers "github.com/oasislabs/oasis-core/go/genesis/tests/helpers"
	registry "github.com/oasislabs/oasis-core/go/registry/api"
	"github.com/oasislabs/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasislabs/oasis-core/go/scheduler/api"
	storage "github.com/oasislabs/oasis-core/go/storage/api"
)

var nopSV = &nopSignatureVerifier{}

// nopSignatureVerifier is a no-op storage verifier.
type nopSignatureVerifier struct{}

func (n *nopSignatureVerifier) VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error {
	return nil
}

type staticSignatureVerifier struct {
	storagePublicKey      signature.PublicKey
	txnSchedulerPublicKey signature.PublicKey
}

func (n *staticSignatureVerifier) VerifyCommitteeSignatures(kind scheduler.CommitteeKind, sigs []signature.Signature) error {
	var pk signature.PublicKey
	switch kind {
	case scheduler.KindStorage:
		pk = n.storagePublicKey
	case scheduler.KindTransactionScheduler:
		pk = n.txnSchedulerPublicKey
	default:
		return errors.New("unsupported committee kind")
	}

	for _, sig := range sigs {
		if !sig.PublicKey.Equal(pk) {
			return errors.New("unknown public key")
		}
	}
	return nil
}

func TestPoolDefault(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a commitment.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	var id common.Namespace
	blk := block.NewGenesisBlock(id, 0)

	body := ComputeBody{
		Header: ComputeResultsHeader{
			PreviousHash: blk.Header.PreviousHash,
			IORoot:       blk.Header.IORoot,
			StateRoot:    blk.Header.StateRoot,
		},
	}
	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// An empty pool should work but should always error.
	pool := Pool{}
	err = pool.AddExecutorCommitment(blk, nopSV, commit)
	require.Error(t, err, "AddExecutorCommitment")
	err = pool.CheckEnoughCommitments(false)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrNoCommittee, err)
	_, err = pool.DetectDiscrepancy()
	require.Error(t, err, "DetectDiscrepancy")
	require.Equal(t, ErrNoCommittee, err)
	_, err = pool.ResolveDiscrepancy()
	require.Error(t, err, "ResolveDiscrepancy")
	require.Equal(t, ErrNoCommittee, err)
}

func TestPoolSingleCommitment(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a non-TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	cID := sk.Public()
	committee := &scheduler.Committee{
		Kind: scheduler.KindExecutor,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}
	nodeInfo := map[signature.PublicKey]NodeInfo{
		cID: NodeInfo{
			CommitteeNode: 0,
			Runtime: &node.Runtime{
				ID: rtID,
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		NodeInfo:  nodeInfo,
	}

	// Generate a commitment.
	childBlk, parentBlk, body := generateComputeBody(t, committee)

	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	sv := &staticSignatureVerifier{
		storagePublicKey:      body.StorageSignatures[0].PublicKey,
		txnSchedulerPublicKey: body.TxnSchedSig.PublicKey,
	}

	// Adding a commitment not based on correct block should fail.
	err = pool.AddExecutorCommitment(parentBlk, sv, commit)
	require.Error(t, err, "AddExecutorCommitment")

	// There should not be enough executor commitments.
	err = pool.CheckEnoughCommitments(false)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
	err = pool.CheckEnoughCommitments(true)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

	// Adding a commitment having a storage receipt signed with an incorrect
	// public key should fail.
	bodyIncorrectStorageSig := body
	// This generates a new signing key so verification should fail.
	bodyIncorrectStorageSig.StorageSignatures[0] = generateStorageReceiptSignature(t, parentBlk, &bodyIncorrectStorageSig)
	incorrectCommit, err := SignExecutorCommitment(sk, &bodyIncorrectStorageSig)
	require.NoError(t, err, "SignExecutorCommitment")
	err = pool.AddExecutorCommitment(childBlk, sv, incorrectCommit)
	require.Error(t, err, "AddExecutorCommitment")

	// Adding a commitment having txn scheduler inputs signed with an incorrect
	// public key should fail.
	bodyIncorrectTxnSchedSig := body
	// This generates a new signing key so verification should fail.
	bodyIncorrectTxnSchedSig.TxnSchedSig = generateTxnSchedulerSignature(t, childBlk, &bodyIncorrectTxnSchedSig)
	incorrectCommit, err = SignExecutorCommitment(sk, &bodyIncorrectTxnSchedSig)
	require.NoError(t, err, "SignExecutorCommitment")
	err = pool.AddExecutorCommitment(childBlk, sv, incorrectCommit)
	require.Error(t, err, "AddExecutorCommitment")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(childBlk, sv, commit)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(childBlk, sv, commit)
	require.Error(t, err, "AddExecutorCommitment(duplicate)")

	// There should be enough executor commitments.
	err = pool.CheckEnoughCommitments(false)
	require.NoError(t, err, "CheckEnoughCommitments")

	// There should be no discrepancy.
	dc, err := pool.DetectDiscrepancy()
	require.NoError(t, err, "DetectDiscrepancy")
	require.Equal(t, false, pool.Discrepancy)
	header := dc.ToDDResult().(ComputeResultsHeader)
	require.EqualValues(t, &body.Header, &header, "DD should return the same header")
}

func TestPoolSingleCommitmentTEE(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareIntelSGX,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a dummy RAK.
	skRAK, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	cID := sk.Public()
	committee := &scheduler.Committee{
		Kind: scheduler.KindExecutor,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}
	nodeInfo := map[signature.PublicKey]NodeInfo{
		cID: NodeInfo{
			CommitteeNode: 0,
			Runtime: &node.Runtime{
				ID: rtID,
				Capabilities: node.Capabilities{
					TEE: &node.CapabilityTEE{
						Hardware:    node.TEEHardwareIntelSGX,
						RAK:         skRAK.Public(),
						Attestation: []byte("My RAK is my attestation. Verify me."),
					},
				},
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		NodeInfo:  nodeInfo,
	}

	// Generate a commitment.
	childBlk, parentBlk, body := generateComputeBody(t, committee)
	rakSig, err := signature.Sign(skRAK, ComputeResultsHeaderSignatureContext, cbor.Marshal(body.Header))
	require.NoError(t, err, "Sign")
	body.RakSig = rakSig.Signature

	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// Adding a commitment not based on correct block should fail.
	err = pool.AddExecutorCommitment(parentBlk, nopSV, commit)
	require.Error(t, err, "AddExecutorCommitment")

	// There should not be enough executor commitments.
	err = pool.CheckEnoughCommitments(false)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
	err = pool.CheckEnoughCommitments(true)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(childBlk, nopSV, commit)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(childBlk, nopSV, commit)
	require.Error(t, err, "AddExecutorCommitment(duplicate)")

	// There should be enough executor commitments.
	err = pool.CheckEnoughCommitments(false)
	require.NoError(t, err, "CheckEnoughCommitments")

	// There should be no discrepancy.
	dc, err := pool.DetectDiscrepancy()
	require.NoError(t, err, "DetectDiscrepancy")
	require.Equal(t, false, pool.Discrepancy)
	header := dc.ToDDResult().(ComputeResultsHeader)
	require.EqualValues(t, &body.Header, &header, "DD should return the same header")
}

func TestPoolTwoCommitments(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nodeInfo := generateMockCommittee(t)
	sk1 := sks[0]
	sk2 := sks[1]
	sk3 := sks[2]

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			NodeInfo:  nodeInfo,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, committee)

		bodyInvalidID := body
		bodyInvalidID.CommitteeID.FromBytes([]byte("invalid-committee-id"))

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Invalid committee.
		cInvalidCommit, err := SignExecutorCommitment(sk1, &bodyInvalidID)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding a commitment for an invalid committee should fail.
		err = pool.AddExecutorCommitment(childBlk, nopSV, cInvalidCommit)
		require.Error(t, err, "AddExecutorCommitment")
		require.Equal(t, ErrInvalidCommitteeID, err, "AddExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = pool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments.
		err = pool.CheckEnoughCommitments(false)
		require.NoError(t, err, "CheckEnoughCommitments")

		// There should be no discrepancy.
		dc, err := pool.DetectDiscrepancy()
		require.NoError(t, err, "DetectDiscrepancy")
		require.Equal(t, false, pool.Discrepancy)
		header := dc.ToDDResult().(ComputeResultsHeader)
		require.EqualValues(t, &body.Header, &header, "DD should return the same header")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			NodeInfo:  nodeInfo,
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t, committee)

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(sk3, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		correctHeader := body.Header

		// Update state root and fix the storage receipt.
		body.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body)}

		commit2, err := SignExecutorCommitment(sk2, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = pool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments.
		err = pool.CheckEnoughCommitments(false)
		require.NoError(t, err, "CheckEnoughCommitments")

		// There should be a discrepancy.
		_, err = pool.DetectDiscrepancy()
		require.Error(t, err, "DetectDiscrepancy")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)

		// There should not be enough executor commitments from backup workers.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit3)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments from backup workers.
		err = pool.CheckEnoughCommitments(false)
		require.NoError(t, err, "CheckEnoughCommitments")

		// Discrepancy resolution should succeed.
		dc, err := pool.ResolveDiscrepancy()
		require.NoError(t, err, "ResolveDiscrepancy")
		require.Equal(t, true, pool.Discrepancy)
		header := dc.ToDDResult().(ComputeResultsHeader)
		require.EqualValues(t, &correctHeader, &header, "DR should return the same header")

		// TODO: Test discrepancy resolution failure.
	})
}

func TestPoolSerialization(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	// Generate a non-TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	cID := sk.Public()
	committee := &scheduler.Committee{
		Kind: scheduler.KindExecutor,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}
	nodeInfo := map[signature.PublicKey]NodeInfo{
		cID: NodeInfo{
			CommitteeNode: 0,
			Runtime: &node.Runtime{
				ID: rtID,
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
		NodeInfo:  nodeInfo,
	}

	// Generate a commitment.
	childBlk, _, body := generateComputeBody(t, committee)

	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(childBlk, nopSV, commit)
	require.NoError(t, err, "AddExecutorCommitment")

	m := cbor.Marshal(pool)
	var d Pool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough executor commitments.
	err = pool.CheckEnoughCommitments(false)
	require.NoError(t, err, "CheckEnoughCommitments")

	// There should be no discrepancy.
	dc, err := pool.DetectDiscrepancy()
	require.NoError(t, err, "DetectDiscrepancy")
	require.Equal(t, false, pool.Discrepancy)
	header := dc.ToDDResult().(ComputeResultsHeader)
	require.EqualValues(t, &body.Header, &header, "DD should return the same header")
}

func TestMultiPoolSerialization(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks1, committee1, nodeInfo1 := generateMockCommittee(t)
	_, sks2, committee2, nodeInfo2 := generateMockCommittee(t)
	com1ID := committee1.EncodedMembersHash()
	com2ID := committee2.EncodedMembersHash()

	// Create a multi-pool.
	pool := MultiPool{
		Committees: map[hash.Hash]*Pool{
			com1ID: &Pool{
				Runtime:   rt,
				Committee: committee1,
				NodeInfo:  nodeInfo1,
			},
			com2ID: &Pool{
				Runtime:   rt,
				Committee: committee2,
				NodeInfo:  nodeInfo2,
			},
		},
	}

	// Generate commitments.
	childBlk, _, body1 := generateComputeBody(t, committee1)
	_, _, body2 := generateComputeBody(t, committee2)

	// First committee.
	c1commit1, err := SignExecutorCommitment(sks1[0], &body1)
	require.NoError(t, err, "SignExecutorCommitment")

	c1commit2, err := SignExecutorCommitment(sks1[1], &body1)
	require.NoError(t, err, "SignExecutorCommitment")

	// Second committee.
	c2commit1, err := SignExecutorCommitment(sks2[0], &body2)
	require.NoError(t, err, "SignExecutorCommitment")

	c2commit2, err := SignExecutorCommitment(sks2[1], &body2)
	require.NoError(t, err, "SignExecutorCommitment")

	// Adding commitment 1 should succeed.
	sp, err := pool.AddExecutorCommitment(childBlk, nopSV, c1commit1)
	require.NoError(t, err, "AddExecutorCommitment")
	require.Equal(t, pool.Committees[com1ID], sp, "AddExecutorCommitment")

	// Adding commitment 2 should succeed.
	sp, err = pool.AddExecutorCommitment(childBlk, nopSV, c1commit2)
	require.NoError(t, err, "AddExecutorCommitment")
	require.Equal(t, pool.Committees[com1ID], sp, "AddExecutorCommitment")

	// Adding commitment 3 should succeed.
	sp, err = pool.AddExecutorCommitment(childBlk, nopSV, c2commit1)
	require.NoError(t, err, "AddExecutorCommitment")
	require.Equal(t, pool.Committees[com2ID], sp, "AddExecutorCommitment")

	// Adding commitment 4 should succeed.
	sp, err = pool.AddExecutorCommitment(childBlk, nopSV, c2commit2)
	require.NoError(t, err, "AddExecutorCommitment")
	require.Equal(t, pool.Committees[com2ID], sp, "AddExecutorCommitment")

	m := cbor.Marshal(pool)
	var d MultiPool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough executor commitments.
	err = d.CheckEnoughCommitments()
	require.NoError(t, err, "CheckEnoughCommitments")
}

func TestPoolMergeCommitment(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, executorSks, executorCommittee, executorNodeInfo := generateMockCommittee(t)
	_, mergeSks, mergeCommittee, mergeNodeInfo := generateMockCommittee(t)
	mergeCommittee.Kind = scheduler.KindMerge
	executorCommitteeID := executorCommittee.EncodedMembersHash()

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a merge commitment pool.
		mergePool := Pool{
			Runtime:   rt,
			Committee: mergeCommittee,
			NodeInfo:  mergeNodeInfo,
		}

		// Create a executor commitment multi-pool.
		executorPool := MultiPool{
			Committees: map[hash.Hash]*Pool{
				executorCommitteeID: &Pool{
					Runtime:   rt,
					Committee: executorCommittee,
					NodeInfo:  executorNodeInfo,
				},
			},
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t, executorCommittee)

		commit1, err := SignExecutorCommitment(executorSks[0], &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(executorSks[1], &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Generate a merge commitment.
		mergeBody := MergeBody{
			ExecutorCommits: []ExecutorCommitment{*commit1, *commit2},
			Header:          parentBlk.Header,
		}

		mergeCommit1, err := SignMergeCommitment(mergeSks[0], &mergeBody)
		require.NoError(t, err, "SignMergeCommitment")

		mergeCommit2, err := SignMergeCommitment(mergeSks[1], &mergeBody)
		require.NoError(t, err, "SignMergeCommitment")

		// Adding commitment 1 should succeed.
		err = mergePool.AddMergeCommitment(childBlk, nopSV, mergeCommit1, &executorPool)
		require.NoError(t, err, "AddMergeCommitment")

		// There should not be enough merge commitments.
		err = mergePool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = mergePool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = mergePool.AddMergeCommitment(childBlk, nopSV, mergeCommit2, &executorPool)
		require.NoError(t, err, "AddExecutorCommitment")

		m := cbor.Marshal(executorPool)
		var d MultiPool
		err = cbor.Unmarshal(m, &d)
		require.NoError(t, err)

		// There should be enough merge commitments.
		err = mergePool.CheckEnoughCommitments(false)
		require.NoError(t, err, "CheckEnoughCommitments")

		// There should be no discrepancy.
		dc, err := mergePool.DetectDiscrepancy()
		require.NoError(t, err, "DetectDiscrepancy")
		require.Equal(t, false, mergePool.Discrepancy)
		header := dc.ToDDResult().(block.Header)
		require.EqualValues(t, &parentBlk.Header, &header, "DD should return the same header")
	})

	t.Run("ResolvedExecutionDiscrepancy", func(t *testing.T) {
		// Create a merge commitment pool.
		mergePool := Pool{
			Runtime:   rt,
			Committee: mergeCommittee,
			NodeInfo:  mergeNodeInfo,
		}

		// Create a executor commitment multi-pool.
		executorPool := MultiPool{
			Committees: map[hash.Hash]*Pool{
				executorCommitteeID: &Pool{
					Runtime:   rt,
					Committee: executorCommittee,
					NodeInfo:  executorNodeInfo,
				},
			},
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t, executorCommittee)

		commit1, err := SignExecutorCommitment(executorSks[0], &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(executorSks[2], &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Update state root and fix the storage receipt.
		body.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body)}

		commit2, err := SignExecutorCommitment(executorSks[1], &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Generate a merge commitment.
		mergeBody := MergeBody{
			ExecutorCommits: []ExecutorCommitment{*commit1, *commit2, *commit3},
			Header:          parentBlk.Header,
		}

		mergeCommit1, err := SignMergeCommitment(mergeSks[0], &mergeBody)
		require.NoError(t, err, "SignMergeCommitment")

		mergeCommit2, err := SignMergeCommitment(mergeSks[1], &mergeBody)
		require.NoError(t, err, "SignMergeCommitment")

		// Adding commitment 1 should succeed.
		err = mergePool.AddMergeCommitment(childBlk, nopSV, mergeCommit1, &executorPool)
		require.NoError(t, err, "AddMergeCommitment")

		// There should not be enough merge commitments.
		err = mergePool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = mergePool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = mergePool.AddMergeCommitment(childBlk, nopSV, mergeCommit2, &executorPool)
		require.NoError(t, err, "AddExecutorCommitment")

		m := cbor.Marshal(executorPool)
		var d MultiPool
		err = cbor.Unmarshal(m, &d)
		require.NoError(t, err)

		// There should be enough merge commitments.
		err = mergePool.CheckEnoughCommitments(false)
		require.NoError(t, err, "CheckEnoughCommitments")

		// There should be no discrepancy.
		dc, err := mergePool.DetectDiscrepancy()
		require.NoError(t, err, "DetectDiscrepancy")
		require.Equal(t, false, mergePool.Discrepancy)
		header := dc.ToDDResult().(block.Header)
		require.EqualValues(t, &parentBlk.Header, &header, "DD should return the same header")
	})
}

func TestMultiPool(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks1, committee1, nodeInfo1 := generateMockCommittee(t)
	_, sks2, committee2, nodeInfo2 := generateMockCommittee(t)
	com1ID := committee1.EncodedMembersHash()
	com2ID := committee2.EncodedMembersHash()

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a multi-pool.
		pool := MultiPool{
			Committees: map[hash.Hash]*Pool{
				com1ID: &Pool{
					Runtime:   rt,
					Committee: committee1,
					NodeInfo:  nodeInfo1,
				},
				com2ID: &Pool{
					Runtime:   rt,
					Committee: committee2,
					NodeInfo:  nodeInfo2,
				},
			},
		}

		// Generate commitments.
		childBlk, _, body1 := generateComputeBody(t, committee1)
		_, _, body2 := generateComputeBody(t, committee2)

		bodyInvalidID := body1
		bodyInvalidID.CommitteeID.FromBytes([]byte("invalid-committee-id"))

		// First committee.
		c1commit1, err := SignExecutorCommitment(sks1[0], &body1)
		require.NoError(t, err, "SignExecutorCommitment")

		c1commit2, err := SignExecutorCommitment(sks1[1], &body1)
		require.NoError(t, err, "SignExecutorCommitment")

		// Second committee.
		c2commit1, err := SignExecutorCommitment(sks2[0], &body2)
		require.NoError(t, err, "SignExecutorCommitment")

		c2commit2, err := SignExecutorCommitment(sks2[1], &body2)
		require.NoError(t, err, "SignExecutorCommitment")

		// Invalid committee.
		cInvalidCommit, err := SignExecutorCommitment(sks1[0], &bodyInvalidID)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding a commitment for an invalid committee should fail.
		_, err = pool.AddExecutorCommitment(childBlk, nopSV, cInvalidCommit)
		require.Error(t, err, "AddExecutorCommitment")
		require.Equal(t, ErrInvalidCommitteeID, err, "AddExecutorCommitment")

		// Adding commitment 1 should succeed.
		sp, err := pool.AddExecutorCommitment(childBlk, nopSV, c1commit1)
		require.NoError(t, err, "AddExecutorCommitment")
		require.Equal(t, pool.Committees[com1ID], sp, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		sp, err = pool.AddExecutorCommitment(childBlk, nopSV, c1commit2)
		require.NoError(t, err, "AddExecutorCommitment")
		require.Equal(t, pool.Committees[com1ID], sp, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 3 should succeed.
		sp, err = pool.AddExecutorCommitment(childBlk, nopSV, c2commit1)
		require.NoError(t, err, "AddExecutorCommitment")
		require.Equal(t, pool.Committees[com2ID], sp, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 4 should succeed.
		sp, err = pool.AddExecutorCommitment(childBlk, nopSV, c2commit2)
		require.NoError(t, err, "AddExecutorCommitment")
		require.Equal(t, pool.Committees[com2ID], sp, "AddExecutorCommitment")

		// There should be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.NoError(t, err, "CheckEnoughCommitments")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		// Create a multi-pool.
		pool := MultiPool{
			Committees: map[hash.Hash]*Pool{
				com1ID: &Pool{
					Runtime:   rt,
					Committee: committee1,
					NodeInfo:  nodeInfo1,
				},
				com2ID: &Pool{
					Runtime:   rt,
					Committee: committee2,
					NodeInfo:  nodeInfo2,
				},
			},
		}

		// Generate commitments.
		childBlk, _, body1 := generateComputeBody(t, committee1)
		_, parentBlk, body2 := generateComputeBody(t, committee2)

		// First committee.
		c1commit1, err := SignExecutorCommitment(sks1[0], &body1)
		require.NoError(t, err, "SignExecutorCommitment")

		c1commit2, err := SignExecutorCommitment(sks1[1], &body1)
		require.NoError(t, err, "SignExecutorCommitment")

		// Second committee.
		c2commit1, err := SignExecutorCommitment(sks2[0], &body2)
		require.NoError(t, err, "SignExecutorCommitment")

		// Update state root and fix the storage receipt.
		body2.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body2.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body2)}

		c2commit2, err := SignExecutorCommitment(sks2[1], &body2)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		_, err = pool.AddExecutorCommitment(childBlk, nopSV, c1commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		_, err = pool.AddExecutorCommitment(childBlk, nopSV, c1commit2)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 3 should succeed.
		_, err = pool.AddExecutorCommitment(childBlk, nopSV, c2commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 4 should succeed.
		_, err = pool.AddExecutorCommitment(childBlk, nopSV, c2commit2)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be enough executor commitments.
		err = pool.CheckEnoughCommitments()
		require.NoError(t, err, "CheckEnoughCommitments")
	})
}

func TestTryFinalize(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nodeInfo := generateMockCommittee(t)
	sk1 := sks[0]
	sk2 := sks[1]
	sk3 := sks[2]

	now := time.Now()
	roundTimeout := 10 * time.Second

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			NodeInfo:  nodeInfo,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, committee)

		bodyInvalidID := body
		bodyInvalidID.CommitteeID.FromBytes([]byte("invalid-committee-id"))

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Invalid committee.
		cInvalidCommit, err := SignExecutorCommitment(sk1, &bodyInvalidID)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding a commitment for an invalid committee should fail.
		err = pool.AddExecutorCommitment(childBlk, nopSV, cInvalidCommit)
		require.Error(t, err, "AddExecutorCommitment")
		require.Equal(t, ErrInvalidCommitteeID, err, "AddExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		header := dc.ToDDResult().(ComputeResultsHeader)
		require.EqualValues(t, &body.Header, &header, "DD should return the same header")
		require.True(t, pool.NextTimeout.IsZero(), "NextTimeout should be zero")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			NodeInfo:  nodeInfo,
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t, committee)

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(sk3, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		correctHeader := body.Header

		// Update state root and fix the storage receipt.
		body.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body)}

		commit2, err := SignExecutorCommitment(sk2, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should be a discrepancy.
		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)

		// There should not be enough executor commitments from backup workers.
		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err)

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit3)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		header := dc.ToDDResult().(ComputeResultsHeader)
		require.EqualValues(t, &correctHeader, &header, "DR should return the same header")
		require.True(t, pool.NextTimeout.IsZero(), "NextTimeout should be zero")
	})

	t.Run("Timeout", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
			NodeInfo:  nodeInfo,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t, committee)

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(sk3, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		correctHeader := body.Header

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Simulate a non-authoritative timeout -- this should return
		// a discrepancy detected error, but not change the internal
		// discrepancy flag.
		nowAfterTimeout := now.Add(roundTimeout)
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, true, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, false, pool.Discrepancy)
		require.True(t, pool.NextTimeout.IsZero(), "NextTimeout should be zero")

		// Simulate a timeout -- this should cause a discrepancy.
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, true, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)
		require.True(t, pool.NextTimeout.IsZero(), "NextTimeout should be zero")

		// There should not be enough executor commitments from backup workers.
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err)
		require.EqualValues(t, nowAfterTimeout.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddExecutorCommitment(childBlk, nopSV, commit3)
		require.NoError(t, err, "AddExecutorCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false, true)
		require.NoError(t, err, "TryFinalize")
		header := dc.ToDDResult().(ComputeResultsHeader)
		require.EqualValues(t, &correctHeader, &header, "DR should return the same header")
		require.True(t, pool.NextTimeout.IsZero(), "NextTimeout should be zero")
	})
}

func generateMockCommittee(t *testing.T) (
	rt *registry.Runtime,
	sks []signature.Signer,
	committee *scheduler.Committee,
	nodeInfo map[signature.PublicKey]NodeInfo,
) {
	// Generate a non-TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt = &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate commitment signing keys.
	sk1, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	sk2, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	sk3, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	sks = append(sks, sk1, sk2, sk3)

	// Generate a committee.
	c1ID := sk1.Public()
	c2ID := sk2.Public()
	c3ID := sk3.Public()
	committee = &scheduler.Committee{
		Kind: scheduler.KindExecutor,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk1.Public(),
			},
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk2.Public(),
			},
			&scheduler.CommitteeNode{
				Role:      scheduler.BackupWorker,
				PublicKey: sk3.Public(),
			},
		},
	}
	nodeInfo = map[signature.PublicKey]NodeInfo{
		c1ID: NodeInfo{
			CommitteeNode: 0,
			Runtime: &node.Runtime{
				ID: rtID,
			},
		},
		c2ID: NodeInfo{
			CommitteeNode: 1,
			Runtime: &node.Runtime{
				ID: rtID,
			},
		},
		c3ID: NodeInfo{
			CommitteeNode: 2,
			Runtime: &node.Runtime{
				ID: rtID,
			},
		},
	}
	return
}

func generateComputeBody(t *testing.T, committee *scheduler.Committee) (*block.Block, *block.Block, ComputeBody) {
	var id common.Namespace
	childBlk := block.NewGenesisBlock(id, 0)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	body := ComputeBody{
		CommitteeID: committee.EncodedMembersHash(),
		Header: ComputeResultsHeader{
			PreviousHash: parentBlk.Header.PreviousHash,
			IORoot:       parentBlk.Header.IORoot,
			StateRoot:    parentBlk.Header.StateRoot,
		},
	}

	// Generate dummy storage receipt signature.
	sig := generateStorageReceiptSignature(t, parentBlk, &body)
	body.StorageSignatures = []signature.Signature{sig}
	parentBlk.Header.StorageSignatures = []signature.Signature{sig}

	// Generate dummy txn scheduler signature.
	body.TxnSchedSig = generateTxnSchedulerSignature(t, childBlk, &body)

	return childBlk, parentBlk, body
}

func generateStorageReceiptSignature(t *testing.T, blk *block.Block, body *ComputeBody) signature.Signature {
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	receiptBody := storage.ReceiptBody{
		Version:   1,
		Namespace: blk.Header.Namespace,
		Round:     blk.Header.Round,
		Roots:     body.RootsForStorageReceipt(),
	}
	signed, err := signature.SignSigned(sk, storage.ReceiptSignatureContext, &receiptBody)
	require.NoError(t, err, "SignSigned")

	return signed.Signature
}

func generateTxnSchedulerSignature(t *testing.T, childBlk *block.Block, body *ComputeBody) signature.Signature {
	body.InputRoot = hash.Hash{}
	body.InputStorageSigs = []signature.Signature{}
	dispatch := &TxnSchedulerBatchDispatch{
		CommitteeID:       body.CommitteeID,
		IORoot:            body.InputRoot,
		StorageSignatures: body.InputStorageSigs,
		Header:            childBlk.Header,
	}
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	signedDispatch, err := signature.SignSigned(sk, TxnSchedulerBatchDispatchSigCtx, dispatch)
	require.NoError(t, err, "SignSigned")

	return signedDispatch.Signature
}
