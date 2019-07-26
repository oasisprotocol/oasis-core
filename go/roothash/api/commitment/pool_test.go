package commitment

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	memorySigner "github.com/oasislabs/ekiden/go/common/crypto/signature/signers/memory"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
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
	// Generate a commitment.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	var id signature.PublicKey
	blk := block.NewGenesisBlock(id, 0)

	body := ComputeBody{
		Header: ComputeResultsHeader{
			PreviousHash: blk.Header.PreviousHash,
			IORoot:       blk.Header.IORoot,
			StateRoot:    blk.Header.StateRoot,
		},
	}
	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// An empty pool should work but should always error.
	pool := Pool{}
	err = pool.AddComputeCommitment(blk, nopSV, commit)
	require.Error(t, err, "AddComputeCommitment")
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
	// Generate a non-TEE runtime.
	var rtID signature.PublicKey
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	cID := sk.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.KindCompute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}
	nodeInfo := map[signature.MapKey]NodeInfo{
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

	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	sv := &staticSignatureVerifier{
		storagePublicKey:      body.StorageSignatures[0].PublicKey,
		txnSchedulerPublicKey: body.TxnSchedSig.PublicKey,
	}

	// Adding a commitment not based on correct block should fail.
	err = pool.AddComputeCommitment(parentBlk, sv, commit)
	require.Error(t, err, "AddComputeCommitment")

	// There should not be enough compute commitments.
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
	incorrectCommit, err := SignComputeCommitment(sk, &bodyIncorrectStorageSig)
	require.NoError(t, err, "SignComputeCommitment")
	err = pool.AddComputeCommitment(childBlk, sv, incorrectCommit)
	require.Error(t, err, "AddComputeCommitment")

	// Adding a commitment having txn scheduler inputs signed with an incorrect
	// public key should fail.
	bodyIncorrectTxnSchedSig := body
	// This generates a new signing key so verification should fail.
	bodyIncorrectTxnSchedSig.TxnSchedSig = generateTxnSchedulerSignature(t, childBlk, &bodyIncorrectTxnSchedSig)
	incorrectCommit, err = SignComputeCommitment(sk, &bodyIncorrectTxnSchedSig)
	require.NoError(t, err, "SignComputeCommitment")
	err = pool.AddComputeCommitment(childBlk, sv, incorrectCommit)
	require.Error(t, err, "AddComputeCommitment")

	// Adding a commitment should succeed.
	err = pool.AddComputeCommitment(childBlk, sv, commit)
	require.NoError(t, err, "AddComputeCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddComputeCommitment(childBlk, sv, commit)
	require.Error(t, err, "AddComputeCommitment(duplicate)")

	// There should be enough compute commitments.
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
	// Generate a TEE runtime.
	var rtID signature.PublicKey
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
	cID := sk.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.KindCompute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}
	nodeInfo := map[signature.MapKey]NodeInfo{
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
	rakSig, err := signature.Sign(skRAK, ComputeResultsHeaderSignatureContext, body.Header.MarshalCBOR())
	require.NoError(t, err, "Sign")
	body.RakSig = rakSig.Signature

	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// Adding a commitment not based on correct block should fail.
	err = pool.AddComputeCommitment(parentBlk, nopSV, commit)
	require.Error(t, err, "AddComputeCommitment")

	// There should not be enough compute commitments.
	err = pool.CheckEnoughCommitments(false)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
	err = pool.CheckEnoughCommitments(true)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

	// Adding a commitment should succeed.
	err = pool.AddComputeCommitment(childBlk, nopSV, commit)
	require.NoError(t, err, "AddComputeCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddComputeCommitment(childBlk, nopSV, commit)
	require.Error(t, err, "AddComputeCommitment(duplicate)")

	// There should be enough compute commitments.
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

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit2, err := SignComputeCommitment(sk2, &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Invalid committee.
		cInvalidCommit, err := SignComputeCommitment(sk1, &bodyInvalidID)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding a commitment for an invalid committee should fail.
		err = pool.AddComputeCommitment(childBlk, nopSV, cInvalidCommit)
		require.Error(t, err, "AddComputeCommitment")
		require.Equal(t, ErrInvalidCommitteeID, err, "AddComputeCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = pool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments.
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

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit3, err := SignComputeCommitment(sk3, &body)
		require.NoError(t, err, "SignComputeCommitment")

		correctHeader := body.Header

		// Update state root and fix the storage receipt.
		body.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body)}

		commit2, err := SignComputeCommitment(sk2, &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = pool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments.
		err = pool.CheckEnoughCommitments(false)
		require.NoError(t, err, "CheckEnoughCommitments")

		// There should be a discrepancy.
		_, err = pool.DetectDiscrepancy()
		require.Error(t, err, "DetectDiscrepancy")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)

		// There should not be enough compute commitments from backup workers.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit3)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments from backup workers.
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
	// Generate a non-TEE runtime.
	var rtID signature.PublicKey
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	cID := sk.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.KindCompute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}
	nodeInfo := map[signature.MapKey]NodeInfo{
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

	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// Adding a commitment should succeed.
	err = pool.AddComputeCommitment(childBlk, nopSV, commit)
	require.NoError(t, err, "AddComputeCommitment")

	m := cbor.Marshal(pool)
	var d Pool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough compute commitments.
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
	c1commit1, err := SignComputeCommitment(sks1[0], &body1)
	require.NoError(t, err, "SignComputeCommitment")

	c1commit2, err := SignComputeCommitment(sks1[1], &body1)
	require.NoError(t, err, "SignComputeCommitment")

	// Second committee.
	c2commit1, err := SignComputeCommitment(sks2[0], &body2)
	require.NoError(t, err, "SignComputeCommitment")

	c2commit2, err := SignComputeCommitment(sks2[1], &body2)
	require.NoError(t, err, "SignComputeCommitment")

	// Adding commitment 1 should succeed.
	sp, err := pool.AddComputeCommitment(childBlk, nopSV, c1commit1)
	require.NoError(t, err, "AddComputeCommitment")
	require.Equal(t, pool.Committees[com1ID], sp, "AddComputeCommitment")

	// Adding commitment 2 should succeed.
	sp, err = pool.AddComputeCommitment(childBlk, nopSV, c1commit2)
	require.NoError(t, err, "AddComputeCommitment")
	require.Equal(t, pool.Committees[com1ID], sp, "AddComputeCommitment")

	// Adding commitment 3 should succeed.
	sp, err = pool.AddComputeCommitment(childBlk, nopSV, c2commit1)
	require.NoError(t, err, "AddComputeCommitment")
	require.Equal(t, pool.Committees[com2ID], sp, "AddComputeCommitment")

	// Adding commitment 4 should succeed.
	sp, err = pool.AddComputeCommitment(childBlk, nopSV, c2commit2)
	require.NoError(t, err, "AddComputeCommitment")
	require.Equal(t, pool.Committees[com2ID], sp, "AddComputeCommitment")

	m := cbor.Marshal(pool)
	var d MultiPool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough compute commitments.
	err = d.CheckEnoughCommitments()
	require.NoError(t, err, "CheckEnoughCommitments")
}

func TestPoolMergeCommitment(t *testing.T) {
	rt, computeSks, computeCommittee, computeNodeInfo := generateMockCommittee(t)
	_, mergeSks, mergeCommittee, mergeNodeInfo := generateMockCommittee(t)
	mergeCommittee.Kind = scheduler.KindMerge
	computeCommitteeID := computeCommittee.EncodedMembersHash()

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a merge commitment pool.
		mergePool := Pool{
			Runtime:   rt,
			Committee: mergeCommittee,
			NodeInfo:  mergeNodeInfo,
		}

		// Create a compute commitment multi-pool.
		computePool := MultiPool{
			Committees: map[hash.Hash]*Pool{
				computeCommitteeID: &Pool{
					Runtime:   rt,
					Committee: computeCommittee,
					NodeInfo:  computeNodeInfo,
				},
			},
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t, computeCommittee)

		commit1, err := SignComputeCommitment(computeSks[0], &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit2, err := SignComputeCommitment(computeSks[1], &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Generate a merge commitment.
		mergeBody := MergeBody{
			ComputeCommits: []ComputeCommitment{*commit1, *commit2},
			Header:         parentBlk.Header,
		}

		mergeCommit1, err := SignMergeCommitment(mergeSks[0], &mergeBody)
		require.NoError(t, err, "SignMergeCommitment")

		mergeCommit2, err := SignMergeCommitment(mergeSks[1], &mergeBody)
		require.NoError(t, err, "SignMergeCommitment")

		// Adding commitment 1 should succeed.
		err = mergePool.AddMergeCommitment(childBlk, nopSV, mergeCommit1, &computePool)
		require.NoError(t, err, "AddMergeCommitment")

		// There should not be enough merge commitments.
		err = mergePool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = mergePool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = mergePool.AddMergeCommitment(childBlk, nopSV, mergeCommit2, &computePool)
		require.NoError(t, err, "AddComputeCommitment")

		m := cbor.Marshal(computePool)
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
		c1commit1, err := SignComputeCommitment(sks1[0], &body1)
		require.NoError(t, err, "SignComputeCommitment")

		c1commit2, err := SignComputeCommitment(sks1[1], &body1)
		require.NoError(t, err, "SignComputeCommitment")

		// Second committee.
		c2commit1, err := SignComputeCommitment(sks2[0], &body2)
		require.NoError(t, err, "SignComputeCommitment")

		c2commit2, err := SignComputeCommitment(sks2[1], &body2)
		require.NoError(t, err, "SignComputeCommitment")

		// Invalid committee.
		cInvalidCommit, err := SignComputeCommitment(sks1[0], &bodyInvalidID)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding a commitment for an invalid committee should fail.
		_, err = pool.AddComputeCommitment(childBlk, nopSV, cInvalidCommit)
		require.Error(t, err, "AddComputeCommitment")
		require.Equal(t, ErrInvalidCommitteeID, err, "AddComputeCommitment")

		// Adding commitment 1 should succeed.
		sp, err := pool.AddComputeCommitment(childBlk, nopSV, c1commit1)
		require.NoError(t, err, "AddComputeCommitment")
		require.Equal(t, pool.Committees[com1ID], sp, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		sp, err = pool.AddComputeCommitment(childBlk, nopSV, c1commit2)
		require.NoError(t, err, "AddComputeCommitment")
		require.Equal(t, pool.Committees[com1ID], sp, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 3 should succeed.
		sp, err = pool.AddComputeCommitment(childBlk, nopSV, c2commit1)
		require.NoError(t, err, "AddComputeCommitment")
		require.Equal(t, pool.Committees[com2ID], sp, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 4 should succeed.
		sp, err = pool.AddComputeCommitment(childBlk, nopSV, c2commit2)
		require.NoError(t, err, "AddComputeCommitment")
		require.Equal(t, pool.Committees[com2ID], sp, "AddComputeCommitment")

		// There should be enough compute commitments.
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
		c1commit1, err := SignComputeCommitment(sks1[0], &body1)
		require.NoError(t, err, "SignComputeCommitment")

		c1commit2, err := SignComputeCommitment(sks1[1], &body1)
		require.NoError(t, err, "SignComputeCommitment")

		// Second committee.
		c2commit1, err := SignComputeCommitment(sks2[0], &body2)
		require.NoError(t, err, "SignComputeCommitment")

		// Update state root and fix the storage receipt.
		body2.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body2.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body2)}

		c2commit2, err := SignComputeCommitment(sks2[1], &body2)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding commitment 1 should succeed.
		_, err = pool.AddComputeCommitment(childBlk, nopSV, c1commit1)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		_, err = pool.AddComputeCommitment(childBlk, nopSV, c1commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 3 should succeed.
		_, err = pool.AddComputeCommitment(childBlk, nopSV, c2commit1)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 4 should succeed.
		_, err = pool.AddComputeCommitment(childBlk, nopSV, c2commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments.
		err = pool.CheckEnoughCommitments()
		require.NoError(t, err, "CheckEnoughCommitments")
	})
}

func TestTryFinalize(t *testing.T) {
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

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit2, err := SignComputeCommitment(sk2, &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Invalid committee.
		cInvalidCommit, err := SignComputeCommitment(sk1, &bodyInvalidID)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding a commitment for an invalid committee should fail.
		err = pool.AddComputeCommitment(childBlk, nopSV, cInvalidCommit)
		require.Error(t, err, "AddComputeCommitment")
		require.Equal(t, ErrInvalidCommitteeID, err, "AddComputeCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddComputeCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false)
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

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit3, err := SignComputeCommitment(sk3, &body)
		require.NoError(t, err, "SignComputeCommitment")

		correctHeader := body.Header

		// Update state root and fix the storage receipt.
		body.Header.StateRoot.FromBytes([]byte("discrepancy"))
		body.StorageSignatures = []signature.Signature{generateStorageReceiptSignature(t, parentBlk, &body)}

		commit2, err := SignComputeCommitment(sk2, &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be a discrepancy.
		_, err = pool.TryFinalize(now, roundTimeout, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)

		// There should not be enough compute commitments from backup workers.
		_, err = pool.TryFinalize(now, roundTimeout, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err)

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit3)
		require.NoError(t, err, "AddComputeCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false)
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

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit3, err := SignComputeCommitment(sk3, &body)
		require.NoError(t, err, "SignComputeCommitment")

		correctHeader := body.Header

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Simulate a timeout -- this should cause a discrepancy.
		nowAfterTimeout := now.Add(roundTimeout)
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrDiscrepancyDetected, err)
		require.Equal(t, true, pool.Discrepancy)
		require.True(t, pool.NextTimeout.IsZero(), "NextTimeout should be zero")

		// There should not be enough compute commitments from backup workers.
		_, err = pool.TryFinalize(nowAfterTimeout, roundTimeout, false)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err)
		require.EqualValues(t, nowAfterTimeout.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddComputeCommitment(childBlk, nopSV, commit3)
		require.NoError(t, err, "AddComputeCommitment")

		dc, err := pool.TryFinalize(now, roundTimeout, false)
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
	nodeInfo map[signature.MapKey]NodeInfo,
) {
	// Generate a non-TEE runtime.
	var rtID signature.PublicKey
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
	c1ID := sk1.Public().ToMapKey()
	c2ID := sk2.Public().ToMapKey()
	c3ID := sk3.Public().ToMapKey()
	committee = &scheduler.Committee{
		Kind: scheduler.KindCompute,
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
	nodeInfo = map[signature.MapKey]NodeInfo{
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
	var id signature.PublicKey
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
