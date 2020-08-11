package commitment

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/signature"
	memorySigner "github.com/oasisprotocol/oasis-core/go/common/crypto/signature/signers/memory"
	"github.com/oasisprotocol/oasis-core/go/common/node"
	genesisTestHelpers "github.com/oasisprotocol/oasis-core/go/genesis/tests"
	registry "github.com/oasisprotocol/oasis-core/go/registry/api"
	"github.com/oasisprotocol/oasis-core/go/roothash/api/block"
	scheduler "github.com/oasisprotocol/oasis-core/go/scheduler/api"
	storage "github.com/oasisprotocol/oasis-core/go/storage/api"
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
	case scheduler.KindComputeTxnScheduler:
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

type staticNodeLookup struct {
	runtime *node.Runtime
}

func (n *staticNodeLookup) Node(ctx context.Context, id signature.PublicKey) (*node.Node, error) {
	return &node.Node{
		Versioned: cbor.NewVersioned(node.LatestNodeDescriptorVersion),
		ID:        id,
		Runtimes:  []*node.Runtime{n.runtime},
	}, nil
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
			Round:        blk.Header.Round,
			PreviousHash: blk.Header.PreviousHash,
			IORoot:       blk.Header.IORoot,
			StateRoot:    blk.Header.StateRoot,
		},
	}
	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// An empty pool should work but should always error.
	pool := Pool{}
	err = pool.AddExecutorCommitment(context.Background(), blk, nopSV, &staticNodeLookup{}, commit)
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
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          rtID,
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareInvalid,
		Storage: registry.StorageParameters{
			GroupSize:           1,
			MinWriteReplication: 1,
		},
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
	}

	// Generate a commitment.
	childBlk, parentBlk, body := generateComputeBody(t)

	sv := &staticSignatureVerifier{
		storagePublicKey:      body.StorageSignatures[0].PublicKey,
		txnSchedulerPublicKey: body.TxnSchedSig.PublicKey,
	}
	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
		},
	}

	// Test invalid commitments.
	for _, tc := range []struct {
		name        string
		fn          func(*ComputeBody)
		expectedErr error
	}{
		{"BlockBadRound", func(b *ComputeBody) { b.Header.Round-- }, ErrNotBasedOnCorrectBlock},
		{"BlockBadPreviousHash", func(b *ComputeBody) { b.Header.PreviousHash.FromBytes([]byte("invalid")) }, ErrNotBasedOnCorrectBlock},
		{"StorageSigs1", func(b *ComputeBody) { b.StorageSignatures = nil }, ErrBadStorageReceipts},
	} {
		_, _, invalidBody := generateComputeBody(t)
		invalidBody.StorageSignatures = append([]signature.Signature{}, body.StorageSignatures...)
		invalidBody.TxnSchedSig = body.TxnSchedSig

		tc.fn(&invalidBody)

		var commit *ExecutorCommitment
		commit, err = SignExecutorCommitment(sk, &invalidBody)
		require.NoError(t, err, "SignExecutorCommitment(%s)", tc.name)

		err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, commit)
		require.Error(t, err, "AddExecutorCommitment(%s)", tc.name)
		require.Equal(t, tc.expectedErr, err, "AddExecutorCommitment(%s)", tc.name)
	}

	// Generate a valid commitment.
	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

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
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, incorrectCommit)
	require.Error(t, err, "AddExecutorCommitment")

	// Adding a commitment having not enough storage receipts should fail.
	bodyNotEnoughStorageSig := body
	bodyNotEnoughStorageSig.StorageSignatures = []signature.Signature{}
	incorrectCommit, err = SignExecutorCommitment(sk, &bodyNotEnoughStorageSig)
	require.NoError(t, err, "SignExecutorCommitment")
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, incorrectCommit)
	require.Error(t, err, "AddExecutorCommitment")
	require.Equal(t, ErrBadStorageReceipts, err, "AddExecutorCommitment")

	// Adding a commitment having txn scheduler inputs signed with an incorrect
	// public key should fail.
	bodyIncorrectTxnSchedSig := body
	// This generates a new signing key so verification should fail.
	bodyIncorrectTxnSchedSig.TxnSchedSig = generateTxnSchedulerSignature(t, childBlk, &bodyIncorrectTxnSchedSig)
	incorrectCommit, err = SignExecutorCommitment(sk, &bodyIncorrectTxnSchedSig)
	require.NoError(t, err, "SignExecutorCommitment")
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, incorrectCommit)
	require.Error(t, err, "AddExecutorCommitment")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, commit)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, sv, nl, commit)
	require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

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
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          rtID,
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareIntelSGX,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a dummy RAK.
	skRAK, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
	}

	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
			Capabilities: node.Capabilities{
				TEE: &node.CapabilityTEE{
					Hardware:    node.TEEHardwareIntelSGX,
					RAK:         skRAK.Public(),
					Attestation: []byte("My RAK is my attestation. Verify me."),
				},
			},
		},
	}

	// Generate a commitment.
	childBlk, _, body := generateComputeBody(t)
	rakSig, err := signature.Sign(skRAK, ComputeResultsHeaderSignatureContext, cbor.Marshal(body.Header))
	require.NoError(t, err, "Sign")
	body.RakSig = rakSig.Signature

	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// There should not be enough executor commitments.
	err = pool.CheckEnoughCommitments(false)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
	err = pool.CheckEnoughCommitments(true)
	require.Error(t, err, "CheckEnoughCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit)
	require.NoError(t, err, "AddExecutorCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit)
	require.Error(t, err, "AddExecutorCommitment(context.Background(), duplicate)")

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

	rt, sks, committee, nl := generateMockCommittee(t)
	sk1 := sks[0]
	sk2 := sks[1]
	sk3 := sks[2]

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:   rt,
			Committee: committee,
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t)

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = pool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2)
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
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t)

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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		// There should not be enough executor commitments.
		err = pool.CheckEnoughCommitments(false)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")
		err = pool.CheckEnoughCommitments(true)
		require.Error(t, err, "CheckEnoughCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2)
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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3)
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
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          rtID,
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate a commitment signing key.
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")

	// Generate a committee.
	committee := &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.Worker,
				PublicKey: sk.Public(),
			},
		},
	}

	// Create a pool.
	pool := Pool{
		Runtime:   rt,
		Committee: committee,
	}

	nl := &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
		},
	}

	// Generate a commitment.
	childBlk, _, body := generateComputeBody(t)

	commit, err := SignExecutorCommitment(sk, &body)
	require.NoError(t, err, "SignExecutorCommitment")

	// Adding a commitment should succeed.
	err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit)
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

func TestTryFinalize(t *testing.T) {
	genesisTestHelpers.SetTestChainContext()

	rt, sks, committee, nl := generateMockCommittee(t)
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
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t)

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit2, err := SignExecutorCommitment(sk2, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2)
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
		}

		// Generate a commitment.
		childBlk, parentBlk, body := generateComputeBody(t)

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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1)
		require.NoError(t, err, "AddExecutorCommitment")

		_, err = pool.TryFinalize(now, roundTimeout, false, true)
		require.Error(t, err, "TryFinalize")
		require.Equal(t, ErrStillWaiting, err, "TryFinalize")
		require.EqualValues(t, now.Add(roundTimeout).Round(time.Second), pool.NextTimeout, "NextTimeout should be set")

		// Adding commitment 2 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit2)
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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3)
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
		}

		// Generate a commitment.
		childBlk, _, body := generateComputeBody(t)

		commit1, err := SignExecutorCommitment(sk1, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		commit3, err := SignExecutorCommitment(sk3, &body)
		require.NoError(t, err, "SignExecutorCommitment")

		correctHeader := body.Header

		// Adding commitment 1 should succeed.
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit1)
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
		err = pool.AddExecutorCommitment(context.Background(), childBlk, nopSV, nl, commit3)
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
	nl NodeLookup,
) {
	// Generate a non-TEE runtime.
	var rtID common.Namespace
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt = &registry.Runtime{
		Versioned:   cbor.NewVersioned(registry.LatestRuntimeDescriptorVersion),
		ID:          rtID,
		Kind:        registry.KindCompute,
		TEEHardware: node.TEEHardwareInvalid,
		Storage: registry.StorageParameters{
			GroupSize:           1,
			MinWriteReplication: 1,
		},
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
	committee = &scheduler.Committee{
		Kind: scheduler.KindComputeExecutor,
		Members: []*scheduler.CommitteeNode{
			{
				Role:      scheduler.Worker,
				PublicKey: sk1.Public(),
			},
			{
				Role:      scheduler.Worker,
				PublicKey: sk2.Public(),
			},
			{
				Role:      scheduler.BackupWorker,
				PublicKey: sk3.Public(),
			},
		},
	}
	nl = &staticNodeLookup{
		runtime: &node.Runtime{
			ID: rtID,
		},
	}

	return
}

func generateComputeBody(t *testing.T) (*block.Block, *block.Block, ComputeBody) {
	var id common.Namespace
	childBlk := block.NewGenesisBlock(id, 0)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	body := ComputeBody{
		Header: ComputeResultsHeader{
			Round:        parentBlk.Header.Round,
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
	dispatch := &TxnSchedulerBatch{
		IORoot:            body.InputRoot,
		StorageSignatures: body.InputStorageSigs,
		Header:            childBlk.Header,
	}
	sk, err := memorySigner.NewSigner(rand.Reader)
	require.NoError(t, err, "NewSigner")
	signedDispatch, err := signature.SignSigned(sk, TxnSchedulerBatchSigCtx, dispatch)
	require.NoError(t, err, "SignSigned")

	return signedDispatch.Signature
}
