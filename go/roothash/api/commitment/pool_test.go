package commitment

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/node"
	registry "github.com/oasislabs/ekiden/go/registry/api"
	roothash "github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	scheduler "github.com/oasislabs/ekiden/go/scheduler/api"
	storage "github.com/oasislabs/ekiden/go/storage/api"
)

func TestPoolDefault(t *testing.T) {
	// Generate a commitment.
	sk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	var id signature.PublicKey
	blk := block.NewGenesisBlock(id, 0)

	body := ComputeBody{
		Header: blk.Header,
	}
	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// An empty pool should work but should always error.
	pool := Pool{}
	err = pool.AddComputeCommitment(blk, commit)
	require.Error(t, err, "AddComputeCommitment")
	err = pool.CheckEnoughComputeCommitments(true, false)
	require.Error(t, err, "CheckEnoughComputeCommitments")
	require.Equal(t, ErrNoCommittee, err)
	_, err = pool.DetectComputeDiscrepancy()
	require.Error(t, err, "DetectComputeDiscrepancy")
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
	sk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	// Generate a committee.
	cID := sk.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.Compute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Leader,
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
	var id signature.PublicKey
	childBlk := block.NewGenesisBlock(id, 0)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	body := ComputeBody{
		Header: parentBlk.Header,
	}

	// Generate dummy storage receipt.
	receipt := storage.MKVSReceiptBody{
		Version: 1,
		Roots:   body.Header.RootsForStorageReceipt(),
	}
	signedReceipt, err := signature.SignSigned(sk, storage.MKVSReceiptSignatureContext, &receipt)
	require.NoError(t, err, "SignSigned")
	body.Header.StorageReceipt = signedReceipt.Signature

	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// Adding a commitment should fail due to there being no NodeVerifyPolicy.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.Error(t, err, "AddComputeCommitment")
	// Configure a NodeVerifyPolicy that accepts all nodes.
	pool.NodeVerifyPolicy = func(*scheduler.CommitteeNode) error { return nil }

	// Adding a commitment not based on correct block should fail.
	err = pool.AddComputeCommitment(parentBlk, commit)
	require.Error(t, err, "AddComputeCommitment")

	// Adding a commitment should fail due to there being no StorageVerifyPolicy.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.Error(t, err, "AddComputeCommitment")
	// Configure a StorageVerifyPolicy that accepts all receipts.
	pool.StorageVerifyPolicy = func(signature.PublicKey) error { return nil }

	// There should not be enough compute commitments.
	err = pool.CheckEnoughComputeCommitments(true, false)
	require.Error(t, err, "CheckEnoughComputeCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")
	err = pool.CheckEnoughComputeCommitments(true, true)
	require.Error(t, err, "CheckEnoughComputeCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")

	// Adding a commitment should succeed.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.NoError(t, err, "AddComputeCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.Error(t, err, "AddComputeCommitment(duplicate)")

	// There should be enough compute commitments.
	err = pool.CheckEnoughComputeCommitments(true, false)
	require.NoError(t, err, "CheckEnoughComputeCommitments")

	// There should be no discrepancy.
	var header *block.Header
	header, err = pool.DetectComputeDiscrepancy()
	require.NoError(t, err, "DetectComputeDiscrepancy")
	require.EqualValues(t, &body.Header, header, "DD should return the same header")
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
	sk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	// Generate a dummy RAK.
	skRAK, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	// Generate a committee.
	cID := sk.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.Compute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Leader,
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
	var id signature.PublicKey
	childBlk := block.NewGenesisBlock(id, 0)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	rakSigBody := block.BatchSigMessage{
		PreviousBlock: *childBlk,
		IORoot:        parentBlk.Header.IORoot,
		StateRoot:     parentBlk.Header.StateRoot,
	}
	rakSig, err := signature.Sign(skRAK, roothash.RakSigContext, cbor.Marshal(rakSigBody))
	require.NoError(t, err, "Sign")
	body := ComputeBody{
		Header: parentBlk.Header,
		RakSig: rakSig.Signature,
	}

	// Generate dummy storage receipt.
	receipt := storage.MKVSReceiptBody{
		Version: 1,
		Roots:   body.Header.RootsForStorageReceipt(),
	}
	signedReceipt, err := signature.SignSigned(sk, storage.MKVSReceiptSignatureContext, &receipt)
	require.NoError(t, err, "SignSigned")
	body.Header.StorageReceipt = signedReceipt.Signature

	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// Adding a commitment should fail due to there being no NodeVerifyPolicy.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.Error(t, err, "AddComputeCommitment")
	// Configure a NodeVerifyPolicy that accepts all nodes.
	pool.NodeVerifyPolicy = func(*scheduler.CommitteeNode) error { return nil }

	// Adding a commitment not based on correct block should fail.
	err = pool.AddComputeCommitment(parentBlk, commit)
	require.Error(t, err, "AddComputeCommitment")

	// Adding a commitment should fail due to there being no StorageVerifyPolicy.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.Error(t, err, "AddComputeCommitment")
	// Configure a StorageVerifyPolicy that accepts all receipts.
	pool.StorageVerifyPolicy = func(signature.PublicKey) error { return nil }

	// There should not be enough compute commitments.
	err = pool.CheckEnoughComputeCommitments(true, false)
	require.Error(t, err, "CheckEnoughComputeCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")
	err = pool.CheckEnoughComputeCommitments(true, true)
	require.Error(t, err, "CheckEnoughComputeCommitments")
	require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")

	// Adding a commitment should succeed.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.NoError(t, err, "AddComputeCommitment")

	// Adding a commitment twice for the same node should fail.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.Error(t, err, "AddComputeCommitment(duplicate)")

	// There should be enough compute commitments.
	err = pool.CheckEnoughComputeCommitments(true, false)
	require.NoError(t, err, "CheckEnoughComputeCommitments")

	// There should be no discrepancy.
	var header *block.Header
	header, err = pool.DetectComputeDiscrepancy()
	require.NoError(t, err, "DetectComputeDiscrepancy")
	require.EqualValues(t, &body.Header, header, "DD should return the same header")
}

func TestPoolTwoCommitments(t *testing.T) {
	// Generate a non-TEE runtime.
	var rtID signature.PublicKey
	_ = rtID.UnmarshalHex("0000000000000000000000000000000000000000000000000000000000000000")

	rt := &registry.Runtime{
		ID:          rtID,
		TEEHardware: node.TEEHardwareInvalid,
	}

	// Generate commitment signing keys.
	sk1, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")
	sk2, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")
	sk3, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	// Generate a committee.
	c1ID := sk1.Public().ToMapKey()
	c2ID := sk2.Public().ToMapKey()
	c3ID := sk3.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.Compute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Leader,
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
	nodeInfo := map[signature.MapKey]NodeInfo{
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

	t.Run("NoDiscrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:             rt,
			Committee:           committee,
			NodeInfo:            nodeInfo,
			NodeVerifyPolicy:    func(*scheduler.CommitteeNode) error { return nil },
			StorageVerifyPolicy: func(signature.PublicKey) error { return nil },
		}

		// Generate a commitment.
		var id signature.PublicKey
		childBlk := block.NewGenesisBlock(id, 0)
		parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

		body := ComputeBody{
			Header: parentBlk.Header,
		}

		// Generate dummy storage receipt.
		receipt := storage.MKVSReceiptBody{
			Version: 1,
			Roots:   body.Header.RootsForStorageReceipt(),
		}
		signedReceipt, err := signature.SignSigned(sk1, storage.MKVSReceiptSignatureContext, &receipt)
		require.NoError(t, err, "SignSigned")
		body.Header.StorageReceipt = signedReceipt.Signature

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit2, err := SignComputeCommitment(sk2, &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughComputeCommitments(true, false)
		require.Error(t, err, "CheckEnoughComputeCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")
		err = pool.CheckEnoughComputeCommitments(true, true)
		require.Error(t, err, "CheckEnoughComputeCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddComputeCommitment(childBlk, commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments.
		err = pool.CheckEnoughComputeCommitments(true, false)
		require.NoError(t, err, "CheckEnoughComputeCommitments")

		// There should be no discrepancy.
		var header *block.Header
		header, err = pool.DetectComputeDiscrepancy()
		require.NoError(t, err, "DetectComputeDiscrepancy")
		require.EqualValues(t, &body.Header, header, "DD should return the same header")
	})

	t.Run("Discrepancy", func(t *testing.T) {
		// Create a pool.
		pool := Pool{
			Runtime:             rt,
			Committee:           committee,
			NodeInfo:            nodeInfo,
			NodeVerifyPolicy:    func(*scheduler.CommitteeNode) error { return nil },
			StorageVerifyPolicy: func(signature.PublicKey) error { return nil },
		}

		// Generate a commitment.
		var id signature.PublicKey
		childBlk := block.NewGenesisBlock(id, 0)
		parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

		body := ComputeBody{
			Header: parentBlk.Header,
		}

		// Generate dummy storage receipt.
		receipt := storage.MKVSReceiptBody{
			Version: 1,
			Roots:   body.Header.RootsForStorageReceipt(),
		}
		signedReceipt, err := signature.SignSigned(sk1, storage.MKVSReceiptSignatureContext, &receipt)
		require.NoError(t, err, "SignSigned")
		body.Header.StorageReceipt = signedReceipt.Signature

		commit1, err := SignComputeCommitment(sk1, &body)
		require.NoError(t, err, "SignComputeCommitment")

		commit3, err := SignComputeCommitment(sk3, &body)
		require.NoError(t, err, "SignComputeCommitment")

		correctHeader := body.Header

		body.Header.StateRoot.FromBytes([]byte("discrepancy"))
		commit2, err := SignComputeCommitment(sk2, &body)
		require.NoError(t, err, "SignComputeCommitment")

		// Adding commitment 1 should succeed.
		err = pool.AddComputeCommitment(childBlk, commit1)
		require.NoError(t, err, "AddComputeCommitment")

		// There should not be enough compute commitments.
		err = pool.CheckEnoughComputeCommitments(true, false)
		require.Error(t, err, "CheckEnoughComputeCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")
		err = pool.CheckEnoughComputeCommitments(true, true)
		require.Error(t, err, "CheckEnoughComputeCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")

		// Adding commitment 2 should succeed.
		err = pool.AddComputeCommitment(childBlk, commit2)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments.
		err = pool.CheckEnoughComputeCommitments(true, false)
		require.NoError(t, err, "CheckEnoughComputeCommitments")

		// There should be a discrepancy.
		_, err = pool.DetectComputeDiscrepancy()
		require.Error(t, err, "DetectComputeDiscrepancy")
		require.Equal(t, ErrDiscrepancyDetected, err)

		// There should not be enough compute commitments from backup workers.
		err = pool.CheckEnoughComputeCommitments(false, false)
		require.Error(t, err, "CheckEnoughComputeCommitments")
		require.Equal(t, ErrStillWaiting, err, "CheckEnoughComputeCommitments")

		// Resolve discrepancy with commit from backup worker.
		err = pool.AddComputeCommitment(childBlk, commit3)
		require.NoError(t, err, "AddComputeCommitment")

		// There should be enough compute commitments from backup workers.
		err = pool.CheckEnoughComputeCommitments(false, false)
		require.NoError(t, err, "CheckEnoughComputeCommitments")

		// Discrepancy resolution should succeed.
		var header *block.Header
		header, err = pool.ResolveComputeDiscrepancy()
		require.NoError(t, err, "ResolveComputeDiscrepancy")
		require.EqualValues(t, &correctHeader, header, "DR should return the same header")

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
	sk, err := signature.NewPrivateKey(rand.Reader)
	require.NoError(t, err, "NewPrivateKey")

	// Generate a committee.
	cID := sk.Public().ToMapKey()
	committee := &scheduler.Committee{
		Kind: scheduler.Compute,
		Members: []*scheduler.CommitteeNode{
			&scheduler.CommitteeNode{
				Role:      scheduler.Leader,
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
		Runtime:             rt,
		Committee:           committee,
		NodeInfo:            nodeInfo,
		NodeVerifyPolicy:    func(*scheduler.CommitteeNode) error { return nil },
		StorageVerifyPolicy: func(signature.PublicKey) error { return nil },
	}

	// Generate a commitment.
	var id signature.PublicKey
	childBlk := block.NewGenesisBlock(id, 0)
	parentBlk := block.NewEmptyBlock(childBlk, 1, block.Normal)

	body := ComputeBody{
		Header: parentBlk.Header,
	}

	// Generate dummy storage receipt.
	receipt := storage.MKVSReceiptBody{
		Version: 1,
		Roots:   body.Header.RootsForStorageReceipt(),
	}
	signedReceipt, err := signature.SignSigned(sk, storage.MKVSReceiptSignatureContext, &receipt)
	require.NoError(t, err, "SignSigned")
	body.Header.StorageReceipt = signedReceipt.Signature

	commit, err := SignComputeCommitment(sk, &body)
	require.NoError(t, err, "SignComputeCommitment")

	// Adding a commitment should succeed.
	err = pool.AddComputeCommitment(childBlk, commit)
	require.NoError(t, err, "AddComputeCommitment")

	m := cbor.Marshal(pool)
	var d Pool
	err = cbor.Unmarshal(m, &d)
	require.NoError(t, err)

	// There should be enough compute commitments.
	err = pool.CheckEnoughComputeCommitments(true, false)
	require.NoError(t, err, "CheckEnoughComputeCommitments")

	// There should be no discrepancy.
	var header *block.Header
	header, err = d.DetectComputeDiscrepancy()
	require.NoError(t, err, "DetectComputeDiscrepancy")
	require.EqualValues(t, &body.Header, header, "DD should return the same header")
}
