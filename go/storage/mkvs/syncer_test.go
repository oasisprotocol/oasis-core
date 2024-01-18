package mkvs

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

func TestProof(t *testing.T) {
	require := require.New(t)

	// Build a simple in-memory Merkle tree.
	ctx := context.Background()
	keys, values := generateKeyValuePairsEx("", 10)
	var ns common.Namespace

	tree := New(nil, nil, node.RootTypeState).(*tree)
	for i, key := range keys {
		err := tree.Insert(ctx, key, values[i])
		require.NoError(err, "Insert")
	}
	_, rootHash, err := tree.Commit(ctx, ns, 0)
	require.NoError(err, "Commit")

	// Create a Merkle proof, starting at the root node.
	builder := syncer.NewProofBuilder(rootHash, rootHash)
	require.False(builder.HasSubtreeRoot(), "HasSubtreeRoot should return false")
	require.EqualValues(rootHash, builder.GetSubtreeRoot(), "GetSubtreeRoot should return correct root")

	rootOnlyProof, err := builder.Build(ctx)
	require.NoError(err, "Build should not fail without a root present")

	// Including a nil node should not panic.
	builder.Include(nil)

	// Include root node.
	rootNode := tree.cache.pendingRoot.Node
	builder.Include(rootNode)
	require.True(builder.HasSubtreeRoot(), "HasRoot should return true after root included")

	proof, err := builder.Build(ctx)
	require.NoError(err, "Build should not fail")
	require.EqualValues(proof.UntrustedRoot, rootHash, "UntrustedRoot should be correct")
	require.Len(proof.Entries, 3, "proof should only contain the root and two child hashes")

	// Include root.left node.
	rootIntNode := rootNode.(*node.InternalNode)
	leftNode1 := rootIntNode.Left.Node
	builder.Include(leftNode1)

	proof, err = builder.Build(ctx)
	require.NoError(err, "Build should not fail")
	// Pre-order: root(full), root.left(full), root.left.left(hash), root.left.right(hash), root.right(hash)
	require.Len(proof.Entries, 5, "proof should only contain the correct amount of nodes")
	require.EqualValues(proof.Entries[0][0], 0x01, "first entry should be a full node")
	require.EqualValues(proof.Entries[1][0], 0x01, "second entry should be a full node")
	require.EqualValues(proof.Entries[2][0], 0x02, "third entry should be a hash")
	require.EqualValues(proof.Entries[3][0], 0x02, "fourth entry should be a hash")
	require.EqualValues(proof.Entries[4][0], 0x02, "fifth entry should be a hash")

	decNode, err := node.UnmarshalBinary(proof.Entries[0][1:])
	require.NoError(err, "first entry should unmarshal as a node")
	decIntNode, ok := decNode.(*node.InternalNode)
	require.True(ok, "first entry must be an internal node (root)")
	require.Nil(decIntNode.Left, "first entry must use compact encoding")
	require.Nil(decIntNode.Right, "first entry must use compact encoding")

	decNode, err = node.UnmarshalBinary(proof.Entries[1][1:])
	require.NoError(err, "second entry should unmarshal as a node")
	decIntNode, ok = decNode.(*node.InternalNode)
	require.True(ok, "second entry must be an internal node (root.left)")
	require.Nil(decIntNode.Left, "second entry must use compact encoding")
	require.Nil(decIntNode.Right, "second entry must use compact encoding")

	leftIntNode1 := leftNode1.(*node.InternalNode)
	require.EqualValues(leftIntNode1.Left.Hash[:], proof.Entries[2][1:], "third entry hash should be correct (root.left.left)")
	require.EqualValues(leftIntNode1.Right.Hash[:], proof.Entries[3][1:], "fourth entry hash should be correct (root.left.left)")
	require.EqualValues(rootIntNode.Right.Hash[:], proof.Entries[4][1:], "fifth entry hash should be correct (root.right)")

	// Proofs should be stable.
	// NOTE: Ensure these match the test in runtime/src/storage/mkvs/sync/proof.rs.
	// TODO: Provide multiple test vectors.
	// Root only proof.
	require.EqualValues(
		"omdlbnRyaWVzgVghAlnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYTbnVudHJ1c3RlZF9yb290WCBZ5nwv3Ai44Q3Qi7a47+YU/Mll7LiWJfl/F/h/BxBGEw==",
		base64.StdEncoding.EncodeToString(cbor.Marshal(rootOnlyProof)),
	)
	// Root and root.left proof.
	require.EqualValues(
		"omdlbnRyaWVzhUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggWeZ8L9wIuOEN0Iu2uO/mFPzJZey4liX5fxf4fwcQRhM=",
		base64.StdEncoding.EncodeToString(cbor.Marshal(proof)),
	)
	testVectorRootHash := rootHash.String()
	require.EqualValues("59e67c2fdc08b8e10dd08bb6b8efe614fcc965ecb89625f97f17f87f07104613", testVectorRootHash)

	// Proof should verify.
	var pv syncer.ProofVerifier
	_, err = pv.VerifyProof(ctx, rootHash, proof)
	require.NoError(err, "VerifyProof should not fail with a valid proof")

	// Proof with only the root node should verify.
	_, err = pv.VerifyProof(ctx, rootHash, rootOnlyProof)
	require.NoError(err, "VerifyProof should not fail on a proof with only the root node")

	// Empty root proof should verify.
	var emptyHash hash.Hash
	emptyHash.Empty()
	builder = syncer.NewProofBuilder(emptyHash, emptyHash)
	emptyRootProof, err := builder.Build(ctx)
	require.NoError(err, "Build should not fail for an empty root")
	emptyRootPtr, err := pv.VerifyProof(ctx, emptyHash, emptyRootProof)
	require.NoError(err, "VerifyProof should not fail with a valid proof for an empty root")
	require.Nil(emptyRootPtr, "VerifyProof should return nil pointer for an empty root")

	// Invalid proofs should not verify.

	// Empty proof.
	var emptyProof syncer.Proof
	_, err = pv.VerifyProof(ctx, rootHash, &emptyProof)
	require.Error(err, "VerifyProof should fail with empty proof")

	// Different root.
	bogusHash := hash.NewFromBytes([]byte("i am a bogus hash"))
	_, err = pv.VerifyProof(ctx, bogusHash, proof)
	require.Error(err, "VerifyProof should fail with proof for a different root")

	// Different hash element.
	corrupted := copyProof(proof)
	corrupted.Entries[4][10] = 0x00
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")

	// Corrupted full node.
	corrupted = copyProof(proof)
	corrupted.Entries[0] = corrupted.Entries[0][:3]
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")

	// Corrupted hash.
	corrupted = copyProof(proof)
	corrupted.Entries[2] = corrupted.Entries[2][:3]
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")

	// Corrupted proof element type.
	corrupted = copyProof(proof)
	corrupted.Entries[3][0] = 0xaa
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")

	// Missing elements.
	corrupted = copyProof(proof)
	corrupted.Entries = corrupted.Entries[:3]
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")
}

func copyProof(p *syncer.Proof) *syncer.Proof {
	if p == nil {
		return nil
	}

	result := *p
	result.Entries = append([][]byte{}, result.Entries...)
	for i, e := range result.Entries {
		result.Entries[i] = append([]byte{}, e...)
	}
	return &result
}

func TestTreeProofs(t *testing.T) {
	// NOTE: Ensure this matches the test in runtime/src/storage/mkvs/sync/proof.rs.
	require := require.New(t)

	// Build a simple in-memory Merkle tree.
	ctx := context.Background()
	keys, values := generateKeyValuePairsEx("", 10)
	var ns common.Namespace

	tree := New(nil, nil, node.RootTypeState).(*tree)
	for i, key := range keys {
		err := tree.Insert(ctx, key, values[i])
		require.NoError(err, "Insert")
	}
	_, roothash, err := tree.Commit(ctx, ns, 0)
	require.NoError(err, "Commit")

	// Ensure SyncGet returns expected proofs.
	// Keys[0].
	resp, err := tree.SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root:     node.Root{Namespace: ns, Version: 0, Hash: roothash, Type: node.RootTypeState},
			Position: roothash,
		},
		Key:             keys[0],
		IncludeSiblings: false,
	})
	require.NoError(err, "SyncGet keys[0]")
	require.EqualValues(
		"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJGAQEBAAACVAEABQBrZXkgMAcAAAB2YWx1ZSAwWCECV0zNDCAeH8Ryb6sX6LfUCc6AVgGKkECVzHlN/mXjJb5YIQIOdiNCGwCnl8P6B/RblhgVjoKcZRGsQRO0m8mn6KMfjFghAqbCZ5IzpyIHOPsn76bKgnCGB4eXpXdYTTFk0+2qwHxxWCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIFnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYT",
		base64.StdEncoding.EncodeToString(cbor.Marshal(resp.Proof)),
	)

	// Keys[5].
	resp, err = tree.SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root:     node.Root{Namespace: ns, Version: 0, Hash: roothash, Type: node.RootTypeState},
			Position: roothash,
		},
		Key:             keys[5],
		IncludeSiblings: false,
	})
	require.NoError(err, "SyncGet keys[5]")
	require.EqualValues(
		"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAlghAsFltYRhD4dAwHOdOmEigY1r02pJH6InhiibKlh9neYlRgEBAQCAAkYBAQEAAAJYIQLGCmUSnaMGinOcyqgElnV7MITsg7YFvkKovKkL4iISGlQBAAUAa2V5IDUHAAAAdmFsdWUgNVghArfWCo9vCnfczvIpvZVKjt4HyniNlmZgacnueN4UEYe1WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIFnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYT",
		base64.StdEncoding.EncodeToString(cbor.Marshal(resp.Proof)),
	)

	// Key[9].
	resp, err = tree.SyncGet(ctx, &syncer.GetRequest{
		Tree: syncer.TreeID{
			Root:     node.Root{Namespace: ns, Version: 0, Hash: roothash, Type: node.RootTypeState},
			Position: roothash,
		},
		Key:             keys[9],
		IncludeSiblings: false,
	})
	require.NoError(err, "SyncGet keys[9]")
	require.EqualValues(
		"omdlbnRyaWVzhUoBASQAa2V5IDACWCECJueKTLbwFMAiJitvfP3+tOruv3XChOjYSpH3U9/Xo/1GAQEDAIACWCECMMFu3slwotsl8hQsxQ/VPkrMtYMEsIrJAUH5PvSglANUAQAFAGtleSA5BwAAAHZhbHVlIDludW50cnVzdGVkX3Jvb3RYIFnmfC/cCLjhDdCLtrjv5hT8yWXsuJYl+X8X+H8HEEYT",
		base64.StdEncoding.EncodeToString(cbor.Marshal(resp.Proof)),
	)
}
