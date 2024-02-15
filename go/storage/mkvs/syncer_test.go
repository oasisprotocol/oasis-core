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

func TestProofV0(t *testing.T) {
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
	builder := syncer.NewProofBuilderV0(rootHash, rootHash)
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

func TestProofV1(t *testing.T) {
	require := require.New(t)

	// Build a simple in-memory Merkle tree.
	ctx := context.Background()
	// Use 11 keys so that "key 1" is prefix of "key 10".
	keys, values := generateKeyValuePairsEx("", 11)
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

	rootIncludedProof, err := builder.Build(ctx)
	require.NoError(err, "Build should not fail")
	require.EqualValues(rootIncludedProof.UntrustedRoot, rootHash, "UntrustedRoot should be correct")
	require.Len(rootIncludedProof.Entries, 4, "proof should only contain the root and three child hashes")

	// Include root.left node.
	rootIntNode := rootNode.(*node.InternalNode)
	leftNode1 := rootIntNode.Left.Node
	builder.Include(leftNode1)

	proof, err := builder.Build(ctx)
	require.NoError(err, "Build should not fail")
	// Pre-order: root(full), root.leaf(nil), root.left(full), root.left.leaf(full), root.left.left(hash), root.left.right(hash), root.right(hash)
	require.Len(proof.Entries, 7, "proof should only contain the correct amount of nodes")
	require.EqualValues(proof.Entries[0][0], 0x01, "first entry should be a full node")
	require.Empty(proof.Entries[1], "second entry should be a nil node")
	require.EqualValues(proof.Entries[2][0], 0x01, "third entry should be a full node")
	require.Empty(proof.Entries[3], "fourth entry should be a nil node")
	require.EqualValues(proof.Entries[4][0], 0x02, "fifth entry should be a hash")
	require.EqualValues(proof.Entries[5][0], 0x02, "sixth entry should be a hash")
	require.EqualValues(proof.Entries[6][0], 0x02, "seventh entry should be a hash")

	decNode, err := node.UnmarshalBinary(proof.Entries[0][1:])
	require.NoError(err, "first entry should unmarshal as a node")
	decIntNode, ok := decNode.(*node.InternalNode)
	require.True(ok, "first entry must be an internal node (root)")
	require.Nil(decIntNode.Left, "first entry must use compact encoding")
	require.Nil(decIntNode.Right, "first entry must use compact encoding")
	require.Nil(decIntNode.LeafNode, "first entry must use compact encoding")

	// Second entry is a nil node. (root.leaf).

	decNode, err = node.UnmarshalBinary(proof.Entries[2][1:])
	require.NoError(err, "third entry should unmarshal as a node")
	decIntNode, ok = decNode.(*node.InternalNode)
	require.True(ok, "third entry must be an internal node (root.left)")
	require.Nil(decIntNode.Left, "third entry must use compact encoding")
	require.Nil(decIntNode.Right, "third entry must use compact encoding")
	require.Nil(decIntNode.LeafNode, "third entry must use compact encoding")

	leftIntNode1 := leftNode1.(*node.InternalNode)
	require.Nil(leftIntNode1.LeafNode, "fourth entry should be correct (root.left.leaf=nil)")
	require.EqualValues(leftIntNode1.Left.Hash[:], proof.Entries[4][1:], "fifth entry hash should be correct (root.left.left)")
	require.EqualValues(leftIntNode1.Right.Hash[:], proof.Entries[5][1:], "sixth entry hash should be correct (root.left.left)")
	require.EqualValues(rootIntNode.Right.Hash[:], proof.Entries[6][1:], "seventh entry hash should be correct (root.right)")

	// Proofs should be stable.
	// NOTE: Ensure these match the test in runtime/src/storage/mkvs/sync/proof.rs.
	// TODO: Provide multiple test vectors.
	// Root only proof.
	require.EqualValues(
		"o2F2AWdlbnRyaWVzgVghAqlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpFbnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
		base64.StdEncoding.EncodeToString(cbor.Marshal(rootOnlyProof)),
	)
	// Root included proof.
	require.EqualValues(
		"o2F2AWdlbnRyaWVzhEoBASQAa2V5IDAC9lghAhQ6RgqFtADx+B6VKE0CVRrfDHmwgZwU3ewsj4gswWv+WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
		base64.StdEncoding.EncodeToString(cbor.Marshal(rootIncludedProof)),
	)
	// Root and root.left included proof.
	require.EqualValues(
		"o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
		base64.StdEncoding.EncodeToString(cbor.Marshal(proof)),
	)
	testVectorRootHash := rootHash.String()
	require.EqualValues("a940b9ded7621a2b10497c846f46dc7778397979551d71bee2c07a9319e6aa45", testVectorRootHash)

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

	// Different leaf hash element.
	corrupted = copyProof(proof)
	corrupted.Entries[1] = bogusHash[:]
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
	corrupted.Entries[4][0] = 0xaa
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")

	// Missing elements.
	corrupted = copyProof(proof)
	corrupted.Entries = corrupted.Entries[:3]
	_, err = pv.VerifyProof(ctx, rootHash, corrupted)
	require.Error(err, "VerifyProof should fail with invalid proof")

	// Test with non-nil leaf node on the path.
	builder = syncer.NewProofBuilder(rootHash, rootHash)

	// Include root node.
	builder.Include(rootNode)

	// Include root.left node.
	rootIntNode = rootNode.(*node.InternalNode)
	leftNode1 = rootIntNode.Left.Node
	builder.Include(leftNode1)

	// Include root.left.left node.
	left2Node := leftNode1.(*node.InternalNode).Left.Node
	builder.Include(left2Node)

	// Include root.left.left.left node.
	left3Node := left2Node.(*node.InternalNode).Left.Node
	builder.Include(left3Node)

	// Include root.left.left.left.right node.
	left3RightNode := left3Node.(*node.InternalNode).Right.Node
	builder.Include(left3RightNode)

	// Ensure this is the expected node (it should have non-nil leaf and left, right is nil).
	require.NotNil(left3RightNode.(*node.InternalNode).LeafNode)
	require.NotNil(left3RightNode.(*node.InternalNode).Left)
	require.Nil(left3RightNode.(*node.InternalNode).Right)

	// Include root.left.left.left.right.left leaf node.
	bottomNode := left3RightNode.(*node.InternalNode).Left.Node
	builder.Include(bottomNode)

	proof, err = builder.Build(ctx)
	require.NoError(err, "Build should not fail")

	// Pre-order: root(full), root.leaf(nil),
	//            root.left(full), root.left.leaf(nil),
	//            root.left.left(full), root.left.left.leaf(nil),
	//            root.left.left.left(full), root.left.left.left.leaf(nil),
	//            root.left.left.left.left(hash), root.left.left.left.right(full), (10th entry->) root.left.left.left.right.leaf(hash),
	//            root.left.left.left.right.left(full)  <- target leaf node,
	//            root.left.left.left.right.right(hash=nil),
	//            root.left.left.left.right(hash),
	//            root.left.left.right(hash),
	//            root.left.right(hash),
	//            root.right(hash)
	require.Len(proof.Entries, 16, "proof should only contain the correct amount of nodes")
	// Ensure 9th entry is the left3RightNode.Leaf, which should be the hash.
	require.EqualValues(left3RightNode.(*node.InternalNode).LeafNode.Hash[:], proof.Entries[10][1:], "10th entry hash should be correct")

	// Ensure 9th entry is the left3RightNode, which is a full node, without leaf.
	decNode, err = node.UnmarshalBinary(proof.Entries[9][1:])
	require.NoError(err, "9th entry should unmarshal as a node")
	decIntNode, ok = decNode.(*node.InternalNode)
	require.True(ok, "9th entry must be an internal node (root.left.left.left.right)")
	require.Nil(decIntNode.Left, "9th entry must use compact encoding")
	require.Nil(decIntNode.Right, "9th entry must use compact encoding")
	require.Nil(decIntNode.LeafNode, "9th entry must use compact encoding")

	require.EqualValues(
		"o2F2AWdlbnRyaWVzkEoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lghAlF8/rp9QOAd1qSchhUxDtVkpmnze6sjz5IfFhdOuaypRgEBAQCAAlghAldMzQwgHh/Ecm+rF+i31AnOgFYBipBAlcx5Tf5l4yW+VgEABgBrZXkgMTAIAAAAdmFsdWUgMTD2WCECDnYjQhsAp5fD+gf0W5YYFY6CnGURrEETtJvJp+ijH4xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
		base64.StdEncoding.EncodeToString(cbor.Marshal(proof)),
	)
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
	keys, values := generateKeyValuePairsEx("", 11)
	var ns common.Namespace

	tree := New(nil, nil, node.RootTypeState).(*tree)
	for i, key := range keys {
		err := tree.Insert(ctx, key, values[i])
		require.NoError(err, "Insert")
	}
	_, roothash, err := tree.Commit(ctx, ns, 0)
	require.NoError(err, "Commit")

	for _, tc := range []struct {
		proofVersion    uint16
		includeSiblings bool
		proofs          []string
	}{
		{
			proofVersion:    0,
			includeSiblings: false,
			proofs: []string{
				// 0.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJGAQEBAAACVAEABQBrZXkgMAcAAAB2YWx1ZSAwWCECU7w+1iQZMSDfThv/P9y/igfr4FFonzyVrJ/tWAiXfFNYIQIOdiNCGwCnl8P6B/RblhgVjoKcZRGsQRO0m8mn6KMfjFghAqbCZ5IzpyIHOPsn76bKgnCGB4eXpXdYTTFk0+2qwHxxWCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 1.
				"omdlbnRyaWVzi0oBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJGAQEBAAACWCECUXz+un1A4B3WpJyGFTEO1WSmafN7qyPPkh8WF065rKlYGAEBAQCAAAUAa2V5IDEHAAAAdmFsdWUgMVghAm2EG0dH85+yEl5rdT67+D59/gbjHB9qDtnCcv0kkuje9lghAg52I0IbAKeXw/oH9FuWGBWOgpxlEaxBE7Sbyafoox+MWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
				// 2.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJYIQLnu/nMm00WQo9ZxRbRFM/hVtoTov4Phs3vIQ/6jS/29kYBAQEAgAJUAQAFAGtleSAyBwAAAHZhbHVlIDJYIQIm0h28G9KzZWHhnWCFjfO8e8rwmygGa3f50GlEI10D/FghAqbCZ5IzpyIHOPsn76bKgnCGB4eXpXdYTTFk0+2qwHxxWCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 3.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJYIQLnu/nMm00WQo9ZxRbRFM/hVtoTov4Phs3vIQ/6jS/29kYBAQEAgAJYIQKhiPVO61Qd4HUrRqdPWFG2zwAo7DwB8S2f3rdcxXFXXFQBAAUAa2V5IDMHAAAAdmFsdWUgM1ghAqbCZ5IzpyIHOPsn76bKgnCGB4eXpXdYTTFk0+2qwHxxWCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 4.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAlghAvjq0kjwgqPf0F0LeyLLpwKfnlKjJ3SgQrtDXBh8eB64RgEBAQCAAkYBAQEAAAJUAQAFAGtleSA0BwAAAHZhbHVlIDRYIQLu4RLQdOG/CJESxLo4oYM6h00aftYYLcFMElIsEiwl/VghArfWCo9vCnfczvIpvZVKjt4HyniNlmZgacnueN4UEYe1WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 5.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAlghAvjq0kjwgqPf0F0LeyLLpwKfnlKjJ3SgQrtDXBh8eB64RgEBAQCAAkYBAQEAAAJYIQLGCmUSnaMGinOcyqgElnV7MITsg7YFvkKovKkL4iISGlQBAAUAa2V5IDUHAAAAdmFsdWUgNVghArfWCo9vCnfczvIpvZVKjt4HyniNlmZgacnueN4UEYe1WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 6.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAlghAvjq0kjwgqPf0F0LeyLLpwKfnlKjJ3SgQrtDXBh8eB64RgEBAQCAAlghAivLwJbWkwZ8nROaPHGxpfthiG8vqyPbvzhkEEX793dIRgEBAQCAAlQBAAUAa2V5IDYHAAAAdmFsdWUgNlghAr3oK8Bozi85F6ot74Cg7opqNgVmJSwDK9KLysSAKVTsWCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 7.
				"omdlbnRyaWVziUoBASQAa2V5IDACRgEBAQAAAlghAvjq0kjwgqPf0F0LeyLLpwKfnlKjJ3SgQrtDXBh8eB64RgEBAQCAAlghAivLwJbWkwZ8nROaPHGxpfthiG8vqyPbvzhkEEX793dIRgEBAQCAAlghAgI8X2yVJ8szMIqkgZQoValdarl3F9V197rB8ZbrGN6vVAEABQBrZXkgNwcAAAB2YWx1ZSA3WCEC4TUy1kW5LNUQX+drpZ5Tkzvuw+RGTTGBc08fFOOrAp5udW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 8.
				"omdlbnRyaWVzhUoBASQAa2V5IDACWCECFDpGCoW0APH4HpUoTQJVGt8MebCBnBTd7CyPiCzBa/5GAQEDAIACVAEABQBrZXkgOAcAAAB2YWx1ZSA4WCECDXMyfNOnjK/k/4hrCZqPPyUBV2bY8tf5PmrNFfRXX1RudW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 9.
				"omdlbnRyaWVzhUoBASQAa2V5IDACWCECFDpGCoW0APH4HpUoTQJVGt8MebCBnBTd7CyPiCzBa/5GAQEDAIACWCECMMFu3slwotsl8hQsxQ/VPkrMtYMEsIrJAUH5PvSglANUAQAFAGtleSA5BwAAAHZhbHVlIDludW50cnVzdGVkX3Jvb3RYIKlAud7XYhorEEl8hG9G3Hd4OXl5VR1xvuLAepMZ5qpF",
				// 10.
				"omdlbnRyaWVzi0oBASQAa2V5IDACRgEBAQAAAkYBAQEAAAJGAQEBAAACWCECUXz+un1A4B3WpJyGFTEO1WSmafN7qyPPkh8WF065rKlYGAEBAQCAAAUAa2V5IDEHAAAAdmFsdWUgMVYBAAYAa2V5IDEwCAAAAHZhbHVlIDEw9lghAg52I0IbAKeXw/oH9FuWGBWOgpxlEaxBE7Sbyafoox+MWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
			},
		},
		{
			proofVersion:    1,
			includeSiblings: false,
			proofs: []string{
				// 0.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lQBAAUAa2V5IDAHAAAAdmFsdWUgMFghAlO8PtYkGTEg304b/z/cv4oH6+BRaJ88layf7VgIl3xTWCECDnYjQhsAp5fD+gf0W5YYFY6CnGURrEETtJvJp+ijH4xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 1.
				"o2F2AWdlbnRyaWVzkEoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lghAlF8/rp9QOAd1qSchhUxDtVkpmnze6sjz5IfFhdOuaypRgEBAQCAAlQBAAUAa2V5IDEHAAAAdmFsdWUgMVghAm2EG0dH85+yEl5rdT67+D59/gbjHB9qDtnCcv0kkuje9lghAg52I0IbAKeXw/oH9FuWGBWOgpxlEaxBE7Sbyafoox+MWCECpsJnkjOnIgc4+yfvpsqCcIYHh5eld1hNMWTT7arAfHFYIQLhNTLWRbks1RBf52ulnlOTO+7D5EZNMYFzTx8U46sCnm51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
				// 2.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZYIQLnu/nMm00WQo9ZxRbRFM/hVtoTov4Phs3vIQ/6jS/29kYBAQEAgAL2VAEABQBrZXkgMgcAAAB2YWx1ZSAyWCECJtIdvBvSs2Vh4Z1ghY3zvHvK8JsoBmt3+dBpRCNdA/xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 3.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZYIQLnu/nMm00WQo9ZxRbRFM/hVtoTov4Phs3vIQ/6jS/29kYBAQEAgAL2WCECoYj1TutUHeB1K0anT1hRts8AKOw8AfEtn963XMVxV1xUAQAFAGtleSAzBwAAAHZhbHVlIDNYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 4.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9kYBAQEAAAL2VAEABQBrZXkgNAcAAAB2YWx1ZSA0WCEC7uES0HThvwiREsS6OKGDOodNGn7WGC3BTBJSLBIsJf1YIQK31gqPbwp33M7yKb2VSo7eB8p4jZZmYGnJ7njeFBGHtVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 5.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9kYBAQEAAAL2WCECxgplEp2jBopznMqoBJZ1ezCE7IO2Bb5CqLypC+IiEhpUAQAFAGtleSA1BwAAAHZhbHVlIDVYIQK31gqPbwp33M7yKb2VSo7eB8p4jZZmYGnJ7njeFBGHtVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 6.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9lghAivLwJbWkwZ8nROaPHGxpfthiG8vqyPbvzhkEEX793dIRgEBAQCAAvZUAQAFAGtleSA2BwAAAHZhbHVlIDZYIQK96CvAaM4vOReqLe+AoO6KajYFZiUsAyvSi8rEgClU7FghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 7.
				"o2F2AWdlbnRyaWVzjUoBASQAa2V5IDAC9kYBAQEAAAL2WCEC+OrSSPCCo9/QXQt7IsunAp+eUqMndKBCu0NcGHx4HrhGAQEBAIAC9lghAivLwJbWkwZ8nROaPHGxpfthiG8vqyPbvzhkEEX793dIRgEBAQCAAvZYIQICPF9slSfLMzCKpIGUKFWpXWq5dxfVdfe6wfGW6xjer1QBAAUAa2V5IDcHAAAAdmFsdWUgN1ghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
				// 8.
				"o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9lghAhQ6RgqFtADx+B6VKE0CVRrfDHmwgZwU3ewsj4gswWv+RgEBAwCAAvZUAQAFAGtleSA4BwAAAHZhbHVlIDhYIQINczJ806eMr+T/iGsJmo8/JQFXZtjy1/k+as0V9FdfVG51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
				// 9.
				"o2F2AWdlbnRyaWVzh0oBASQAa2V5IDAC9lghAhQ6RgqFtADx+B6VKE0CVRrfDHmwgZwU3ewsj4gswWv+RgEBAwCAAvZYIQIwwW7eyXCi2yXyFCzFD9U+Ssy1gwSwiskBQfk+9KCUA1QBAAUAa2V5IDkHAAAAdmFsdWUgOW51bnRydXN0ZWRfcm9vdFggqUC53tdiGisQSXyEb0bcd3g5eXlVHXG+4sB6kxnmqkU=",
				// 10.
				"o2F2AWdlbnRyaWVzkEoBASQAa2V5IDAC9kYBAQEAAAL2RgEBAQAAAvZGAQEBAAAC9lghAlF8/rp9QOAd1qSchhUxDtVkpmnze6sjz5IfFhdOuaypRgEBAQCAAlghAldMzQwgHh/Ecm+rF+i31AnOgFYBipBAlcx5Tf5l4yW+VgEABgBrZXkgMTAIAAAAdmFsdWUgMTD2WCECDnYjQhsAp5fD+gf0W5YYFY6CnGURrEETtJvJp+ijH4xYIQKmwmeSM6ciBzj7J++myoJwhgeHl6V3WE0xZNPtqsB8cVghAuE1MtZFuSzVEF/na6WeU5M77sPkRk0xgXNPHxTjqwKebnVudHJ1c3RlZF9yb290WCCpQLne12IaKxBJfIRvRtx3eDl5eVUdcb7iwHqTGeaqRQ==",
			},
		},
	} {
		// Ensure SyncGet returns expected proofs for all keys.

		for i, key := range keys {
			resp, err := tree.SyncGet(ctx, &syncer.GetRequest{
				Tree: syncer.TreeID{
					Root:     node.Root{Namespace: ns, Version: 0, Hash: roothash, Type: node.RootTypeState},
					Position: roothash,
				},
				Key:             key,
				IncludeSiblings: tc.includeSiblings,
				ProofVersion:    tc.proofVersion,
			})
			require.NoError(err, "SyncGet keys[%d], version: %d", i, tc.proofVersion)
			require.EqualValues(

				tc.proofs[i],
				base64.StdEncoding.EncodeToString(cbor.Marshal(resp.Proof)),
				"keys[%d], version: %d", i, tc.proofVersion,
			)
			// Proof should verify.
			var pv syncer.ProofVerifier
			_, err = pv.VerifyProof(ctx, roothash, &resp.Proof)
			require.NoError(err, "VerifyProof should not fail with a valid proof: keys[%d], version: %d", i, tc.proofVersion)
		}
	}
}
