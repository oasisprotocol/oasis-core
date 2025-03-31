package merkle

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProofs(t *testing.T) {
	items := [][]byte{
		[]byte("foo"),
		[]byte("bar"),
		[]byte("baz"),
	}

	rootHash, proofs := Proofs(items)
	require.Len(t, proofs, len(items), "there should be one proof for every item")

	// Verify valid proofs.
	for i, item := range items {
		err := Verify(proofs[i], rootHash, item)
		require.NoError(t, err, "proof verification should succeed")
	}

	// Verify invalid proof.
	err := Verify(proofs[0], rootHash, []byte("invalid"))
	require.Error(t, err, "proof verification should fail")
}

func TestProofsForTransaction(t *testing.T) {
	txs := [][]byte{
		[]byte("tx1"),
		[]byte("tx2"),
		[]byte("tx3"),
	}

	rootHash, proofs := ProofsForTransactions(txs)
	require.Len(t, proofs, len(txs), "there should be one proof for every transaction")

	// Verify valid transaction proofs.
	for i, tx := range txs {
		err := VerifyTransaction(proofs[i], rootHash, tx)
		require.NoError(t, err, "transaction proof verification should succeed")
	}

	// Verify invalid transaction proof.
	err := VerifyTransaction(proofs[0], rootHash, []byte("invalid tx"))
	require.Error(t, err, "transaction proof verification should fail")
}

func TestEncodeDecodeProof(t *testing.T) {
	items := [][]byte{
		[]byte("foo"),
		[]byte("bar"),
		[]byte("baz"),
	}

	rootHash, proofs := Proofs(items)
	require.Len(t, proofs, len(items), "there should be one proof for every item")

	for i, originalProof := range proofs {
		// Decode the proof.
		decodedProof, err := decodeProof(originalProof)
		require.NoError(t, err, "decoding proof should succeed")

		// Encode it again.
		encodedProof := encodeProof(decodedProof)

		// The re-encoded proof should be equal to the original.
		require.Equal(t, originalProof, encodedProof, "encoded proof should match original")

		// Verify the decoded proof works.
		err = decodedProof.Verify(rootHash, items[i])
		require.NoError(t, err, "decoded proof verification should succeed")
	}

	// Test decoding invalid proof data.
	_, err := decodeProof([]byte("invalid data"))
	require.Error(t, err, "decoding invalid proof should fail")
}
