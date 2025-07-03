// Package merkle provides utilities for creating and verifying Merkle tree
// inclusion proofs over arbitrary byte slices and transactions.
package merkle

import (
	"crypto/sha256"

	cmtmerkle "github.com/cometbft/cometbft/crypto/merkle"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
)

// Proofs generates Merkle tree inclusion proofs for the given byte slices,
// where proofs[i] is the proof for byte slice items[i].
func Proofs(items [][]byte) (rootHash []byte, proofs [][]byte) {
	rootHash, tmproofs := cmtmerkle.ProofsFromByteSlices(items)
	proofs = encodeProofs(tmproofs)
	return rootHash, proofs
}

// ProofsForTransactions generates Merkle tree inclusion proofs for the given
// transactions, where proofs[i] is the proof for transaction txs[i].
//
// Note: The Merkle tree is built over the hashes of the transactions,
// not the raw transactions themselves.
func ProofsForTransactions(txs [][]byte) (rootHash []byte, proofs [][]byte) {
	hashes := hashTransactions(txs)
	return Proofs(hashes)
}

// Verify checks whether the given proof correctly verifies the item against
// the root hash.
func Verify(proof []byte, rootHash []byte, item []byte) error {
	tmproof, err := decodeProof(proof)
	if err != nil {
		return err
	}
	return tmproof.Verify(rootHash, item)
}

// VerifyTransaction checks whether the given proof correctly verifies
// the transaction against the root hash.
//
// Note: The Merkle proof is verified against the hash of the transaction,
// as the Merkle tree is built over transaction hashes.
func VerifyTransaction(proof []byte, rootHash []byte, tx []byte) error {
	hash := hashTransaction(tx)
	return Verify(proof, rootHash, hash)
}

// RootHash computes the Merkle root hash from the given byte slices.
func RootHash(items [][]byte) []byte {
	return cmtmerkle.HashFromByteSlices(items)
}

// RootHashOfTransactions computes the Merkle root hash from the given transactions.
//
// Note: The Merkle tree is built over the hashes of the transactions,
// not the raw transactions themselves.
func RootHashOfTransactions(txs [][]byte) []byte {
	hashes := hashTransactions(txs)
	return RootHash(hashes)
}

func hashTransaction(tx []byte) []byte {
	hash := sha256.Sum256(tx)
	return hash[:]
}

func hashTransactions(txs [][]byte) [][]byte {
	hashes := make([][]byte, 0, len(txs))
	for _, tx := range txs {
		hashes = append(hashes, hashTransaction(tx))
	}
	return hashes
}

func encodeProof(proof *cmtmerkle.Proof) []byte {
	return cbor.Marshal(proof)
}

func decodeProof(proof []byte) (*cmtmerkle.Proof, error) {
	var decoded cmtmerkle.Proof
	if err := cbor.Unmarshal(proof, &decoded); err != nil {
		return nil, err
	}
	return &decoded, nil
}

func encodeProofs(proofs []*cmtmerkle.Proof) [][]byte {
	encoded := make([][]byte, 0, len(proofs))
	for _, proof := range proofs {
		encoded = append(encoded, encodeProof(proof))
	}
	return encoded
}
