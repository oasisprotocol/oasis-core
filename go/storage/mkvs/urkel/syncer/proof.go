package syncer

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
)

const (
	// proofEntryFull is the proof entry type for full nodes.
	proofEntryFull byte = 0x01
	// proofEntryHash is the proof entry type for subtree hashes.
	proofEntryHash byte = 0x02
)

// Proof is a Merkle proof for a subtree.
type Proof struct {
	// UntrustedRoot is the root hash this proof is for. This should only be
	// used as a quick sanity check and proof verification MUST use an
	// independently obtained root hash as the prover can provide any root.
	UntrustedRoot hash.Hash `codec:"untrusted_root"`
	// Entries are the proof entries in pre-order traversal.
	Entries [][]byte `codec:"entries"`
}

// ProofBuilder is a Merkle proof builder.
type ProofBuilder struct {
	root     hash.Hash
	included map[hash.Hash]node.Node
}

// NewProofBuilder creates a new Merkle proof builder for the given root.
func NewProofBuilder(root hash.Hash) *ProofBuilder {
	return &ProofBuilder{
		root:     root,
		included: make(map[hash.Hash]node.Node),
	}
}

// Include adds a node to the set of included nodes.
//
// The node must be clean.
func (b *ProofBuilder) Include(n node.Node) {
	if n == nil {
		return
	}
	if !n.IsClean() {
		panic("proof: attempted to add a dirty node")
	}

	b.included[n.GetHash()] = n
}

// HasRoot returns true if the root node has already been included.
func (b *ProofBuilder) HasRoot() bool {
	return b.included[b.root] != nil
}

// GetRoot returns the root hash for this proof.
func (b *ProofBuilder) GetRoot() hash.Hash {
	return b.root
}

// Build tries to build the proof.
func (b *ProofBuilder) Build(ctx context.Context) (*Proof, error) {
	proof := Proof{
		UntrustedRoot: b.root,
	}
	if err := b.build(ctx, &proof, b.root); err != nil {
		return nil, err
	}
	return &proof, nil
}

func (b *ProofBuilder) build(ctx context.Context, proof *Proof, h hash.Hash) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}

	if h.IsEmpty() {
		// Append nil for empty nodes.
		proof.Entries = append(proof.Entries, nil)
		return nil
	}
	n := b.included[h]
	if n == nil {
		// Node is not included in this proof, just add hash of subtree.
		data, err := h.MarshalBinary()
		if err != nil {
			return err
		}
		proof.Entries = append(proof.Entries, append([]byte{proofEntryHash}, data...))
		return nil
	}

	// Pre-order traversal, add visited node.
	data, err := n.CompactMarshalBinary()
	if err != nil {
		return err
	}
	proof.Entries = append(proof.Entries, append([]byte{proofEntryFull}, data...))

	if nd, ok := n.(*node.InternalNode); ok {
		// Add leaf, left and right.
		for _, child := range []*node.Pointer{
			// NOTE: LeafNode is always included with the internal node.
			nd.Left,
			nd.Right,
		} {
			var childHash hash.Hash
			if child == nil {
				childHash.Empty()
			} else {
				childHash = child.Hash
			}

			if err := b.build(ctx, proof, childHash); err != nil {
				return err
			}
		}
	}

	return nil
}

// ProofVerifier enables verifying proofs returned by the ReadSyncer API.
type ProofVerifier struct {
}

// VerifyProof verifies a proof and generates an in-memory subtree representing
// the nodes which are included in the proof.
func (pv *ProofVerifier) VerifyProof(ctx context.Context, root hash.Hash, proof *Proof) (*node.Pointer, error) {
	// Sanity check that the proof is for the correct root (as otherwise it
	// makes no sense to verify the proof).
	if !proof.UntrustedRoot.Equal(&root) {
		return nil, fmt.Errorf("verifier: got proof for unexpected root (expected: %s got: %s)",
			root,
			proof.UntrustedRoot,
		)
	}
	if len(proof.Entries) == 0 {
		return nil, errors.New("verifier: empty proof")
	}

	_, rootNode, err := pv.verifyProof(ctx, proof, 0)
	if err != nil {
		return nil, err
	}
	rootNodeHash := rootNode.GetHash()
	if rootNodeHash.IsEmpty() {
		// Make sure that in case the root node is empty we always return nil
		// and not a pointer that represents nil.
		rootNode = nil
	}

	if !rootNodeHash.Equal(&root) {
		return nil, fmt.Errorf("verifier: bad root (expected: %s got: %s)",
			root,
			rootNode.Hash,
		)
	}
	return rootNode, nil
}

func (pv *ProofVerifier) verifyProof(ctx context.Context, proof *Proof, idx int) (int, *node.Pointer, error) {
	if ctx.Err() != nil {
		return -1, nil, ctx.Err()
	}
	if idx >= len(proof.Entries) {
		return -1, nil, errors.New("verifier: malformed proof")
	}

	entry := proof.Entries[idx]
	if entry == nil {
		return idx + 1, nil, nil
	}

	switch entry[0] {
	case proofEntryFull:
		// Full node.
		n, err := node.UnmarshalBinary(entry[1:])
		if err != nil {
			return -1, nil, err
		}

		// For internal nodes, also decode children.
		pos := idx + 1
		if nd, ok := n.(*node.InternalNode); ok {
			// Left.
			pos, nd.Left, err = pv.verifyProof(ctx, proof, pos)
			if err != nil {
				return -1, nil, err
			}
			// Right.
			pos, nd.Right, err = pv.verifyProof(ctx, proof, pos)
			if err != nil {
				return -1, nil, err
			}

			// Recompute hash as hashes were not recomputed for compact encoding.
			nd.UpdateHash()
		}

		return pos, &node.Pointer{Clean: true, Hash: n.GetHash(), Node: n}, nil
	case proofEntryHash:
		// Hash of a node.
		var h hash.Hash
		if err := h.UnmarshalBinary(entry[1:]); err != nil {
			return -1, nil, err
		}

		return idx + 1, &node.Pointer{Clean: true, Hash: h}, nil
	default:
		return -1, nil, fmt.Errorf("verifier: unexpected entry in proof (%x)", entry[0])
	}
}
