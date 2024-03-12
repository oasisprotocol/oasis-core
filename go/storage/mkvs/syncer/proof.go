package syncer

import (
	"context"
	"errors"
	"fmt"

	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

const (
	// MinimumProofVersion is the minimum supported proof version.
	MinimumProofVersion = 0
	// LatestProofVersion is the latest supported proof version.
	LatestProofVersion = 1
)

const (
	// proofEntryFull is the proof entry type for full nodes.
	proofEntryFull byte = 0x01
	// proofEntryHash is the proof entry type for subtree hashes.
	proofEntryHash byte = 0x02
)

// Proof is a Merkle proof for a subtree.
type Proof struct {
	// V is the proof version.
	//
	// Similar to `cbor.Versioned` but the version is omitted if it is 0.
	// We don't use `cbor.Versioned` since we want version 0 proofs to be
	// backwards compatible with the old structure which was not versioned.
	//
	// Version 0:
	// Initial format.
	//
	// Version 1 change:
	// Leaf nodes are included separately, as children. In version 0 the leaf node was
	// serialized within the internal node.  The rationale behind this change is to eliminate
	// the need to serialize all leaf nodes on the path when proving the existence of a
	// specific value.
	V uint16 `json:"v,omitempty"`

	// UntrustedRoot is the root hash this proof is for. This should only be
	// used as a quick sanity check and proof verification MUST use an
	// independently obtained root hash as the prover can provide any root.
	UntrustedRoot hash.Hash `json:"untrusted_root"`
	// Entries are the proof entries in pre-order traversal.
	Entries [][]byte `json:"entries"`
}

type proofNode struct {
	serialized []byte
	children   []hash.Hash
}

// ProofBuilder is a Merkle proof builder.
type ProofBuilder struct {
	proofVersion uint16
	root         hash.Hash
	subtree      hash.Hash
	included     map[hash.Hash]*proofNode
	size         uint64
}

// NewProofBuilder creates a new Merkle proof builder for the given root.
func NewProofBuilder(root, subtree hash.Hash) *ProofBuilder {
	pb, err := NewProofBuilderForVersion(root, subtree, LatestProofVersion)
	if err != nil {
		panic(err)
	}
	return pb
}

// NewProofBuilderV0 creates a new version 0 proof builder for the given root.
func NewProofBuilderV0(root, subtree hash.Hash) *ProofBuilder {
	pb, err := NewProofBuilderForVersion(root, subtree, 0)
	if err != nil {
		panic(err)
	}
	return pb
}

// NewProofBuilderForVersion creates a new Merkle proof builder for the given root
// in a given proof version format.
func NewProofBuilderForVersion(root, subtree hash.Hash, proofVersion uint16) (*ProofBuilder, error) {
	if proofVersion < MinimumProofVersion || proofVersion > LatestProofVersion {
		return nil, fmt.Errorf("%v: %d", ErrUnsupportedProofVersion, proofVersion)
	}
	return &ProofBuilder{
		proofVersion: proofVersion,
		root:         root,
		subtree:      subtree,
		included:     make(map[hash.Hash]*proofNode),
	}, nil
}

// Version returns the proof version.
func (b *ProofBuilder) Version() uint16 {
	return b.proofVersion
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

	// If node is already included, skip it.
	nh := n.GetHash()
	if _, ok := b.included[nh]; ok {
		return
	}

	// Node is available, serialize it.
	var err error
	var pn proofNode
	switch b.proofVersion {
	case 0:
		// In version 0, the leaf is included in the internal node.
		pn.serialized, err = n.CompactMarshalBinaryV0()
	case 1:
		// In version 1, the leaf node is added separately, as a child.
		pn.serialized, err = n.CompactMarshalBinaryV1()
	default:
		panic("proof: unexpected proof version")
	}
	if err != nil {
		panic(err)
	}

	// For internal nodes, also add any children.
	if nd, ok := n.(*node.InternalNode); ok {

		var children []*node.Pointer
		switch b.proofVersion {
		case 0:
			// In version 0, the leaf node is included in the internal node.
			children = []*node.Pointer{
				nd.Left,
				nd.Right,
			}
		case 1:
			// In version 1, the leaf node is added separately, as a child.
			children = []*node.Pointer{
				nd.LeafNode,
				nd.Left,
				nd.Right,
			}
		default:
			panic("proof: unexpected proof version")
		}

		for _, child := range children {
			var childHash hash.Hash
			if child == nil {
				childHash.Empty()
			} else {
				childHash = child.Hash
			}

			pn.children = append(pn.children, childHash)
		}
	}

	b.included[nh] = &pn
	b.size += 1 + uint64(len(pn.serialized))
}

// HasSubtreeRoot returns true if the subtree root node has already been included.
func (b *ProofBuilder) HasSubtreeRoot() bool {
	return b.included[b.subtree] != nil
}

// GetSubtreeRoot returns the subtree root hash for this proof.
func (b *ProofBuilder) GetSubtreeRoot() hash.Hash {
	return b.subtree
}

// Size returns the current size of this proof.
func (b *ProofBuilder) Size() uint64 {
	return b.size
}

// Build tries to build the proof.
func (b *ProofBuilder) Build(ctx context.Context) (*Proof, error) {
	proof := Proof{
		V: b.proofVersion,
	}

	switch b.HasSubtreeRoot() {
	case true:
		// A partial proof for the subtree is available, include that.
		proof.UntrustedRoot = b.subtree
	case false:
		// No partial proof available, we need to use the tree root.
		proof.UntrustedRoot = b.root
	}

	if err := b.build(ctx, &proof, proof.UntrustedRoot); err != nil {
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
	proof.Entries = append(proof.Entries, append([]byte{proofEntryFull}, n.serialized...))

	// And then add any children.
	for _, childHash := range n.children {
		if err := b.build(ctx, proof, childHash); err != nil {
			return err
		}
	}

	return nil
}

// ProofVerifier enables verifying proofs returned by the ReadSyncer API.
type ProofVerifier struct{}

type verifyOpts struct {
	writeLog bool
}

type verifyResult struct {
	// rootPtr is the pointer to the in-memory root node of the verified proof.
	rootPtr *node.Pointer
	// writeLog is the writelog containing key/value pairs if requested.
	writeLog writelog.WriteLog
}

func (vr *verifyResult) addLeafToWriteLog(leaf *node.Pointer) {
	if leaf == nil {
		return
	}
	leafNode, ok := leaf.Node.(*node.LeafNode)
	if !ok {
		return
	}
	vr.writeLog = append(vr.writeLog, writelog.LogEntry{Key: leafNode.Key, Value: leafNode.Value})
}

// VerifyProof verifies a proof and generates an in-memory subtree representing
// the nodes which are included in the proof.
func (pv *ProofVerifier) VerifyProof(ctx context.Context, root hash.Hash, proof *Proof) (*node.Pointer, error) {
	res, err := pv.verifyProofOpts(ctx, root, proof, &verifyOpts{})
	if err != nil {
		return nil, err
	}
	return res.rootPtr, nil
}

// VerifyProofToWriteLog verifies a proof and generates a write log representing the key/value pairs
// which are included in the proof.
func (pv *ProofVerifier) VerifyProofToWriteLog(ctx context.Context, root hash.Hash, proof *Proof) (writelog.WriteLog, error) {
	res, err := pv.verifyProofOpts(ctx, root, proof, &verifyOpts{writeLog: true})
	if err != nil {
		return nil, err
	}
	return res.writeLog, nil
}

func (pv *ProofVerifier) verifyProofOpts(ctx context.Context, root hash.Hash, proof *Proof, opts *verifyOpts) (*verifyResult, error) {
	if proof.V < MinimumProofVersion || proof.V > LatestProofVersion {
		return nil, fmt.Errorf("verifier: unsupported proof version: %d", proof.V)
	}

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

	var res verifyResult
	idx, rootPtr, err := pv.verifyProof(ctx, proof, 0, opts, &res)
	if err != nil {
		return nil, err
	}
	// Make sure that all of the entries in the proof have been used. The returned index should
	// point to just beyond the last element.
	if idx != len(proof.Entries) {
		return nil, fmt.Errorf("verifier: unused entries in proof")
	}
	rootNodeHash := rootPtr.GetHash()
	if rootNodeHash.IsEmpty() {
		// Make sure that in case the root node is empty we always return nil
		// and not a pointer that represents nil.
		rootPtr = nil
	}

	if !rootNodeHash.Equal(&root) {
		return nil, fmt.Errorf("verifier: bad root (expected: %s got: %s)",
			root,
			rootNodeHash,
		)
	}

	res.rootPtr = rootPtr

	return &res, nil
}

func (pv *ProofVerifier) verifyProof(ctx context.Context, proof *Proof, idx int, opts *verifyOpts, res *verifyResult) (int, *node.Pointer, error) {
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
	if len(entry) == 0 {
		return -1, nil, errors.New("verifier: malformed proof")
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
			switch proof.V {
			case 0:
				// In version 0, the leaf node is included in the internal node.
				if opts.writeLog {
					res.addLeafToWriteLog(nd.LeafNode)
				}
			case 1:
				// In version 1, the leaf node is added separately, as a child.
				// Leaf.
				pos, nd.LeafNode, err = pv.verifyProof(ctx, proof, pos, opts, res)
				if err != nil {
					return -1, nil, err
				}
			default:
				// Checked in verifyProofOpts.
				panic("unexpected proof version")
			}

			// Left.
			pos, nd.Left, err = pv.verifyProof(ctx, proof, pos, opts, res)
			if err != nil {
				return -1, nil, err
			}
			// Right.
			pos, nd.Right, err = pv.verifyProof(ctx, proof, pos, opts, res)
			if err != nil {
				return -1, nil, err
			}

			// Recompute hash as hashes were not recomputed for compact encoding.
			nd.UpdateHash()
		}

		ptr := &node.Pointer{Clean: true, Hash: n.GetHash(), Node: n}

		if opts.writeLog {
			res.addLeafToWriteLog(ptr)
		}

		return pos, ptr, nil
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
