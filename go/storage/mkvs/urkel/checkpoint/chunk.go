package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/golang/snappy"

	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
	db "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/syncer"
)

func createChunk(
	ctx context.Context,
	tree urkel.Tree,
	root node.Root,
	offset node.Key,
	chunkSize uint64,
	w io.Writer,
) (
	chunkHash hash.Hash,
	nextOffset node.Key,
	err error,
) {
	it := tree.NewIterator(ctx, urkel.WithProof(root.Hash))
	defer it.Close()

	// We build the chunk until the proof becomes too large or we have reached the end.
	for it.Seek(offset); it.Valid() && it.GetProofBuilder().Size() < chunkSize; it.Next() {
		// Check if context got cancelled while iterating to abort early.
		if ctx.Err() != nil {
			err = ctx.Err()
			return
		}

		nextOffset = it.Key()
	}
	if it.Err() != nil {
		err = fmt.Errorf("chunk: failed to iterate: %w", it.Err())
		return
	}
	if !it.Valid() {
		// We have finished iterating.
		nextOffset = nil
	}

	// Build our chunk.
	proof, err := it.GetProof()
	if err != nil {
		err = fmt.Errorf("chunk: failed to build proof: %w", err)
		return
	}

	hb := hash.NewBuilder()
	sw := snappy.NewBufferedWriter(io.MultiWriter(w, hb))
	enc := cbor.NewEncoder(sw)
	for _, entry := range proof.Entries {
		if err = enc.Encode(entry); err != nil {
			err = fmt.Errorf("chunk: failed to encode chunk part: %w", err)
			return
		}
	}
	if err = sw.Close(); err != nil {
		err = fmt.Errorf("chunk: failed to close chunk: %w", err)
		return
	}

	chunkHash = hb.Build()
	return
}

func restoreChunk(ctx context.Context, ndb db.NodeDB, chunk *ChunkMetadata, r io.Reader) error {
	hb := hash.NewBuilder()
	sr := snappy.NewReader(io.TeeReader(r, hb))
	dec := cbor.NewDecoder(sr)

	// Reconstruct the proof.
	var p syncer.Proof
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var entry []byte
		if err := dec.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("chunk: failed to decode chunk: %w", err)
		}

		p.Entries = append(p.Entries, entry)
	}
	p.UntrustedRoot = chunk.Root.Hash

	// Verify overall chunk integrity.
	chunkHash := hb.Build()
	if !chunk.Digest.Equal(&chunkHash) {
		return fmt.Errorf("chunk: digest incorrect (expected: %s got: %s)",
			chunk.Digest,
			chunkHash,
		)
	}

	// Verify the proof.
	var pv syncer.ProofVerifier
	ptr, err := pv.VerifyProof(ctx, chunk.Root.Hash, &p)
	if err != nil {
		return fmt.Errorf("chunk: chunk proof verification failed: %w", err)
	}

	// Import chunk into the node database.
	emptyRoot := node.Root{
		Namespace: chunk.Root.Namespace,
		Round:     chunk.Root.Round,
	}
	emptyRoot.Hash.Empty()

	batch := ndb.NewBatch(emptyRoot, true)
	defer batch.Reset()

	subtree := batch.MaybeStartSubtree(nil, 0, ptr)
	if err = doRestoreChunk(ctx, batch, subtree, 0, ptr); err != nil {
		return fmt.Errorf("chunk: node import failed: %w", err)
	}
	if err = subtree.Commit(); err != nil {
		return fmt.Errorf("chunk: node import failed: %w", err)
	}
	if err = batch.Commit(chunk.Root); err != nil {
		return fmt.Errorf("chunk: node import failed: %w", err)
	}

	return nil
}

func doRestoreChunk(
	ctx context.Context,
	batch db.Batch,
	subtree db.Subtree,
	depth node.Depth,
	ptr *node.Pointer,
) (err error) {
	if ptr == nil {
		return
	}

	switch n := ptr.Node.(type) {
	case nil:
	case *node.InternalNode:
		// Commit internal leaf (considered to be on the same depth as the internal node).
		if err = doRestoreChunk(ctx, batch, subtree, depth, n.LeafNode); err != nil {
			return
		}

		for _, subNode := range []*node.Pointer{n.Left, n.Right} {
			newSubtree := batch.MaybeStartSubtree(subtree, depth+1, subNode)
			if err = doRestoreChunk(ctx, batch, newSubtree, depth+1, subNode); err != nil {
				return
			}
			if newSubtree != subtree {
				if err = newSubtree.Commit(); err != nil {
					return
				}
			}
		}

		// Store the node.
		if err = subtree.PutNode(depth, ptr); err != nil {
			return
		}
	case *node.LeafNode:
		// Leaf node -- store the node.
		if err = subtree.PutNode(depth, ptr); err != nil {
			return
		}
	}

	return
}
