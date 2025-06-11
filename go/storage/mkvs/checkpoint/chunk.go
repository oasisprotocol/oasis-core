package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/golang/snappy"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// writerFactor is a factory that provides writers a chunker can write to.
type writerFactory interface {
	// next returns the next writer together with its index.
	next() (int, io.WriteCloser, error)
}

// seqChunker enables splitting database state at the given root into chunks,
// where chunks are merkle proofs representing part of the state.
//
// Chunks are created by (sequentially) iterating over database keyset.
//
// Internally, this triggers pre-order traversal of state trie (proof).
// When we reach a key that makes proof greater or equal than chunk size,
// it marks the end of the chunk.
type seqChunker struct {
	ndb       db.NodeDB
	root      node.Root
	chunkSize uint64
}

// Chunk creates chunks and writes each into writer provided by the factory.
//
// A list of hashes corresponding to created chunks is returned.
func (sc *seqChunker) chunk(ctx context.Context, wf writerFactory) ([]hash.Hash, error) {
	tree := mkvs.NewWithRoot(nil, sc.ndb, sc.root)
	defer tree.Close()

	// Create chunks until we are done.
	var chunks []hash.Hash
	var nextOffset node.Key
	for {
		// Generate chunk.
		idx, f, err := wf.next()
		if err != nil {
			return nil, fmt.Errorf("chunk: get writer for chunk %d: %w", idx, err)
		}

		var chunkHash hash.Hash
		chunkHash, nextOffset, err = sc.createChunk(ctx, tree, nextOffset, f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("chunk: create chunk %d: %w", idx, err)
		}

		chunks = append(chunks, chunkHash)

		// Check if we are finished.
		if nextOffset == nil {
			break
		}
	}

	return chunks, nil
}

func (sc *seqChunker) createChunk(ctx context.Context, tree mkvs.Tree, offset node.Key, w io.Writer) (
	chunkHash hash.Hash,
	nextOffset node.Key,
	err error,
) {
	it := tree.NewIterator(
		ctx,
		// V1 checkpoints use V0 proofs.
		mkvs.WithProofBuilder(syncer.NewProofBuilderV0(sc.root.Hash, sc.root.Hash)),
	)
	defer it.Close()

	// We build the chunk until the proof becomes too large or we have reached the end.
	for it.Seek(offset); it.Valid() && it.GetProofBuilder().Size() < sc.chunkSize; it.Next() {
		// Check if context got cancelled while iterating to abort early.
		if ctx.Err() != nil {
			err = ctx.Err()
			return
		}
	}
	if it.Err() != nil {
		err = fmt.Errorf("failed to iterate: %w", it.Err())
		return
	}

	// Build our chunk.
	proof, err := it.GetProof()
	if err != nil {
		err = fmt.Errorf("failed to build proof: %w", err)
		return
	}

	// Determine the next offset (not included in proof).
	if it.Valid() {
		it.Next()
		nextOffset = it.Key()
	}

	chunkHash, err = writeChunk(proof, w)
	return
}

func writeChunk(proof *syncer.Proof, w io.Writer) (hash.Hash, error) {
	hb := hash.NewBuilder()
	sw := snappy.NewBufferedWriter(io.MultiWriter(w, hb))
	enc := cbor.NewEncoder(sw)
	for _, entry := range proof.Entries {
		if err := enc.Encode(entry); err != nil {
			return hash.Hash{}, fmt.Errorf("failed to encode chunk part: %w", err)
		}
	}
	if err := sw.Close(); err != nil {
		return hash.Hash{}, fmt.Errorf("failed to close chunk: %w", err)
	}

	return hb.Build(), nil
}

func restoreChunk(ctx context.Context, ndb db.NodeDB, chunk *ChunkMetadata, r io.Reader) error {
	hb := hash.NewBuilder()
	tr := io.TeeReader(r, hb)
	sr := snappy.NewReader(tr)
	dec := cbor.NewDecoder(sr)

	// Reconstruct the proof.
	var decodeErr error
	var p syncer.Proof
	p.V = v1ProofsVersion
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var entry []byte
		if err := dec.Decode(&entry); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			decodeErr = fmt.Errorf("failed to decode chunk: %w", err)

			// Read everything until EOF so we can verify the overall chunk integrity.
			_, _ = io.Copy(io.Discard, tr)
			break
		}

		p.Entries = append(p.Entries, entry)
	}
	p.UntrustedRoot = chunk.Root.Hash

	// Verify overall chunk integrity.
	chunkHash := hb.Build()
	if !chunk.Digest.Equal(&chunkHash) {
		return fmt.Errorf("%w: digest incorrect (expected: %s got: %s)",
			ErrChunkCorrupted,
			chunk.Digest,
			chunkHash,
		)
	}

	// Treat decode errors after integrity verification as proof verification failures.
	if decodeErr != nil {
		return fmt.Errorf("%w: %s", ErrChunkProofVerificationFailed, decodeErr.Error())
	}

	// Verify the proof.
	var pv syncer.ProofVerifier
	ptr, err := pv.VerifyProof(ctx, chunk.Root.Hash, &p)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrChunkProofVerificationFailed, err.Error())
	}

	// Import chunk into the node database.
	emptyRoot := node.Root{
		Namespace: chunk.Root.Namespace,
		Version:   chunk.Root.Version,
		Type:      chunk.Root.Type,
	}
	emptyRoot.Hash.Empty()

	batch, err := ndb.NewBatch(emptyRoot, chunk.Root.Version, true)
	if err != nil {
		return fmt.Errorf("chunk: failed to create batch: %w", err)
	}
	defer batch.Reset()

	if err = doRestoreChunk(ctx, batch, ptr, nil); err != nil {
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
	ptr *node.Pointer,
	parent *node.Pointer,
) (err error) {
	if ptr == nil {
		return
	}

	switch n := ptr.Node.(type) {
	case nil:
		if err = batch.VisitDirtyNode(ptr, parent); err != nil {
			return
		}
	case *node.InternalNode:
		if err = batch.VisitDirtyNode(ptr, parent); err != nil {
			return
		}

		// Commit internal leaf (considered to be on the same depth as the internal node).
		if err = doRestoreChunk(ctx, batch, n.LeafNode, ptr); err != nil {
			return
		}

		for _, subNode := range []*node.Pointer{n.Left, n.Right} {
			if err = doRestoreChunk(ctx, batch, subNode, ptr); err != nil {
				return
			}
		}

		// Store the node.
		if err = batch.PutNode(ptr); err != nil {
			return
		}
	case *node.LeafNode:
		// Leaf node -- store the node.
		if err = batch.VisitDirtyNode(ptr, parent); err != nil {
			return
		}
		if err = batch.PutNode(ptr); err != nil {
			return
		}
	}

	return
}
