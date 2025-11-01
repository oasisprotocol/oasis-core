package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/golang/snappy"
	"golang.org/x/sync/errgroup"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

// Chunker enables splitting database state into chunks, where chunks are merkle proofs
// representing part of the state.
type chunker interface {
	// Chunk creates chunks and writes each into writer provided by the factory.
	//
	// A list of hashes corresponding to created chunks is returned.
	//
	// A chunker implementation is expected to produce a deterministic result.
	// This allows using chunks from multiple chunker instances for state
	// restoration.
	chunk(ctx context.Context, wf writerFactory) ([]hash.Hash, error)
}

// writerFactory is a factory that provides writers a chunker can write to.
type writerFactory interface {
	// next returns the next writer together with its index.
	next() (int, io.WriteCloser, error)
}

// seqChunker implements chunker interface.
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

// chunk implements chunker's chunk method.
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
		if err := ctx.Err(); err != nil {
			return hash.Hash{}, nil, err
		}
	}
	if err := it.Err(); err != nil {
		return hash.Hash{}, nil, fmt.Errorf("failed to iterate: %w", err)
	}

	// Build our chunk.
	proof, err := it.GetProof()
	if err != nil {
		return hash.Hash{}, nil, fmt.Errorf("failed to build proof: %w", err)
	}

	// Determine the next offset (not included in proof).
	if it.Valid() {
		it.Next()
		nextOffset = it.Key()
	}

	chunkHash, err = writeChunk(proof, w)
	if err != nil {
		return hash.Hash{}, nil, err
	}

	return chunkHash, nextOffset, nil
}

// parallelChunker implements chunker interface.
//
// Chunks are created in parallel using target number of subtrees (threads).
// For every subtree, we trigger sequential iteration for each subtree keyset.
//
// Internally, this triggers pre-order traversal of state trie (proof).
// When we reach a key that makes proof greater or equal than chunk size,
// it marks the end of the chunk.
type parallelChunker struct {
	ndb       db.NodeDB
	root      node.Root
	chunkSize uint64
	threads   uint16
}

// chunk implements chunker's chunk method.
func (pc *parallelChunker) chunk(ctx context.Context, wf writerFactory) ([]hash.Hash, error) {
	root, err := newSubtree(pc.ndb, pc.root)
	if err != nil {
		return nil, err
	}
	pending := []*subtree{root}

	// Chunking result must be deterministic, so we should be careful with parallelization.
	// This is achieved by:
	//    1. Always splitting subtree tasks from left to right.
	//    2. Process single chunk for each subtree in parallel.
	//    3. Wait for all subtrees to finish creating single chunk.
	//    4. Repeat from 1., filtering out finished tasks.
	// As benchmarked, the wait time for 3. is negligible.
	var chunks []hash.Hash
	for len(pending) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		pending, err = pc.splitTasks(pending)
		if err != nil {
			return nil, fmt.Errorf("chunk: splitting chunking tasks: %w", err)
		}

		hashes, err := pc.createChunks(ctx, wf, pending)
		if err != nil {
			return nil, fmt.Errorf("chunk: processing chunking tasks: %w", err)
		}

		chunks = append(chunks, hashes...)

		pending = pc.filterFinished(pending)
	}

	return chunks, nil
}

func (pc *parallelChunker) splitTasks(tasks []*subtree) ([]*subtree, error) {
	for i := 0; i < 10; i++ {
		var nextTasks []*subtree
		for i, task := range tasks {
			if len(nextTasks)+len(tasks)-i >= int(pc.threads) {
				nextTasks = append(nextTasks, tasks[i:]...)
				return nextTasks, nil
			}
			children, err := task.split()
			if err != nil {
				return nil, fmt.Errorf("splitting chunking task: %w", err)
			}
			nextTasks = append(nextTasks, children...)
		}

		tasks = nextTasks
	}

	return tasks, nil
}

func (pc *parallelChunker) createChunks(ctx context.Context, wf writerFactory, tasks []*subtree) ([]hash.Hash, error) {
	group, ctx := errgroup.WithContext(ctx)

	chunks := make([]hash.Hash, len(tasks))
	var mu sync.Mutex
	for i, task := range tasks {
		idx, w, err := wf.next()
		if err != nil {
			return nil, fmt.Errorf("getting writer for chunk %d: %w", idx, err)
		}

		group.Go(func() error {
			hash, err := task.nextChunk(ctx, w, pc.chunkSize)
			if err != nil {
				return fmt.Errorf("creating new chunk with index %d", idx)
			}

			mu.Lock()
			defer mu.Unlock()
			chunks[i] = hash

			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return nil, err
	}

	return chunks, nil
}

func (pc *parallelChunker) filterFinished(tasks []*subtree) []*subtree {
	var pending []*subtree
	for _, task := range tasks {
		if task.hasNext() {
			continue
		}
		pending = append(pending, task)
	}
	return pending
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
) error {
	if ptr == nil {
		return nil
	}

	switch n := ptr.Node.(type) {
	case nil:
		if err := batch.VisitDirtyNode(ptr, parent); err != nil {
			return err
		}
	case *node.InternalNode:
		if err := batch.VisitDirtyNode(ptr, parent); err != nil {
			return err
		}

		// Commit internal leaf (considered to be on the same depth as the internal node).
		if err := doRestoreChunk(ctx, batch, n.LeafNode, ptr); err != nil {
			return err
		}

		for _, subNode := range []*node.Pointer{n.Left, n.Right} {
			if err := doRestoreChunk(ctx, batch, subNode, ptr); err != nil {
				return err
			}
		}

		// Store the node.
		if err := batch.PutNode(ptr); err != nil {
			return err
		}
	case *node.LeafNode:
		// Leaf node -- store the node.
		if err := batch.VisitDirtyNode(ptr, parent); err != nil {
			return err
		}
		if err := batch.PutNode(ptr); err != nil {
			return err
		}
	}

	return nil
}
