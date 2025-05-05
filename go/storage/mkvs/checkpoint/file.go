package checkpoint

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	chunksDir              = "chunks"
	checkpointMetadataFile = "meta"
	checkpointVersion      = 1

	// Versions 1 of checkpoint chunks use proofs version 0. Consider bumping
	// this to latest version when introducing new checkpoint versions.
	checkpointProofsVersion = 0
)

type fileCreator struct {
	dataDir string
	ndb     db.NodeDB
}

func (fc *fileCreator) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (meta *Metadata, err error) {
	// Create checkpoint directory.
	checkpointDir := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
	)
	if err = common.Mkdir(checkpointDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint directory: %w", err)
	}
	defer func() {
		if err != nil {
			// In case we have failed to create a checkpoint, make sure to clean up after ourselves.
			_ = os.RemoveAll(checkpointDir)
		}
	}()

	// Check if the checkpoint already exists and just return the existing metadata in this case.
	data, err := os.ReadFile(filepath.Join(checkpointDir, checkpointMetadataFile))
	if err == nil {
		var existing Metadata
		if err = cbor.Unmarshal(data, &existing); err != nil {
			return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
		}
		return &existing, nil
	}

	// Create chunks directory.
	chunksDir := filepath.Join(checkpointDir, chunksDir)
	if err = common.Mkdir(chunksDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunk directory: %w", err)
	}

	depth := 7 // TODO make this configurable.
	subtrees, err := mkvs.NewIterSubtrees(ctx, fc.ndb, root, depth)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create subtrees (depth: %d): %w", depth, err)
	}
	defer func() {
		for _, st := range subtrees {
			st.Close()
		}
	}()

	indexer := newChunkIndexer()
	createSubtreeChunks := func(ctx context.Context, subtree mkvs.Subtree) error {
		// Create chunks until we are done.
		var nextOffset node.Key
		var count int64
		for {
			idx := indexer.next()

			dataFilename := filepath.Join(chunksDir, strconv.Itoa(idx))

			// Generate chunk.
			f, err := os.Create(dataFilename)
			if err != nil {
				return fmt.Errorf("checkpoint: failed to create chunk file for chunk %d: %w", idx, err)
			}

			var chunkHash hash.Hash
			chunkHash, nextOffset, err = createChunk(ctx, root, subtree, nextOffset, chunkSize, f, &count)
			errClose := f.Close()
			err = errors.Join(err, errClose)
			if err != nil {
				return fmt.Errorf("checkpoint: failed to create chunk %d: %w", idx, err)
			}

			indexer.add(idx, chunkHash)

			// Check if we are finished.
			if nextOffset == nil {
				fmt.Printf("Subtree: %s has %d keys\n", subtree.String(), count)
				break
			}
		}

		return nil
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	errCh := make(chan error, len(subtrees))
	for _, st := range subtrees {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := createSubtreeChunks(ctx, st)
			if err != nil {
				cancel()
				errCh <- err
			}
		}()
	}

	wg.Wait()

	close(errCh)
	for err := range errCh { // return first error if present
		return nil, err
	}

	// Generate and write checkpoint metadata.
	meta = &Metadata{
		Version: checkpointVersion,
		Root:    root,
		Chunks:  indexer.hashes(),
	}

	if err = os.WriteFile(filepath.Join(checkpointDir, checkpointMetadataFile), cbor.Marshal(meta), 0o600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

// TODO consider testing independently.
type chunkIndexer struct {
	sync.Mutex
	chunks    map[int]hash.Hash
	nextIndex int
}

func newChunkIndexer() chunkIndexer {
	return chunkIndexer{
		chunks: make(map[int]hash.Hash),
	}
}

func (ci *chunkIndexer) next() int {
	ci.Lock()
	defer ci.Unlock()
	ci.nextIndex++
	return ci.nextIndex - 1

}

func (ci *chunkIndexer) add(idx int, hash hash.Hash) {
	ci.Lock()
	defer ci.Unlock()
	ci.chunks[idx] = hash
}

func (ci *chunkIndexer) hashes() []hash.Hash {
	ci.Lock()
	defer ci.Unlock()
	idxs := slices.Collect(maps.Keys(ci.chunks))
	slices.Sort(idxs)

	hashes := make([]hash.Hash, 0, len(ci.chunks))
	for _, idx := range idxs {
		hashes = append(hashes, ci.chunks[idx])
	}
	return hashes

}

func (fc *fileCreator) GetCheckpoints(_ context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	// Currently we only support a single version so we report no checkpoints for other versions.
	if request.Version != checkpointVersion {
		return []*Metadata{}, nil
	}

	// Apply optional root version filter.
	versionGlob := "*"
	if request.RootVersion != nil {
		versionGlob = strconv.FormatUint(*request.RootVersion, 10)
	}

	matches, err := filepath.Glob(filepath.Join(fc.dataDir, versionGlob, "*", checkpointMetadataFile))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to enumerate checkpoints: %w", err)
	}

	var cps []*Metadata
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, fmt.Errorf("checkpoint: failed to read checkpoint metadata at %s: %w", m, err)
		}

		var cp Metadata
		if err = cbor.Unmarshal(data, &cp); err != nil {
			return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata at %s: %w", m, err)
		}

		cps = append(cps, &cp)
	}
	return cps, nil
}

func (fc *fileCreator) GetCheckpoint(_ context.Context, version uint16, root node.Root) (*Metadata, error) {
	// Currently we only support a single version.
	if version != checkpointVersion {
		return nil, ErrCheckpointNotFound
	}

	checkpointFilename := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
		checkpointMetadataFile,
	)
	data, err := os.ReadFile(checkpointFilename)
	if err != nil {
		return nil, ErrCheckpointNotFound
	}

	var cp Metadata
	if err = cbor.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
	}
	return &cp, nil
}

func (fc *fileCreator) DeleteCheckpoint(_ context.Context, version uint16, root node.Root) error {
	// Currently we only support a single version.
	if version != checkpointVersion {
		return ErrCheckpointNotFound
	}

	versionDir := filepath.Join(fc.dataDir, strconv.FormatUint(root.Version, 10))
	checkpointDir := filepath.Join(versionDir, root.Hash.String())
	checkpointFilename := filepath.Join(checkpointDir, checkpointMetadataFile)
	if err := os.Remove(checkpointFilename); err != nil {
		return ErrCheckpointNotFound
	}

	if err := os.RemoveAll(checkpointDir); err != nil {
		return fmt.Errorf("checkpoint: failed to remove checkpoint directory: %w", err)
	}

	// If there are no more roots for the given version, remove the version directory as well.
	f, err := os.Open(versionDir)
	if err != nil {
		return fmt.Errorf("checkpoint: failed to open directory: %w", err)
	}
	defer f.Close()

	switch _, err = f.Readdir(1); err {
	case nil:
		// Non-empty directory.
	case io.EOF:
		// Directory is empty, we can remove it.
		if err = os.RemoveAll(versionDir); err != nil {
			return fmt.Errorf("checkpoint: failed to remove version %d directory: %w", root.Version, err)
		}
	default:
		return fmt.Errorf("checkpoint: failed to read directory: %w", err)
	}

	return nil
}

func (fc *fileCreator) GetCheckpointChunk(_ context.Context, chunk *ChunkMetadata, w io.Writer) error {
	// Currently we only support a single version.
	if chunk.Version != checkpointVersion {
		return ErrChunkNotFound
	}

	chunkFilename := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(chunk.Root.Version, 10),
		chunk.Root.Hash.String(),
		chunksDir,
		strconv.FormatUint(chunk.Index, 10),
	)

	f, err := os.Open(chunkFilename)
	if err != nil {
		return ErrChunkNotFound
	}
	defer f.Close()

	if _, err = io.Copy(w, f); err != nil {
		return fmt.Errorf("checkpoint: failed to read chunk: %w", err)
	}
	return nil
}

// NewFileCreator creates a new checkpoint creator that writes created chunks into the filesystem.
func NewFileCreator(dataDir string, ndb db.NodeDB) (Creator, error) {
	return &fileCreator{
		dataDir: dataDir,
		ndb:     ndb,
	}, nil
}
