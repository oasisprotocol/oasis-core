package checkpoint

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const (
	chunksDirname = "chunks"
	metaFilename  = "meta"
	v1            = 1

	// Versions 1 of checkpoint chunks use proofs version 0.
	//
	// Using proof version 1 (latest), does not reduce chunk size and would require
	// releasing new checkpoint version.
	//
	// Consider reevaluating when introducing a new checkpoint version.
	v1ProofsVersion = 0
)

type fileCreator struct {
	dataDir string
	ndb     db.NodeDB
}

func (fc *fileCreator) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64, chunkerThreads uint16) (meta *Metadata, err error) {
	// Create checkpoint directory.
	cpDir := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
	)
	if err = common.Mkdir(cpDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint directory: %w", err)
	}
	defer func() {
		if err != nil {
			// In case we have failed to create a checkpoint, make sure to clean up after ourselves.
			_ = os.RemoveAll(cpDir)
		}
	}()

	// Check if the checkpoint already exists and just return the existing metadata in this case.
	data, err := os.ReadFile(filepath.Join(cpDir, metaFilename))
	if err == nil {
		var existing Metadata
		if err = cbor.Unmarshal(data, &existing); err != nil {
			return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
		}
		return &existing, nil
	}

	// Create chunks directory.
	chunksDir := filepath.Join(cpDir, chunksDirname)
	if err = common.Mkdir(chunksDir); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunk directory: %w", err)
	}
	// Create chunks.
	fp := &fileProvider{dir: chunksDir}
	var ch chunker
	switch {
	case chunkerThreads > 0:
		ch = &parallelChunker{ndb: fc.ndb, root: root, chunkSize: chunkSize, threads: chunkerThreads}
	default:
		// Deprecated.
		ch = &seqChunker{ndb: fc.ndb, root: root, chunkSize: chunkSize}
	}
	chunks, err := ch.chunk(ctx, fp)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunks (chunker threads: %d): %w", chunkerThreads, err)
	}

	meta = &Metadata{
		Version: v1,
		Root:    root,
		Chunks:  chunks,
	}

	if err = os.WriteFile(filepath.Join(cpDir, metaFilename), cbor.Marshal(meta), 0o600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

func (fc *fileCreator) GetCheckpoints(_ context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	// Currently we only support a single version so we report no checkpoints for other versions.
	if request.Version != v1 {
		return []*Metadata{}, nil
	}

	// Apply optional root version filter.
	versionGlob := "*"
	if request.RootVersion != nil {
		versionGlob = strconv.FormatUint(*request.RootVersion, 10)
	}

	matches, err := filepath.Glob(filepath.Join(fc.dataDir, versionGlob, "*", metaFilename))
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
	if version != v1 {
		return nil, ErrCheckpointNotFound
	}

	metaPath := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Version, 10),
		root.Hash.String(),
		metaFilename,
	)
	data, err := os.ReadFile(metaPath)
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
	if version != v1 {
		return ErrCheckpointNotFound
	}

	versionDir := filepath.Join(fc.dataDir, strconv.FormatUint(root.Version, 10))
	cpDir := filepath.Join(versionDir, root.Hash.String())
	metaPath := filepath.Join(cpDir, metaFilename)
	if err := os.Remove(metaPath); err != nil {
		return ErrCheckpointNotFound
	}

	if err := os.RemoveAll(cpDir); err != nil {
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
	if chunk.Version != v1 {
		return ErrChunkNotFound
	}

	chunkPath := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(chunk.Root.Version, 10),
		chunk.Root.Hash.String(),
		chunksDirname,
		strconv.FormatUint(chunk.Index, 10),
	)

	f, err := os.Open(chunkPath)
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

// fileProvider implements writerFactory.
//
// Writers are created on demand by opening a new OS file that the chunker can use
// for writing chunk data.
type fileProvider struct {
	idx int
	dir string
}

// Implements writerFactory's next method.
func (fp *fileProvider) next() (int, io.WriteCloser, error) {
	fname := filepath.Join(fp.dir, strconv.Itoa(fp.idx))
	f, err := os.Create(fname)
	idx := fp.idx
	if err != nil {
		return idx, nil, err
	}
	fp.idx++
	return idx, f, nil
}
