package checkpoint

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"

	"github.com/oasislabs/oasis-core/go/common"
	"github.com/oasislabs/oasis-core/go/common/cbor"
	"github.com/oasislabs/oasis-core/go/common/crypto/hash"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel"
	db "github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/db/api"
	"github.com/oasislabs/oasis-core/go/storage/mkvs/urkel/node"
)

const (
	chunksDir              = "chunks"
	checkpointMetadataFile = "meta"
	checkpointVersion      = 1
)

type fileCreator struct {
	dataDir string
	ndb     db.NodeDB
}

func (fc *fileCreator) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (meta *Metadata, err error) {
	tree := urkel.NewWithRoot(nil, fc.ndb, root)
	defer tree.Close()

	// Create checkpoint directory.
	checkpointDir := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(root.Round, 10),
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
	data, err := ioutil.ReadFile(filepath.Join(checkpointDir, checkpointMetadataFile))
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

	// Create chunks until we are done.
	var chunks []hash.Hash
	var nextOffset node.Key
	for chunkIndex := 0; ; chunkIndex++ {
		dataFilename := filepath.Join(chunksDir, strconv.Itoa(chunkIndex))

		// Generate chunk.
		var f *os.File
		if f, err = os.Create(dataFilename); err != nil {
			return nil, fmt.Errorf("checkpoint: failed to create chunk file for chunk %d: %w", chunkIndex, err)
		}

		var chunkHash hash.Hash
		chunkHash, nextOffset, err = createChunk(ctx, tree, root, nextOffset, chunkSize, f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("checkpoint: failed to create chunk %d: %w", chunkIndex, err)
		}

		chunks = append(chunks, chunkHash)

		// Check if we are finished.
		if nextOffset == nil {
			break
		}
	}

	// Generate and write checkpoint metadata.
	meta = &Metadata{
		Version: checkpointVersion,
		Root:    root,
		Chunks:  chunks,
	}

	if err = ioutil.WriteFile(filepath.Join(checkpointDir, checkpointMetadataFile), cbor.Marshal(meta), 0600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

func (fc *fileCreator) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	// Currently we only support a single version so we report no checkpoints for other versions.
	if request.Version != checkpointVersion {
		return []*Metadata{}, nil
	}

	matches, err := filepath.Glob(filepath.Join(fc.dataDir, "*", "*", checkpointMetadataFile))
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to enumerate checkpoints: %w", err)
	}

	var cps []*Metadata
	for _, m := range matches {
		data, err := ioutil.ReadFile(m)
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

func (fc *fileCreator) GetCheckpoint(ctx context.Context, request *GetCheckpointRequest) (*Metadata, error) {
	// Currently we only support a single version.
	if request.Version != checkpointVersion {
		return nil, ErrCheckpointNotFound
	}

	checkpointFilename := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(request.Root.Round, 10),
		request.Root.Hash.String(),
		checkpointMetadataFile,
	)
	data, err := ioutil.ReadFile(checkpointFilename)
	if err != nil {
		return nil, ErrCheckpointNotFound
	}

	var cp Metadata
	if err = cbor.Unmarshal(data, &cp); err != nil {
		return nil, fmt.Errorf("checkpoint: corrupted checkpoint metadata: %w", err)
	}
	return &cp, nil
}

func (fc *fileCreator) DeleteCheckpoint(ctx context.Context, request *DeleteCheckpointRequest) error {
	// Currently we only support a single version.
	if request.Version != checkpointVersion {
		return ErrCheckpointNotFound
	}

	checkpointDir := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(request.Root.Round, 10),
		request.Root.Hash.String(),
	)
	if _, err := os.Stat(checkpointDir); err != nil {
		return ErrCheckpointNotFound
	}

	return os.RemoveAll(checkpointDir)
}

func (fc *fileCreator) GetCheckpointChunk(ctx context.Context, chunk *ChunkMetadata, w io.Writer) error {
	// Currently we only support a single version.
	if chunk.Version != checkpointVersion {
		return ErrChunkNotFound
	}

	chunkFilename := filepath.Join(
		fc.dataDir,
		strconv.FormatUint(chunk.Root.Round, 10),
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
