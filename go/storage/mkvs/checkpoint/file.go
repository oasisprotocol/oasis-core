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
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	db "github.com/oasisprotocol/oasis-core/go/storage/mkvs/db/api"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
)

const (
	chunksDir              = "chunks"
	checkpointMetadataFile = "meta"
	checkpointV1           = 1
	checkpointV2           = 1 // TODO same version was used to first ensure equal logic. (sanity)

	// Versions 1 of checkpoint chunks use proofs version 0. Consider bumping
	// this to latest version when introducing new checkpoint versions.
	checkpointProofsVersion = 0
)

type fileCreatorV1 struct {
	dataDir string
	ndb     db.NodeDB
}

func (fc *fileCreatorV1) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (meta *Metadata, err error) {
	tree := mkvs.NewWithRoot(nil, fc.ndb, root)
	defer tree.Close()

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
		chunkHash, nextOffset, err = createChunkV1(ctx, tree, root, nextOffset, chunkSize, f)
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
		Version: checkpointV1,
		Root:    root,
		Chunks:  chunks,
	}

	if err = os.WriteFile(filepath.Join(checkpointDir, checkpointMetadataFile), cbor.Marshal(meta), 0o600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

func (fc *fileCreatorV1) GetCheckpoints(_ context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	// Currently we only support two versions so we report no checkpoints for other versions.
	if request.Version != checkpointV1 && request.Version != checkpointV2 {
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

func (fc *fileCreatorV1) GetCheckpoint(_ context.Context, version uint16, root node.Root) (*Metadata, error) {
	// Currently we only support two versions.
	if version != checkpointV1 && version != checkpointV2 {
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

func (fc *fileCreatorV1) DeleteCheckpoint(_ context.Context, version uint16, root node.Root) error {
	// Currently we only support two versions.
	if version != checkpointV1 && version != checkpointV2 {
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

func (fc *fileCreatorV1) GetCheckpointChunk(_ context.Context, chunk *ChunkMetadata, w io.Writer) error {
	// Currently we only support two versions.
	if chunk.Version != checkpointV1 && chunk.Version != checkpointV2 {
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

// NewFileCreatorV1 creates a new checkpoint creator that writes created chunks into the filesystem.
func NewFileCreatorV1(dataDir string, ndb db.NodeDB) (Creator, error) {
	return &fileCreatorV1{
		dataDir: dataDir,
		ndb:     ndb,
	}, nil
}

type fileCreatorV2 struct {
	dataDir string
	ndb     db.NodeDB
}

// This is first iteration of CreateCheckpoint that should produce exactly equal checkpoint as V1.
// Internally instead of relying on Iterator for preparing proofs we build them manually.
//
// Next iteration is to use more compact V1 proofs.
// Final iteration is to dynamically parallelize and generate proofs/chunks in parallel.
func (fc *fileCreatorV2) CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (meta *Metadata, err error) {
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

	// Create chunks.
	chunks, err := createChunksV2(ctx, fc.ndb, chunkSize, root, chunksDir)
	if err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create chunks: %w", err)
	}

	// Generate and write checkpoint metadata.
	meta = &Metadata{
		Version: checkpointV1,
		Root:    root,
		Chunks:  chunks,
	}

	if err = os.WriteFile(filepath.Join(checkpointDir, checkpointMetadataFile), cbor.Marshal(meta), 0o600); err != nil {
		return nil, fmt.Errorf("checkpoint: failed to create checkpoint metadata: %w", err)
	}
	return meta, nil
}

func (fc *fileCreatorV2) GetCheckpoint(ctx context.Context, version uint16, root node.Root) (*Metadata, error) {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.GetCheckpoint(ctx, version, root)
}

func (fc *fileCreatorV2) DeleteCheckpoint(ctx context.Context, version uint16, root node.Root) error {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.DeleteCheckpoint(ctx, version, root)
}

func (fc *fileCreatorV2) GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Metadata, error) {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.GetCheckpoints(ctx, request)
}

func (fc *fileCreatorV2) GetCheckpointChunk(ctx context.Context, chunk *ChunkMetadata, w io.Writer) error {
	fcv1 := fileCreatorV1{
		dataDir: fc.dataDir,
		ndb:     fc.ndb,
	}
	return fcv1.GetCheckpointChunk(ctx, chunk, w)
}

// NewFileCreatorV2 creates a new checkpoint creator that writes created chunks into the filesystem.
func NewFileCreatorV2(dataDir string, ndb db.NodeDB) (Creator, error) {
	return &fileCreatorV2{
		dataDir: dataDir,
		ndb:     ndb,
	}, nil
}

// TODO consider using V1 proofs so that checkpoints size is reduced.
// TODO parallelize dynamically and keep output constant.
func createChunksV2(ctx context.Context, ndb db.NodeDB, chunkSize uint64, root node.Root, chunksDir string) ([]hash.Hash, error) {
	type visitState uint8
	const (
		visitBefore visitState = iota
		visitAt
		visitAtLeft
		visitAfter
	)
	type pathAtom struct {
		nd    node.Node
		state visitState
	}

	if root.Hash.IsEmpty() {
		return []hash.Hash{}, nil
	}

	rootPtr := node.Pointer{
		Clean: true,
		Hash:  root.Hash,
	}
	rootNode, err := ndb.GetNode(root, &rootPtr)
	if err != nil {
		return nil, fmt.Errorf("getting node from nodedb (hash: %.8s): %w", rootPtr.Hash, err)
	}

	path := []pathAtom{
		pathAtom{
			nd:    rootNode,
			state: visitBefore,
		},
	}

	pb := syncer.NewProofBuilderV0(root.Hash, root.Hash)
	var chunks []hash.Hash
	var chunkIndex int
	var lastIncludedIsLeaf bool
	for len(path) > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		current := path[len(path)-1]
		path = path[:len(path)-1]

		if pb.Size() >= chunkSize && lastIncludedIsLeaf { // Just like existing code this does not respect chunkSize boundary...
			// Write proof to chunk file.
			dataFilename := filepath.Join(chunksDir, strconv.Itoa(chunkIndex))
			hash, err := createChunkV2(ctx, pb, dataFilename)
			if err != nil {
				return nil, fmt.Errorf("creating chunk (chunk index: %d): %w", chunkIndex, err)
			}
			chunks = append(chunks, hash)
			chunkIndex++

			// Reset proof builder and include access path.
			pb = syncer.NewProofBuilderV0(root.Hash, root.Hash)
			lastIncludedIsLeaf = false
			for _, nd := range path {
				pb.Include(nd.nd)
			}
			if current.state != visitBefore {
				pb.Include(current.nd)
			}
		}

		switch currNode := current.nd.(type) {
		case nil:
			continue
		case *node.LeafNode:
			pb.Include(currNode)
			lastIncludedIsLeaf = true
		case *node.InternalNode:
			visitNext := func(ptr *node.Pointer) error {
				if ptr != nil {
					nd, err := ndb.GetNode(root, ptr)
					if err != nil {
						return fmt.Errorf("getting node from nodedb (ptr hash: %.8s): %w", ptr.Hash, err)
					}
					path = append(path, pathAtom{nd, visitBefore})
				}
				return nil
			}
			switch current.state {
			case visitBefore:
				pb.Include(currNode)
				if currNode.LeafNode != nil {
					lastIncludedIsLeaf = true
				} else {
					lastIncludedIsLeaf = false
				}
				path = append(path, pathAtom{currNode, visitAt})
			case visitAt:
				path = append(path, pathAtom{currNode, visitAtLeft})
				if err := visitNext(currNode.Left); err != nil {
					return nil, err
				}
			case visitAtLeft:
				path = append(path, pathAtom{currNode, visitAfter})
				if err := visitNext(currNode.Right); err != nil {
					return nil, err
				}
			case visitAfter:
				continue
			default:
				return nil, fmt.Errorf("unexpected atom state")
			}
		default:
			return nil, fmt.Errorf("unexpected node type")
		}
	}

	// Write last proof to chunk file.
	dataFilename := filepath.Join(chunksDir, strconv.Itoa(chunkIndex))
	hash, err := createChunkV2(ctx, pb, dataFilename)
	if err != nil {
		return nil, fmt.Errorf("creating chunk (chunk index: %d): %w", chunkIndex, err)
	}
	chunks = append(chunks, hash)

	return chunks, nil
}
