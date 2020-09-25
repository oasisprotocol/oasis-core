// Package checkpoint provides methods for creating MKVS checkpoints.
package checkpoint

import (
	"context"
	"io"

	"github.com/oasisprotocol/oasis-core/go/common"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/errors"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
)

const moduleName = "storage/mkvs/checkpoint"

var (
	// ErrCheckpointNotFound is the error when a checkpoint is not found.
	ErrCheckpointNotFound = errors.New(moduleName, 1, "checkpoint: not found")

	// ErrChunkNotFound is the error when a chunk is not found.
	ErrChunkNotFound = errors.New(moduleName, 2, "checkpoint: chunk not found")

	// ErrRestoreAlreadyInProgress is the error when a checkpoint restore is already in progress and
	// the caller wanted to start another restore.
	ErrRestoreAlreadyInProgress = errors.New(moduleName, 3, "checkpoint: restore already in progress")

	// ErrNoRestoreInProgress is the error when no checkpoint restore is currently in progress.
	ErrNoRestoreInProgress = errors.New(moduleName, 4, "checkpoint: no restore in progress")

	// ErrChunkAlreadyRestored is the error when a chunk has already been restored.
	ErrChunkAlreadyRestored = errors.New(moduleName, 5, "checkpoint: chunk already restored")

	// ErrChunkProofVerificationFailed is the error when a chunk fails proof verification.
	ErrChunkProofVerificationFailed = errors.New(moduleName, 6, "chunk: chunk proof verification failed")

	// ErrChunkCorrupted is the error when a chunk is corrupted.
	ErrChunkCorrupted = errors.New(moduleName, 7, "chunk: corrupted chunk")
)

// ChunkProvider is a chunk provider.
type ChunkProvider interface {
	// GetCheckpoints returns a list of checkpoint metadata for all known checkpoints.
	GetCheckpoints(ctx context.Context, request *GetCheckpointsRequest) ([]*Metadata, error)

	// GetCheckpointChunk fetches a specific chunk from an existing chekpoint.
	GetCheckpointChunk(ctx context.Context, chunk *ChunkMetadata, w io.Writer) error
}

// GetCheckpointsRequest is a GetCheckpoints request.
type GetCheckpointsRequest struct {
	Version   uint16           `json:"version"`
	Namespace common.Namespace `json:"namespace"`

	// RootVersion specifies an optional root version to limit the request to. If specified, only
	// checkpoints for roots with the specific version will be considered.
	RootVersion *uint64 `json:"root_version,omitempty"`
}

// Creator is a checkpoint creator.
type Creator interface {
	ChunkProvider

	// CreateCheckpoint creates a new checkpoint at the given root.
	CreateCheckpoint(ctx context.Context, root node.Root, chunkSize uint64) (*Metadata, error)

	// GetCheckpoint retrieves checkpoint metadata for a specific checkpoint.
	GetCheckpoint(ctx context.Context, version uint16, root node.Root) (*Metadata, error)

	// DeleteCheckpoint deletes a specific checkpoint.
	DeleteCheckpoint(ctx context.Context, version uint16, root node.Root) error
}

// Restorer is a checkpoint restorer.
type Restorer interface {
	// StartRestore starts a checkpoint restoration process.
	StartRestore(ctx context.Context, checkpoint *Metadata) error

	// AbortRestore aborts a checkpoint restore in progress.
	//
	// It is not an error to call this method when no checkpoint restore is in progress.
	AbortRestore(ctx context.Context) error

	// GetCurrentCheckpoint returns the checkpoint that is being restored. If no restoration is in
	// progress, this method may return nil.
	GetCurrentCheckpoint() *Metadata

	// RestoreChunk restores the given chunk into the underlying node database.
	//
	// This method requires that a restoration is in progress.
	//
	// Returns true when the checkpoint has been fully restored.
	RestoreChunk(ctx context.Context, index uint64, r io.Reader) (bool, error)
}

// CreateRestorer is an interface that combines the checkpoint creator and restorer.
type CreateRestorer interface {
	Creator
	Restorer
}

type createRestorer struct {
	Creator
	Restorer
}

// NewCreateRestorer combines a checkpoint creator and a restorer.
func NewCreateRestorer(creator Creator, restorer Restorer) CreateRestorer {
	return &createRestorer{
		Creator:  creator,
		Restorer: restorer,
	}
}

// ChunkMetadata is chunk metadata.
type ChunkMetadata struct {
	Version uint16    `json:"version"`
	Root    node.Root `json:"root"`
	Index   uint64    `json:"index"`
	Digest  hash.Hash `json:"digest"`
}

// Metadata is checkpoint metadata.
type Metadata struct {
	Version uint16      `json:"version"`
	Root    node.Root   `json:"root"`
	Chunks  []hash.Hash `json:"chunks"`
}

// EncodedHash returns the encoded cryptographic hash of the checkpoint metadata.
func (m *Metadata) EncodedHash() hash.Hash {
	return hash.NewFrom(m)
}

// GetChunkMetadata returns the chunk metadata for the corresponding chunk.
func (m Metadata) GetChunkMetadata(idx uint64) (*ChunkMetadata, error) {
	if idx >= uint64(len(m.Chunks)) {
		return nil, ErrChunkNotFound
	}

	return &ChunkMetadata{
		Version: m.Version,
		Root:    m.Root,
		Index:   idx,
		Digest:  m.Chunks[int(idx)],
	}, nil
}
