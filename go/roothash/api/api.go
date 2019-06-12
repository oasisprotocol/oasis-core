// Package api implements the root hash backend API and common datastructures.
package api

import (
	"context"
	"errors"
	"time"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/pubsub"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
	"github.com/oasislabs/ekiden/go/roothash/api/commitment"
)

const (
	// HashSize is the size of the various hashes in bytes.
	HashSize = 32
)

var (
	// ErrMalformedHash is the error returned when a hash is malformed.
	ErrMalformedHash = errors.New("roothash: malformed hash")

	// ErrInvalidArgument is the error returned on malformed argument(s).
	ErrInvalidArgument = errors.New("roothash: invalid argument")

	// ErrNotFound is the error returned when a block is not found.
	ErrNotFound = errors.New("roothash: block not found")

	_ cbor.Marshaler   = (*ComputeDiscrepancyDetectedEvent)(nil)
	_ cbor.Unmarshaler = (*ComputeDiscrepancyDetectedEvent)(nil)
	_ cbor.Marshaler   = (*MergeDiscrepancyDetectedEvent)(nil)
	_ cbor.Unmarshaler = (*MergeDiscrepancyDetectedEvent)(nil)
)

// Info contains information about a root hash backend.
type Info struct {
	// ComputeRoundTimeout is the compute round timeout.
	ComputeRoundTimeout time.Duration
	// MergeRoundTimeout is the merge round timeout.
	MergeRoundTimeout time.Duration
}

// Backend is a root hash implementation.
type Backend interface {
	// Info returns information about a root hash backend.
	Info() Info

	// GetLatestBlock returns the latest block.
	//
	// The metadata contained in this block can be further used to get
	// the latest state from the storage backend.
	GetLatestBlock(context.Context, signature.PublicKey) (*block.Block, error)

	// GetBlock returns the block at a specific height.
	GetBlock(context.Context, signature.PublicKey, uint64) (*block.Block, error)

	// WatchAnnotatedBlocks returns a channel that produces a stream of
	// annotated blocks.
	WatchAnnotatedBlocks(signature.PublicKey) (<-chan *AnnotatedBlock, *pubsub.Subscription, error)

	// WatchBlocks returns a channel that produces a stream of blocks.
	//
	// The latest block if any will get pushed to the stream immediately.
	// Subsequent blocks will be pushed into the stream as they are
	// confirmed.
	WatchBlocks(signature.PublicKey) (<-chan *block.Block, *pubsub.Subscription, error)

	// WatchEvents returns a stream of protocol events.
	WatchEvents(signature.PublicKey) (<-chan *Event, *pubsub.Subscription, error)

	// WatchPrunedBlocks returns a channel that produces a stream of pruned
	// blocks.
	WatchPrunedBlocks() (<-chan *PrunedBlock, *pubsub.Subscription, error)

	// MergeCommit submits a batch of merge commitments.
	MergeCommit(context.Context, signature.PublicKey, []commitment.MergeCommitment) error

	// ComputeCommit submits a batch of compute commitments for slashing.
	ComputeCommit(context.Context, signature.PublicKey, []commitment.ComputeCommitment) error

	// Cleanup cleans up the roothash backend.
	Cleanup()
}

// AnnotatedBlock is an annotated roothash block.
type AnnotatedBlock struct {
	// Height is the underlying roothash backend's block height that
	// generated this block.
	Height int64

	// Block is the roothash block.
	Block *block.Block
}

// MapAnnotatedBlockToBlock maps a channel of annotated blocks to a channel of
// plain blocks.
func MapAnnotatedBlockToBlock(annCh <-chan *AnnotatedBlock) <-chan *block.Block {
	ch := make(chan *block.Block)
	go func() {
		for {
			ann, ok := <-annCh
			if !ok {
				close(ch)
				return
			}

			ch <- ann.Block
		}
	}()

	return ch
}

// ComputeDiscrepancyDetectedEvent is a compute discrepancy detected event.
type ComputeDiscrepancyDetectedEvent struct {
	// CommitteeID is the identifier of the compute committee where a
	// discrepancy has been detected.
	CommitteeID hash.Hash `codec:"cid"`
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *ComputeDiscrepancyDetectedEvent) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR decodes a CBOR marshaled event.
func (e *ComputeDiscrepancyDetectedEvent) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

// MergeDiscrepancyDetectedEvent is a merge discrepancy detected event.
type MergeDiscrepancyDetectedEvent struct {
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (e *MergeDiscrepancyDetectedEvent) MarshalCBOR() []byte {
	return cbor.Marshal(e)
}

// UnmarshalCBOR decodes a CBOR marshaled event.
func (e *MergeDiscrepancyDetectedEvent) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, e)
}

// Event is a protocol event.
type Event struct {
	ComputeDiscrepancyDetected *ComputeDiscrepancyDetectedEvent
	MergeDiscrepancyDetected   *MergeDiscrepancyDetectedEvent
}

// MetricsMonitorable is the interface exposed by backends capable of
// providing metrics data.
type MetricsMonitorable interface {
	// WatchAllBlocks returns a channel that produces a stream of blocks.
	//
	// All blocks from all runtimes will be pushed into the stream
	// immediately as they are finalized.
	WatchAllBlocks() (<-chan *block.Block, *pubsub.Subscription)
}

// PrunedBlock describes a block that was pruned.
type PrunedBlock struct {
	// RuntimeID is the runtime identifier of the block that was pruned.
	RuntimeID signature.PublicKey
	// Round is the block round.
	Round uint64
}

// Genesis is the roothash genesis state.
type Genesis struct {
	// Blocks is the per-runtime map of genesis blocks.
	Blocks map[signature.MapKey]*block.Block `codec:"blocks,omit_empty"`
}
