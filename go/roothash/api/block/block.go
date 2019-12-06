// Package block implements the roothash block and header.
package block

import (
	"fmt"
	"time"

	"github.com/oasislabs/oasis-core/go/common/crypto/signature"
)

// Block is an Oasis block.
//
// Keep this in sync with /runtime/src/common/roothash.rs.
type Block struct {
	// Header is the block header.
	Header Header `json:"header"`
}

// NewGenesisBlock creates a new empty genesis block given a runtime
// id and POSIX timestamp.
func NewGenesisBlock(id signature.PublicKey, timestamp uint64) *Block {
	var blk Block

	blk.Header.Version = 0
	blk.Header.Timestamp = timestamp
	_ = blk.Header.Namespace.UnmarshalBinary(id[:])
	blk.Header.PreviousHash.Empty()
	blk.Header.IORoot.Empty()
	blk.Header.StateRoot.Empty()

	return &blk
}

// NewEmptyBlock creates a new empty block with a specific type.
func NewEmptyBlock(child *Block, timestamp uint64, htype HeaderType) *Block {
	var blk Block

	blk.Header.Version = child.Header.Version
	blk.Header.Namespace = child.Header.Namespace
	blk.Header.Round = child.Header.Round + 1
	blk.Header.Timestamp = timestamp
	blk.Header.HeaderType = htype
	blk.Header.PreviousHash = child.Header.EncodedHash()
	blk.Header.IORoot.Empty()
	// State root is unchanged.
	blk.Header.StateRoot = child.Header.StateRoot

	return &blk
}

// TODO Matevz: Where to call this?
// SanityCheck does basic sanity checking on the block state.
func (blk Block) SanityCheck() error {
	// Check blocks.
	hdr := blk.Header

	if hdr.HeaderType != Normal {
		return fmt.Errorf("roothash: sanity check failed: invalid block header type")
	}

	if !hdr.PreviousHash.IsEmpty() {
		return fmt.Errorf("roothash: sanity check failed: non-empty previous hash")
	}

	if hdr.Timestamp > uint64(time.Now().Unix()+61*60) {
		return fmt.Errorf("roothash: sanity check failed: block header timestamp is more than 1h1m in the future")
	}

	if len(hdr.StorageSignatures) != 0 {
		return fmt.Errorf("roothash: sanity check failed: non-empty storage signatures")
	}

	if len(hdr.RoothashMessages) != 0 {
		return fmt.Errorf("roothash: sanity check failed: non-empty roothash messages")
	}

	return nil
}
