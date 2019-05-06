package tendermint

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"

	bolt "github.com/etcd-io/bbolt"

	"github.com/oasislabs/ekiden/go/common/crypto/signature"
	"github.com/oasislabs/ekiden/go/common/logging"
	"github.com/oasislabs/ekiden/go/roothash/api"
	"github.com/oasislabs/ekiden/go/roothash/api/block"
)

var (
	bktIndexRoundToHeight = []byte("\x01")
	bktIndexHeightToRound = []byte("\x02")
)

// A thread-safe Tendermint roothash block indexer.
type blockIndexer struct {
	logger *logging.Logger

	db *bolt.DB
}

func encodeUint64(value uint64) []byte {
	var enc [8]byte
	binary.BigEndian.PutUint64(enc[:], value)
	return enc[:]
}

func decodeUint64(value []byte) uint64 {
	return binary.BigEndian.Uint64(value)
}

// Prune erases indices at the specific tendermint height.
//
// Returns a list of pruned rounds.
func (b *blockIndexer) Prune(height int64) ([]*api.PrunedBlock, error) {
	b.logger.Debug("pruning indices",
		"height", height,
	)

	var blocks []*api.PrunedBlock
	encHeight := encodeUint64(uint64(height))

	txErr := b.db.Update(func(tx *bolt.Tx) error {
		// Go through all runtimes.
		return tx.ForEach(func(name []byte, bkt *bolt.Bucket) error {
			// Resolve round using height-to-round index.
			h2r := bkt.Bucket(bktIndexHeightToRound)
			if h2r == nil {
				return nil
			}

			encRound := h2r.Get(encHeight)
			if encRound == nil {
				return nil
			}

			if err := h2r.Delete(encHeight); err != nil {
				return err
			}

			// Delete round from round-to-height index.
			r2h := bkt.Bucket(bktIndexRoundToHeight)
			if r2h == nil {
				return nil
			}

			if err := r2h.Delete(encRound); err != nil {
				return err
			}

			var runtimeID signature.PublicKey
			_ = runtimeID.UnmarshalBinary(name)
			blocks = append(blocks, &api.PrunedBlock{
				RuntimeID: runtimeID,
				Round:     decodeUint64(encRound),
			})

			return nil
		})
	})
	if txErr != nil {
		b.logger.Error("failed to prune indices",
			"err", txErr,
			"height", height,
		)
		return nil, txErr
	}

	b.logger.Debug("indices pruned",
		"height", height,
	)

	return blocks, nil
}

// Index indexes a roothash block at the given tendermint height.
func (b *blockIndexer) Index(blk *block.Block, height int64) error {
	if height < 0 {
		return errors.New("indexer: invalid argument")
	}

	encRound := encodeUint64(blk.Header.Round)
	encHeight := encodeUint64(uint64(height))

	txErr := b.db.Update(func(tx *bolt.Tx) error {
		// Create per-runtime bucket.
		bkt, err := tx.CreateBucketIfNotExists(blk.Header.Namespace[:])
		if err != nil {
			return err
		}

		// Update round-to-height index.
		r2h, err := bkt.CreateBucketIfNotExists(bktIndexRoundToHeight)
		if err != nil {
			return err
		}

		// Ensure that we are not re-writing history.
		existing := r2h.Get(encRound)
		if existing != nil {
			if bytes.Equal(existing, encHeight) {
				return nil
			}
			return errors.New("indexer: attempted to re-index with conflicting (round, height)")
		}

		if err = r2h.Put(encRound, encHeight); err != nil {
			return err
		}

		// Update height-to-round index.
		h2r, err := bkt.CreateBucketIfNotExists(bktIndexHeightToRound)
		if err != nil {
			return err
		}

		// Ensure that we are not re-writing history.
		existing = h2r.Get(encHeight)
		if existing != nil {
			if bytes.Equal(existing, encRound) {
				return nil
			}
			return errors.New("indexer: attempted to re-index with conflicting (round, height)")
		}

		return h2r.Put(encHeight, encRound)
	})
	if txErr != nil {
		b.logger.Error("failed to index block",
			"err", txErr,
			"blk", blk,
			"height", height,
		)
	}

	return txErr
}

// GetBlockHeight returns a tendermint height at which a roothash
// block at given round was finalized.
func (b *blockIndexer) GetBlockHeight(id signature.PublicKey, round uint64) (int64, error) {
	encRound := encodeUint64(round)

	var value []byte
	if txErr := b.db.View(func(tx *bolt.Tx) error {
		// If no blocks have been indexed for the given runtime ID, the bucket will not exist.
		bkt := tx.Bucket(id[:])
		if bkt == nil {
			return nil
		}

		bkt = bkt.Bucket(bktIndexRoundToHeight)
		if bkt == nil {
			return nil
		}

		value = bkt.Get(encRound)

		return nil
	}); txErr != nil {
		b.logger.Error("failed to get block height",
			"err", txErr,
			"id", id,
			"round", round,
		)
		return -1, txErr
	}

	if len(value) == 0 {
		return -1, api.ErrNotFound
	}
	if len(value) != 8 {
		b.logger.Error("corrupted block index",
			"id", id,
			"round", round,
			"value", hex.EncodeToString(value),
		)
		return -1, errors.New("indexer: corrupted block index")
	}
	height := int64(decodeUint64(value))

	return height, nil
}

// Stop closes the block index.
//
// After this method is called, no further operations should be done.
func (b *blockIndexer) Stop() {
	if err := b.db.Close(); err != nil {
		b.logger.Error("failed to close index",
			"err", err,
		)
	}
	b.db = nil
}

func newBlockIndex(dataDir string) (*blockIndexer, error) {
	b := &blockIndexer{
		logger: logging.GetLogger("roothash/tendermint/blockIndexer"),
	}

	var err error
	if b.db, err = bolt.Open(filepath.Join(dataDir, "roothash-tm-block-index.bolt.db"), 0600, nil); err != nil {
		return nil, err
	}

	b.logger.Info("initialized block indexer")

	// TODO: The file format could be versioned.

	return b, nil
}
