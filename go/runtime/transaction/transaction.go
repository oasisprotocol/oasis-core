// Package transaction implements the runtime transaction semantics.
package transaction

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/oasisprotocol/oasis-core/go/common/cbor"
	"github.com/oasisprotocol/oasis-core/go/common/crypto/hash"
	"github.com/oasisprotocol/oasis-core/go/common/keyformat"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/node"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/syncer"
	"github.com/oasisprotocol/oasis-core/go/storage/mkvs/writelog"
)

// NOTE: This should be kept in sync with runtime/src/transaction/tree.rs.

var (
	// ErrNotFound is the error returned when a transaction with the given hash
	// cannot be found.
	ErrNotFound = errors.New("transaction: not found")

	errMalformedArtifactKind = errors.New("transaction: malformed artifact kind")
)

// prefetchArtifactCount is the number of items to prefetch from storage when
// iterating over all artifacts.
const prefetchArtifactCount uint16 = 20000

// artifactKind is an artifact kind.
type artifactKind uint8

const (
	// kindInvalid is invalid (not set) artifact kind and should never be stored.
	kindInvalid artifactKind = 0
	// kindInput is the input artifact kind.
	kindInput artifactKind = 1
	// kindOutput is the output artifact kind.
	kindOutput artifactKind = 2
)

// MarshalBinary encodes an artifact kind into binary form.
func (ak artifactKind) MarshalBinary() (data []byte, err error) {
	// kindInvalid should not be marshaled.
	if ak == kindInvalid {
		return nil, errMalformedArtifactKind
	}

	data = []byte{uint8(ak)}

	return
}

// UnmarshalBinary decodes a binary marshaled artifact kind.
func (ak *artifactKind) UnmarshalBinary(data []byte) error {
	if len(data) != 1 {
		return errMalformedArtifactKind
	}

	kind := artifactKind(data[0])
	switch kind {
	case kindInput:
	case kindOutput:
	default:
		return errMalformedArtifactKind
	}

	*ak = kind

	return nil
}

var (
	// txnKeyFmt is the key format used for transaction artifacts.
	// The artifactKind parameter is needed to compute the enum size in bytes. We put some marshallable value there.
	txnKeyFmt = keyformat.New('T', &hash.Hash{}, artifactKind(1))
	// tagKeyFmt is the key format used for emitted tags.
	//
	// This is kept separate so that clients can query only tags they are
	// interested in instead of needing to go through all transactions.
	tagKeyFmt = keyformat.New('E', []byte{}, &hash.Hash{})
)

// ValidateIOWriteLog validates the writelog for IO storage.
func ValidateIOWriteLog(writeLog writelog.WriteLog, maxBatchSize, maxBatchSizeBytes uint64) error {
	var (
		hash            hash.Hash
		kind            artifactKind
		decKey          []byte
		inputs, outputs uint64
		inputSize       uint64
	)
	for _, wle := range writeLog {
		switch {
		case txnKeyFmt.Decode(wle.Key, &hash, &kind):
			if kind != kindInput && kind != kindOutput {
				return fmt.Errorf("transaction: invalid artifact kind")
			}
			if kind == kindInput {
				inputs++
				inputSize += uint64(len(wle.Value))
			}
			if kind == kindOutput {
				outputs++
			}
		case tagKeyFmt.Decode(wle.Key, &decKey, &hash):
		default:
			return fmt.Errorf("transaction: invalid key format")
		}

		if inputs > maxBatchSize || outputs > maxBatchSize {
			return fmt.Errorf("transaction: too many inputs or outputs")
		}
		if inputSize > maxBatchSizeBytes {
			return fmt.Errorf("transaction: input set size exceeds configuration")
		}
	}

	return nil
}

// inputArtifacts are the input transaction artifacts.
//
// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
type inputArtifacts struct {
	_ struct{} `cbor:",toarray"` // nolint

	// Input is the transaction input.
	Input []byte
	// BatchOrder is the transaction order within the batch.
	//
	// This is only relevant within the committee that is processing the batch
	// and should be ignored once transactions from multiple committees are
	// merged together.
	BatchOrder uint32
}

// outputArtifacts are the output transaction artifacts.
//
// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
type outputArtifacts struct {
	_ struct{} `cbor:",toarray"` // nolint

	// Output is the transaction output (if available).
	Output []byte
}

// Transaction is an executed (or executing) transaction.
//
// This is the transaction representation used for convenience as a collection
// of all transaction artifacts. It is never serialized directly.
type Transaction struct {
	// Input is the transaction input.
	Input []byte
	// Output is the transaction output (if available).
	Output []byte
	// BatchOrder is the transaction order within the batch.
	//
	// This is only relevant within the committee that is processing the batch
	// and should be ignored once transactions from multiple committees are
	// merged together.
	BatchOrder uint32
}

// Hash returns the hash of the transaction.
//
// This requires the input artifact to be available.
func (t Transaction) Hash() hash.Hash {
	return hash.NewFromBytes(t.Input)
}

// Equal checks whether the transaction is equal to another.
func (t Transaction) Equal(other *Transaction) bool {
	return bytes.Equal(t.Input, other.Input) && bytes.Equal(t.Output, other.Output) && t.BatchOrder == other.BatchOrder
}

// asInputArtifacts returns the input artifacts of this transaction.
func (t Transaction) asInputArtifacts() inputArtifacts {
	return inputArtifacts{Input: t.Input, BatchOrder: t.BatchOrder}
}

// asOutputArtifacts returns the output artifacts of this transaction.
func (t Transaction) asOutputArtifacts() outputArtifacts {
	return outputArtifacts{Output: t.Output}
}

// Tree is a Merkle tree containing transaction artifacts.
type Tree struct {
	ioRoot node.Root
	tree   mkvs.Tree
}

// NewTree creates a new transaction artifacts tree.
func NewTree(rs syncer.ReadSyncer, ioRoot node.Root) *Tree {
	return &Tree{
		ioRoot: ioRoot,
		tree:   mkvs.NewWithRoot(rs, nil, ioRoot, mkvs.Capacity(50000, 16*1024*1024)),
	}
}

// Close releases resources associated with this transaction artifact tree.
func (t *Tree) Close() {
	t.tree.Close()
}

// AddTransaction adds a new set of transaction artifacts for a given
// transaction, optionally with emitted transaction tags.
//
// At least the Input artifact must be specified as that defines the hash of
// the transaction.
func (t *Tree) AddTransaction(ctx context.Context, tx Transaction, tags Tags) error {
	if len(tx.Input) == 0 {
		return fmt.Errorf("transaction: no input artifact given")
	}

	// Compute the transaction hash.
	txHash := tx.Hash()

	// Add transaction artifacts.
	if err := t.tree.Insert(ctx, txnKeyFmt.Encode(&txHash, kindInput), cbor.Marshal(tx.asInputArtifacts())); err != nil {
		return fmt.Errorf("transaction: input artifacts insert failed: %w", err)
	}
	if tx.Output != nil {
		if err := t.tree.Insert(ctx, txnKeyFmt.Encode(&txHash, kindOutput), cbor.Marshal(tx.asOutputArtifacts())); err != nil {
			return fmt.Errorf("transaction: output artifacts insert failed: %w", err)
		}
	}
	// Add tags if specified.
	for _, tag := range tags {
		if err := t.tree.Insert(ctx, tagKeyFmt.Encode(tag.Key, &txHash), tag.Value); err != nil {
			return fmt.Errorf("transaction: tag insert failed: %w", err)
		}
	}

	return nil
}

// inBatchOrder is a helper for sorting transactions in batch order.
type inBatchOrder struct {
	order []uint32
	batch RawBatch
}

func (bo inBatchOrder) Len() int { return len(bo.batch) }
func (bo inBatchOrder) Swap(i, j int) {
	bo.batch[i], bo.batch[j], bo.order[i], bo.order[j] = bo.batch[j], bo.batch[i], bo.order[j], bo.order[i]
}
func (bo inBatchOrder) Less(i, j int) bool { return bo.order[i] < bo.order[j] }

// GetInputBatch returns a batch of transaction input artifacts in batch order.
func (t *Tree) GetInputBatch(ctx context.Context, maxBatchSize, maxBatchSizeBytes uint64) (RawBatch, error) {
	it := t.tree.NewIterator(ctx, mkvs.IteratorPrefetch(prefetchArtifactCount))
	defer it.Close()

	var curTx hash.Hash
	curTx.Empty()

	var (
		bo             inBatchOrder
		batchSizeBytes uint64
	)
	for it.Seek(txnKeyFmt.Encode()); it.Valid(); it.Next() {
		var decHash hash.Hash
		var decKind artifactKind
		if !txnKeyFmt.Decode(it.Key(), &decHash, &decKind) {
			break
		}

		if decKind != kindInput {
			continue
		}

		var ia inputArtifacts
		if err := cbor.Unmarshal(it.Value(), &ia); err != nil {
			return nil, fmt.Errorf("transaction: malformed input artifacts: %w", err)
		}

		bo.batch = append(bo.batch, ia.Input)
		bo.order = append(bo.order, ia.BatchOrder)
		batchSizeBytes += uint64(len(ia.Input))

		if maxBatchSize > 0 && uint64(len(bo.batch)) > maxBatchSize {
			return nil, fmt.Errorf("transaction: input batch too large (max: %d txes)", maxBatchSize)
		}
		if maxBatchSizeBytes > 0 && batchSizeBytes > maxBatchSizeBytes {
			return nil, fmt.Errorf("transaction: input batch too large (max: %d bytes)", maxBatchSizeBytes)
		}
	}
	if it.Err() != nil {
		return nil, fmt.Errorf("transaction: get input batch failed: %w", it.Err())
	}

	// Sort transactions to be in batch order.
	sort.Stable(bo)

	// Make sure that item orders are consistent.
	for i, v := range bo.order {
		if uint32(i) != v {
			return nil, fmt.Errorf("transaction: inconsistent order: item %d has batch order %d", i, v)
		}
	}
	bo.order = nil

	return bo.batch, nil
}

// GetTransactions returns a list of all transaction artifacts in batch order.
func (t *Tree) GetTransactions(ctx context.Context) ([]*Transaction, error) {
	it := t.tree.NewIterator(ctx, mkvs.IteratorPrefetch(prefetchArtifactCount))
	defer it.Close()

	var curTx hash.Hash
	curTx.Empty()

	var txs []*Transaction
	for it.Seek(txnKeyFmt.Encode()); it.Valid(); it.Next() {
		var decHash hash.Hash
		var decKind artifactKind
		if !txnKeyFmt.Decode(it.Key(), &decHash, &decKind) {
			break
		}

		switch decKind {
		case kindInput:
			var ia inputArtifacts
			if err := cbor.Unmarshal(it.Value(), &ia); err != nil {
				return nil, fmt.Errorf("transaction: malformed input artifacts: %w", err)
			}

			curTx = decHash
			txs = append(txs, &Transaction{
				Input:      ia.Input,
				BatchOrder: ia.BatchOrder,
			})
		case kindOutput:
			// Input artifacts always come before output artifacts.
			if !curTx.Equal(&decHash) {
				return nil, fmt.Errorf("transaction: malformed transaction tree")
			}

			var oa outputArtifacts
			if err := cbor.Unmarshal(it.Value(), &oa); err != nil {
				return nil, fmt.Errorf("transaction: malformed output artifacts: %w", err)
			}

			tx := txs[len(txs)-1]
			tx.Output = oa.Output
		}

	}
	if it.Err() != nil {
		return nil, fmt.Errorf("transaction: get transactions failed: %w", it.Err())
	}

	// Reorder transactions so they are in batch order (how they were executed).
	sort.SliceStable(txs, func(i, j int) bool {
		return txs[i].BatchOrder < txs[j].BatchOrder
	})

	return txs, nil
}

// GetTransaction looks up a transaction by its hash and retrieves all of
// its artifacts.
func (t *Tree) GetTransaction(ctx context.Context, txHash hash.Hash) (*Transaction, error) {
	it := t.tree.NewIterator(ctx)
	defer it.Close()

	var tx Transaction
	for it.Seek(txnKeyFmt.Encode(&txHash)); it.Valid(); it.Next() {
		var decHash hash.Hash
		var decKind artifactKind
		if !txnKeyFmt.Decode(it.Key(), &decHash, &decKind) || !decHash.Equal(&txHash) {
			break
		}

		switch decKind {
		case kindInput:
			var ia inputArtifacts
			if err := cbor.Unmarshal(it.Value(), &ia); err != nil {
				return nil, fmt.Errorf("transaction: malformed input artifacts: %w", err)
			}

			tx.Input = ia.Input
			tx.BatchOrder = ia.BatchOrder
		case kindOutput:
			var oa outputArtifacts
			if err := cbor.Unmarshal(it.Value(), &oa); err != nil {
				return nil, fmt.Errorf("transaction: malformed output artifacts: %w", err)
			}

			tx.Output = oa.Output
		}

	}
	if it.Err() != nil {
		return nil, fmt.Errorf("transaction: get transaction failed: %w", it.Err())
	}
	if len(tx.Input) == 0 {
		return nil, ErrNotFound
	}

	return &tx, nil
}

// GetTransactionMultiple looks up multiple transactions by their hashes at
// once and retrieves all of their artifacts.
//
// The function behaves identically to multiple GetTransaction calls, but is
// more efficient as it performs prefetching to get all the requested
// transactions in one round trip.
func (t *Tree) GetTransactionMultiple(ctx context.Context, txHashes []hash.Hash) (map[hash.Hash]*Transaction, error) {
	// Prefetch all of the specified transactions from storage so that we
	// don't need to do multiple round trips.
	var keys [][]byte
	for _, txHash := range txHashes {
		keys = append(keys, txnKeyFmt.Encode(&txHash)) // nolint: gosec
	}
	if err := t.tree.PrefetchPrefixes(ctx, keys, prefetchArtifactCount); err != nil {
		return nil, fmt.Errorf("transaction: prefetch failed: %w", err)
	}

	// Look up each transaction.
	result := make(map[hash.Hash]*Transaction)
	for _, txHash := range txHashes {
		tx, err := t.GetTransaction(ctx, txHash)
		switch err {
		case nil:
			result[txHash] = tx
		case ErrNotFound:
			// Just continue.
		default:
			return nil, err
		}
	}

	return result, nil
}

// GetTags retrieves all tags emitted in this tree.
func (t *Tree) GetTags(ctx context.Context) (Tags, error) {
	it := t.tree.NewIterator(ctx, mkvs.IteratorPrefetch(prefetchArtifactCount))
	defer it.Close()

	var curTx hash.Hash
	curTx.Empty()

	var tags Tags
	for it.Seek(tagKeyFmt.Encode()); it.Valid(); it.Next() {
		var decKey []byte
		var decHash hash.Hash
		if !tagKeyFmt.Decode(it.Key(), &decKey, &decHash) {
			break
		}

		tags = append(tags, Tag{
			Key:    decKey,
			Value:  it.Value(),
			TxHash: decHash,
		})
	}
	if it.Err() != nil {
		return nil, fmt.Errorf("transaction: get tags failed: %w", it.Err())
	}

	return tags, nil
}

// Commit commits the updates to the underlying Merkle tree and returns the
// write log and root hash.
func (t *Tree) Commit(ctx context.Context) (writelog.WriteLog, hash.Hash, error) {
	return t.tree.Commit(ctx, t.ioRoot.Namespace, t.ioRoot.Version)
}
