// Package transaction implements the runtime transaction semantics.
package transaction

import (
	"bytes"
	"context"
	"sort"

	"github.com/pkg/errors"

	"github.com/oasislabs/ekiden/go/common/cbor"
	"github.com/oasislabs/ekiden/go/common/crypto/hash"
	"github.com/oasislabs/ekiden/go/common/keyformat"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/node"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/syncer"
	"github.com/oasislabs/ekiden/go/storage/mkvs/urkel/writelog"
)

// NOTE: This should be kept in sync with runtime/src/transaction/tree.rs.

var (
	// ErrNotFound is the error returned when a transaction with the given hash
	// cannot be found.
	ErrNotFound = errors.New("transaction: not found")

	errMalformedArtifactKind = errors.New("transaction: malformed artifact kind")
)

// artifactKind is an artifact kind.
type artifactKind uint8

const (
	// kindInput is the input artifact kind.
	kindInput artifactKind = 0
	// kindOutput is the output artifact kind.
	kindOutput artifactKind = 1
)

// MarshalBinary encodes an artifact kind into binary form.
func (ak artifactKind) MarshalBinary() (data []byte, err error) {
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
	txnKeyFmt = keyformat.New('T', &hash.Hash{}, artifactKind(0))
	// tagKeyFmt is the key format used for emitted tags.
	//
	// This is kept separate so that clients can query only tags they are
	// interested in instead of needing to go through all transactions.
	tagKeyFmt = keyformat.New('E', []byte{}, &hash.Hash{})
)

// inputArtifacts are the input transaction artifacts.
//
// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
type inputArtifacts struct {
	_struct struct{} `codec:",toarray"` // nolint

	// Input is the transaction input.
	Input []byte
	// BatchOrder is the transaction order within the batch.
	//
	// This is only relevant within the committee that is processing the batch
	// and should be ignored once transactions from multiple committees are
	// merged together.
	BatchOrder uint32
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (ia inputArtifacts) MarshalCBOR() []byte {
	return cbor.Marshal(ia)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (ia *inputArtifacts) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, ia)
}

// outputArtifacts are the output transaction artifacts.
//
// These are the artifacts that are stored CBOR-serialized in the Merkle tree.
type outputArtifacts struct {
	_struct struct{} `codec:",toarray"` // nolint

	// Output is the transaction output (if available).
	Output []byte
}

// MarshalCBOR serializes the type into a CBOR byte vector.
func (oa outputArtifacts) MarshalCBOR() []byte {
	return cbor.Marshal(oa)
}

// UnmarshalCBOR deserializes a CBOR byte vector into given type.
func (oa *outputArtifacts) UnmarshalCBOR(data []byte) error {
	return cbor.Unmarshal(data, oa)
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
func (t Transaction) Hash() (h hash.Hash) {
	h.FromBytes(t.Input)
	return
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
	tree   *urkel.Tree
}

// NewTree creates a new transaction artifacts tree.
func NewTree(ctx context.Context, rs syncer.ReadSyncer, ioRoot node.Root) (*Tree, error) {
	tree, err := urkel.NewWithRoot(ctx, rs, nil, ioRoot)
	if err != nil {
		return nil, err
	}

	return &Tree{
		ioRoot: ioRoot,
		tree:   tree,
	}, nil
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
		return errors.New("transaction: no input artifact given")
	}

	// Compute the transaction hash.
	txHash := tx.Hash()

	// Add transaction artifacts.
	if err := t.tree.Insert(ctx, txnKeyFmt.Encode(&txHash, kindInput), tx.asInputArtifacts().MarshalCBOR()); err != nil {
		return err
	}
	if tx.Output != nil {
		if err := t.tree.Insert(ctx, txnKeyFmt.Encode(&txHash, kindOutput), tx.asOutputArtifacts().MarshalCBOR()); err != nil {
			return err
		}
	}
	// Add tags if specified.
	for _, tag := range tags {
		if err := t.tree.Insert(ctx, tagKeyFmt.Encode(tag.Key, &txHash), tag.Value); err != nil {
			return err
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
func (t *Tree) GetInputBatch(ctx context.Context) (RawBatch, error) {
	// TODO: Hint the tree to prefetch everything.
	it := t.tree.NewIterator(ctx)
	defer it.Close()

	var curTx hash.Hash
	curTx.Empty()

	var bo inBatchOrder
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
		if err := ia.UnmarshalCBOR(it.Value()); err != nil {
			return nil, errors.Wrap(err, "transaction: malformed input artifacts")
		}

		bo.batch = append(bo.batch, ia.Input)
		bo.order = append(bo.order, ia.BatchOrder)
	}
	if it.Err() != nil {
		return nil, it.Err()
	}

	// Sort transactions to be in batch order.
	sort.Stable(bo)
	bo.order = nil

	return bo.batch, nil
}

// GetTransactions returns a list of all transaction artifacts in the tree
// in a stable order (transactions are ordered by their hash).
func (t *Tree) GetTransactions(ctx context.Context) ([]*Transaction, error) {
	// TODO: Hint the tree to prefetch everything.
	it := t.tree.NewIterator(ctx)
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
			if err := ia.UnmarshalCBOR(it.Value()); err != nil {
				return nil, errors.Wrap(err, "transaction: malformed input artifacts")
			}

			curTx = decHash
			txs = append(txs, &Transaction{
				Input:      ia.Input,
				BatchOrder: ia.BatchOrder,
			})
		case kindOutput:
			// Input artifacts always come before output artifacts.
			if !curTx.Equal(&decHash) {
				return nil, errors.New("transaction: malformed transaction tree")
			}

			var oa outputArtifacts
			if err := oa.UnmarshalCBOR(it.Value()); err != nil {
				return nil, errors.Wrap(err, "transaction: malformed output artifacts")
			}

			tx := txs[len(txs)-1]
			tx.Output = oa.Output
		}

	}
	if it.Err() != nil {
		return nil, it.Err()
	}

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
			if err := ia.UnmarshalCBOR(it.Value()); err != nil {
				return nil, errors.Wrap(err, "transaction: malformed input artifacts")
			}

			tx.Input = ia.Input
			tx.BatchOrder = ia.BatchOrder
		case kindOutput:
			var oa outputArtifacts
			if err := oa.UnmarshalCBOR(it.Value()); err != nil {
				return nil, errors.Wrap(err, "transaction: malformed output artifacts")
			}

			tx.Output = oa.Output
		}

	}
	if it.Err() != nil {
		return nil, it.Err()
	}
	if len(tx.Input) == 0 {
		return nil, ErrNotFound
	}

	return &tx, nil
}

// GetTags retrieves all tags emitted in this tree.
func (t *Tree) GetTags(ctx context.Context) (Tags, error) {
	// TODO: Hint the tree to prefetch everything.
	it := t.tree.NewIterator(ctx)
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
		return nil, it.Err()
	}

	return tags, nil
}

// Commit commits the updates to the underlying Merkle tree and returns the
// write log and root hash.
func (t *Tree) Commit(ctx context.Context) (writelog.WriteLog, hash.Hash, error) {
	return t.tree.Commit(ctx, t.ioRoot.Namespace, t.ioRoot.Round)
}
